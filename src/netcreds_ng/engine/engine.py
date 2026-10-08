"""The analysis engine: frames -> flows -> protocol plugins -> pipeline."""

from __future__ import annotations

import itertools
import logging
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.engine.decode import (
    ETH_IPV4,
    ETH_IPV6,
    PROTO_TCP,
    PROTO_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
    Packet,
    decode_ip,
    decode_l4,
    l3_offset,
)
from netcreds_ng.engine.ipfrag import Defragmenter
from netcreds_ng.engine.pcapio import RawFrame
from netcreds_ng.engine.pipeline import Pipeline
from netcreds_ng.engine.tcp import Chunk, TCPStream
from netcreds_ng.model import Endpoint, Finding, RunStats
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin, Transport

log = logging.getLogger(__name__)

IDLE_TIMEOUT = 600.0
UDP_IDLE_TIMEOUT = 120.0
MAX_FLOWS = 100_000
SWEEP_EVERY = 2048


@dataclass
class _Flow:
    info: FlowInfo
    contexts: list[tuple[ProtocolPlugin, Context]]
    streams: tuple[TCPStream, TCPStream] | None
    last_ts: float
    closing: bool = False
    rst: bool = False
    pending_close: set[int] = field(default_factory=set)


def _canonical(src: str, sport: int, dst: str, dport: int) -> tuple[Any, ...]:
    a, b = (src, sport), (dst, dport)
    return (a, b) if a <= b else (b, a)


class Engine:
    def __init__(
        self,
        plugins: Iterable[ProtocolPlugin],
        pipeline: Pipeline,
        stats: RunStats | None = None,
        options: dict[str, Any] | None = None,
        idle_timeout: float = IDLE_TIMEOUT,
        max_flows: int = MAX_FLOWS,
        exclude_hosts: set[str] | None = None,
    ) -> None:
        self.exclude_hosts = exclude_hosts or set()
        self.plugins = sorted(plugins, key=lambda p: (p.priority, p.name))
        self.pipeline = pipeline
        self.stats = stats or pipeline.stats
        self.options = options or {}
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows
        self._flows: OrderedDict[tuple[Any, ...], _Flow] = OrderedDict()
        self._defrag = Defragmenter()
        self._ids = itertools.count(1)
        self._since_sweep = 0
        self._now = 0.0
        self.server_ports: set[int] = set()
        for p in self.plugins:
            self.server_ports |= set(p.default_ports)

    # public ----------------------------------------------------------------

    def process_frame(self, frame: RawFrame) -> None:
        st = self.stats
        st.frames += 1
        self._now = frame.timestamp
        if st.first_ts is None:
            st.first_ts = frame.timestamp
        st.last_ts = frame.timestamp
        if frame.wirelen > len(frame.data):
            st.truncated_frames += 1
        res = l3_offset(frame)
        if res is None or res[1] not in (ETH_IPV4, ETH_IPV6):
            st.undecodable += 1
            return
        ip = decode_ip(frame.data[res[0] :])
        if ip is None:
            st.undecodable += 1
            return
        if self.exclude_hosts and (ip.src in self.exclude_hosts or ip.dst in self.exclude_hosts):
            st.filtered += 1
            return
        if ip.is_fragment:
            st.ip_fragments += 1
            l4 = self._defrag.add(ip, frame.timestamp)
            if l4 is None:
                return
            st.ip_reassembled += 1
            ip.frag_offset, ip.more_fragments = 0, False
            pkt = decode_l4(frame, res[0], ip, l4)
        else:
            pkt = decode_l4(frame, res[0], ip)
        st.decoded += 1
        if pkt.proto == PROTO_TCP and pkt.l4_header_len:
            self._tcp(pkt)
        elif pkt.proto == PROTO_UDP and pkt.l4_header_len:
            self._udp(pkt)
        self._since_sweep += 1
        if self._since_sweep >= SWEEP_EVERY:
            self._since_sweep = 0
            self._sweep()

    def process(self, frames: Iterable[RawFrame]) -> None:
        for frame in frames:
            self.process_frame(frame)

    def finish(self) -> None:
        for key in list(self._flows):
            self._close(key)

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    # flows -----------------------------------------------------------------

    def _new_flow(self, key: tuple[Any, ...], pkt: Packet, transport: Transport, sender_is_client: bool) -> _Flow:
        if len(self._flows) >= self.max_flows:
            oldest = next(iter(self._flows))
            self.stats.evicted_flows += 1
            self._close(oldest)
        snd, rcv = Endpoint(pkt.src, pkt.sport), Endpoint(pkt.dst, pkt.dport)
        client, server = (snd, rcv) if sender_is_client else (rcv, snd)
        info = FlowInfo(next(self._ids), transport, client, server)
        contexts: list[tuple[ProtocolPlugin, Context]] = []
        for plugin in self.plugins:
            if transport not in plugin.transports:
                continue
            if plugin.ports_only and server.port not in plugin.default_ports and client.port not in plugin.default_ports:
                continue
            ctx = Context(info, self._emit, self.options)
            try:
                ctx.state = plugin.new_state(info)
            except Exception as exc:  # noqa: BLE001
                self._plugin_error(plugin, info, exc)
                continue
            contexts.append((plugin, ctx))
        streams = (TCPStream(), TCPStream()) if transport is Transport.TCP else None
        flow = _Flow(info, contexts, streams, pkt.timestamp)
        self._flows[key] = flow
        if transport is Transport.TCP:
            self.stats.tcp_flows += 1
        else:
            self.stats.udp_flows += 1
        return flow

    def _guess_sender_is_client(self, pkt: Packet) -> bool:
        if pkt.proto == PROTO_TCP and pkt.flags & TCP_SYN:
            return not (pkt.flags & TCP_ACK)
        s_srv = pkt.sport in self.server_ports or pkt.sport < 1024
        d_srv = pkt.dport in self.server_ports or pkt.dport < 1024
        if d_srv and not s_srv:
            return True
        if s_srv and not d_srv:
            return False
        if s_srv and d_srv:
            return pkt.sport >= pkt.dport
        return pkt.sport >= pkt.dport

    def _direction(self, flow: _Flow, pkt: Packet) -> Direction:
        c = flow.info.client
        if pkt.src == c.ip and pkt.sport == c.port:
            return Direction.CLIENT_TO_SERVER
        return Direction.SERVER_TO_CLIENT

    def _tcp(self, pkt: Packet) -> None:
        key = (PROTO_TCP, *_canonical(pkt.src, pkt.sport, pkt.dst, pkt.dport))
        flow = self._flows.get(key)
        syn_only = bool(pkt.flags & TCP_SYN) and not (pkt.flags & TCP_ACK)
        if flow is not None and syn_only and self._is_new_connection(flow, pkt):
            self._close(key)  # port reuse: a new connection on the same 4-tuple
            flow = None
        if flow is None:
            if pkt.flags & TCP_RST and not pkt.payload:
                return
            flow = self._new_flow(key, pkt, Transport.TCP, self._guess_sender_is_client(pkt))
        else:
            self._flows.move_to_end(key)
        flow.last_ts = pkt.timestamp
        direction = self._direction(flow, pkt)
        assert flow.streams is not None
        stream = flow.streams[direction]
        before_retx, before_gaps, before_gap_bytes = stream.retransmitted, stream.gaps, stream.gap_bytes
        chunks = stream.add(pkt.seq, pkt.payload, syn=bool(pkt.flags & TCP_SYN), fin=bool(pkt.flags & TCP_FIN))
        self._account(stream, before_retx, before_gaps, before_gap_bytes)
        self._deliver(flow, direction, chunks, pkt)
        if pkt.flags & TCP_RST:
            flow.rst = True
            self._close(key)
            return
        if pkt.flags & TCP_FIN:
            flow.pending_close.add(int(direction))
            if len(flow.pending_close) == 2:
                flow.closing = True

    def _is_new_connection(self, flow: _Flow, pkt: Packet) -> bool:
        """A SYN on a known 4-tuple starts a new connection unless it repeats the original SYN."""
        if flow.closing or flow.rst:
            return True
        assert flow.streams is not None
        stream = flow.streams[self._direction(flow, pkt)]
        if stream.isn is not None:
            return pkt.seq != stream.isn
        # No SYN seen from this side yet: a SYN after data from it means the old connection is gone.
        return stream.offset > 0 or stream.next_seq is not None

    def _account(self, stream: TCPStream, retx: int, gaps: int, gap_bytes: int) -> None:
        self.stats.tcp_retransmitted_bytes += stream.retransmitted - retx
        self.stats.tcp_gaps += stream.gaps - gaps
        self.stats.tcp_gap_bytes += stream.gap_bytes - gap_bytes

    def _udp(self, pkt: Packet) -> None:
        key = (PROTO_UDP, *_canonical(pkt.src, pkt.sport, pkt.dst, pkt.dport))
        flow = self._flows.get(key)
        if flow is None:
            flow = self._new_flow(key, pkt, Transport.UDP, self._guess_sender_is_client(pkt))
        else:
            self._flows.move_to_end(key)
        flow.last_ts = pkt.timestamp
        direction = self._direction(flow, pkt)
        for plugin, ctx in flow.contexts:
            if ctx.detached:
                continue
            ctx.timestamp, ctx.frame = pkt.timestamp, pkt.index
            try:
                plugin.on_datagram(ctx, direction, pkt.payload)
            except Exception as exc:  # noqa: BLE001
                self._plugin_error(plugin, flow.info, exc)
                ctx.detach()

    def _deliver(self, flow: _Flow, direction: Direction, chunks: list[Chunk], pkt: Packet | None) -> None:
        if not chunks:
            return
        for plugin, ctx in flow.contexts:
            if ctx.detached:
                continue
            if pkt is not None:
                ctx.timestamp, ctx.frame = pkt.timestamp, pkt.index
            try:
                for chunk in chunks:
                    if chunk.gap_before:
                        plugin.on_gap(ctx, direction, chunk.gap_before)
                    if ctx.detached:
                        break
                    plugin.on_data(ctx, direction, chunk.data)
                    if ctx.detached:
                        break
            except Exception as exc:  # noqa: BLE001
                self._plugin_error(plugin, flow.info, exc)
                ctx.detach()

    def _close(self, key: tuple[Any, ...]) -> None:
        flow = self._flows.pop(key, None)
        if flow is None:
            return
        if flow.streams is not None:
            for direction in (Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT):
                stream = flow.streams[direction]
                before = stream.retransmitted, stream.gaps, stream.gap_bytes
                chunks = stream.flush()
                self._account(stream, *before)
                self._deliver(flow, direction, chunks, None)
        for plugin, ctx in flow.contexts:
            try:
                plugin.on_close(ctx)
            except Exception as exc:  # noqa: BLE001
                self._plugin_error(plugin, flow.info, exc)

    def _sweep(self) -> None:
        for key, flow in list(self._flows.items()):
            timeout = self.idle_timeout if flow.streams is not None else UDP_IDLE_TIMEOUT
            if flow.closing or self._now - flow.last_ts > timeout:
                self._close(key)

    # plumbing --------------------------------------------------------------

    def _emit(self, finding: Finding) -> None:
        self.pipeline.publish(finding)

    def _plugin_error(self, plugin: ProtocolPlugin, flow: FlowInfo, exc: BaseException) -> None:
        self.stats.plugin_errors[plugin.name] += 1
        msg = f"plugin {plugin.name} failed on flow {flow.client} -> {flow.server}: {type(exc).__name__}: {exc}"
        if len(self.pipeline.errors) < 100:
            self.pipeline.errors.append(msg)
        log.warning(msg)
        log.debug("plugin traceback", exc_info=exc)
