"""The analysis engine: frames -> flows -> protocol plugins -> pipeline."""

from __future__ import annotations

import itertools
import logging
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.engine.decode import (
    ETH_IPV4,
    ETH_IPV6,
    IPV6_EXTENSIONS,
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
    skip_ipv6_extensions,
)
from netcreds_ng.engine.ipfrag import Defragmenter
from netcreds_ng.engine.pcapio import RawFrame
from netcreds_ng.engine.pipeline import Pipeline
from netcreds_ng.engine.tcp import Chunk, TCPStream
from netcreds_ng.engine.tls import TLSDecryptor, TLSSession, could_start_client_hello, looks_like_client_hello
from netcreds_ng.model import Endpoint, Finding, RunStats
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin, Transport

log = logging.getLogger(__name__)

IDLE_TIMEOUT = 600.0
UDP_IDLE_TIMEOUT = 120.0
MAX_FLOWS = 100_000
SWEEP_EVERY = 2048
#: A data segment repeated (same seq, ack, flags, length and non-zero IP ID) within this many seconds is
#: a capture duplicate: a retransmission is a new IP datagram with a new ID. Typical of a SPAN port that
#: copies both ingress and egress.
DUP_WINDOW = 0.010
#: Without an IP ID (IPv6, or IPv4 senders that set 0 with DF) only the timing separates a SPAN copy
#: (microseconds apart) from a fast retransmit (at least one round trip later), so the window is tight.
DUP_WINDOW_NO_ID = 0.0002
DUP_HISTORY = 4


@dataclass(eq=False)
class _Slot:
    """One plugin attached to one flow, in one orientation.

    For a flow whose client/server roles are ambiguous each plugin gets two slots,
    one per orientation (``swapped``); the first slot that emits a finding wins and
    its sibling is detached.
    """

    plugin: ProtocolPlugin
    ctx: Context
    swapped: bool = False
    sibling: _Slot | None = None
    lost: bool = False  # the other orientation won; this slot gets no further callbacks
    twin: _Slot | None = None  # the other orientation, kept after resolution (``sibling`` is cleared)
    won: bool = False  # this orientation produced a finding
    suppressed: BaseException | None = None  # error raised in a guessed orientation, reported if it never resolves
    decrypted: bool = False  # the data this slot saw last was decrypted TLS


@dataclass
class _Flow:
    info: FlowInfo
    contexts: list[_Slot]
    streams: tuple[TCPStream, TCPStream] | None
    last_ts: float
    closing: bool = False
    rst: bool = False
    pending_close: set[int] = field(default_factory=set)
    certain: bool = True  # client/server roles known (SYN or ports), not guessed
    tls: TLSSession | None = None
    tls_client: Direction = Direction.CLIENT_TO_SERVER  # direction that sent the ClientHello
    # Bytes held back per direction while deciding whether a ClientHello starts (E-8).
    tls_probe: list[bytes] = field(default_factory=lambda: [b"", b""])
    # Capture health (TCP): packets per direction, whether a direction sent anything but bare SYNs,
    # whether a handshake was seen, and recent data-segment signatures per direction.
    packets: list[int] = field(default_factory=lambda: [0, 0])
    beyond_syn: list[bool] = field(default_factory=lambda: [False, False])
    data: list[bool] = field(default_factory=lambda: [False, False])  # a direction carried payload
    handshake: bool = False
    recent: tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]] = field(default_factory=lambda: ([], []))


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
        dual_orientation: bool = True,
        tls: TLSDecryptor | None = None,
    ) -> None:
        self.tls = tls
        self._decrypted_context = False  # set while plugins handle decrypted TLS data
        self.exclude_hosts = exclude_hosts or set()
        self.dual_orientation = dual_orientation
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
        #: Called with every decoded TCP/UDP packet before plugins see it (e.g. evidence capture).
        self.packet_observers: list[Callable[[Packet], None]] = []
        self.server_ports: set[int] = set()
        for p in self.plugins:
            self.server_ports |= set(p.default_ports)

    # public ----------------------------------------------------------------

    def process_frame(self, frame: RawFrame) -> None:
        st = self.stats
        st.frames += 1
        self._now = frame.timestamp
        # Earliest and latest, not first and last seen: merged or out-of-order captures (and the -j merge).
        if st.first_ts is None or frame.timestamp < st.first_ts:
            st.first_ts = frame.timestamp
        if st.last_ts is None or frame.timestamp > st.last_ts:
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
            l4 = self._defrag.add(ip, frame.timestamp, frame)
            if l4 is None:
                return
            st.ip_reassembled += 1
            ip.frag_offset, ip.more_fragments = 0, False
            if ip.version == 6 and ip.proto in IPV6_EXTENSIONS:
                # Extension headers after the Fragment header belong to the fragmentable part.
                skipped = skip_ipv6_extensions(ip.proto, l4)
                if skipped is None:
                    st.undecodable += 1
                    return
                ip.proto, l4 = skipped[0], l4[skipped[1] :]
            pkt = decode_l4(frame, res[0], ip, l4)
            pkt.fragment_frames = tuple(self._defrag.last_frames)  # type: ignore[arg-type]
        else:
            pkt = decode_l4(frame, res[0], ip)
        st.decoded += 1
        if pkt.l4_header_len:
            for observer in self.packet_observers:
                observer(pkt)
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
        # Fragments that never completed a datagram are reported, not silently dropped.
        self._defrag.expire_all()
        self.stats.ip_fragments_expired = self._defrag.expired
        self.stats.ip_fragment_duplicates = self._defrag.duplicates

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    # flows -----------------------------------------------------------------

    def _new_flow(self, key: tuple[Any, ...], pkt: Packet, transport: Transport) -> _Flow:
        if len(self._flows) >= self.max_flows:
            oldest = next(iter(self._flows))
            self.stats.evicted_flows += 1
            self._close(oldest)
        sender_is_client, certain = self._guess_sender_is_client(pkt)
        snd, rcv = Endpoint(pkt.src, pkt.sport), Endpoint(pkt.dst, pkt.dport)
        client, server = (snd, rcv) if sender_is_client else (rcv, snd)
        info = FlowInfo(next(self._ids), transport, client, server)
        swapped_info = FlowInfo(info.flow_id, transport, server, client)
        dual = self.dual_orientation and not certain
        if dual:
            self.stats.ambiguous_flows += 1
        contexts: list[_Slot] = []
        for plugin in self.plugins:
            if transport not in plugin.transports:
                continue
            if plugin.ports_only and server.port not in plugin.default_ports and client.port not in plugin.default_ports:
                continue
            slot = self._slot(plugin, info, swapped=False)
            if slot is None:
                continue
            contexts.append(slot)
            if dual:
                twin = self._slot(plugin, swapped_info, swapped=True)
                if twin is not None:
                    slot.sibling, twin.sibling = twin, slot
                    slot.twin, twin.twin = twin, slot
                    contexts.append(twin)
        streams = (TCPStream(), TCPStream()) if transport is Transport.TCP else None
        flow = _Flow(info, contexts, streams, pkt.timestamp, certain=certain)
        self._flows[key] = flow
        if transport is Transport.TCP:
            self.stats.tcp_flows += 1
        else:
            self.stats.udp_flows += 1
        return flow

    def _slot(self, plugin: ProtocolPlugin, info: FlowInfo, swapped: bool) -> _Slot | None:
        slot = _Slot(plugin, Context(info, self._emit, self.options), swapped)
        slot.ctx.tls_decryption = self.tls is not None
        if self.dual_orientation:
            slot.ctx._emit = lambda finding, s=slot: self._emit_from(s, finding)
        try:
            slot.ctx.state = plugin.new_state(info)
        except Exception as exc:  # noqa: BLE001
            self._plugin_error(plugin, info, exc)
            return None
        return slot

    def _emit_from(self, slot: _Slot, finding: Finding) -> None:
        slot.won = True
        twin = slot.sibling
        if twin is not None:  # this orientation produced a finding: it wins for this plugin
            twin.ctx.detach()
            twin.lost = True
            twin.sibling = None
            slot.sibling = None
            self.stats.orientation_resolved += 1
        self._emit(finding)

    def _guess_sender_is_client(self, pkt: Packet) -> tuple[bool, bool]:
        """(sender is the client, whether that is certain rather than a guess)."""
        if pkt.proto == PROTO_TCP and pkt.flags & TCP_SYN:
            return not (pkt.flags & TCP_ACK), True
        s_srv = pkt.sport in self.server_ports or pkt.sport < 1024
        d_srv = pkt.dport in self.server_ports or pkt.dport < 1024
        if d_srv and not s_srv:
            return True, True
        if s_srv and not d_srv:
            return False, True
        return pkt.sport >= pkt.dport, False

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
            flow = self._new_flow(key, pkt, Transport.TCP)
        else:
            self._flows.move_to_end(key)
        flow.last_ts = pkt.timestamp
        direction = self._direction(flow, pkt)
        self._health(flow, direction, pkt)
        assert flow.streams is not None
        stream = flow.streams[direction]
        other = flow.streams[direction.other]
        if pkt.payload and other.warming:
            # Keep request/response order: data now flowing this way ends the other side's warm-up.
            self._flush_stream(flow, direction.other, other.release, pkt)
        if pkt.payload and pkt.flags & TCP_ACK and other.pending:
            # Only a reply carrying data forces the skip (it must be delivered after the request).
            # A pure ACK may be captured ahead of the segment it acknowledges (merged taps, skew),
            # so it never declares a hole lost: the late segment can still fill it.
            self._flush_stream(flow, direction.other, lambda: other.acknowledged(pkt.ack), pkt)
        syn, fin = bool(pkt.flags & TCP_SYN), bool(pkt.flags & TCP_FIN)
        origin = (pkt.index, pkt.timestamp)
        self._flush_stream(flow, direction, lambda: stream.add(pkt.seq, pkt.payload, syn=syn, fin=fin, origin=origin),
                           pkt)  # fmt: skip
        if pkt.flags & TCP_RST:
            flow.rst = True
            self._close(key)
            return
        if pkt.flags & TCP_FIN:
            flow.pending_close.add(int(direction))
            if len(flow.pending_close) == 2:
                flow.closing = True

    def _health(self, flow: _Flow, direction: Direction, pkt: Packet) -> None:
        """Capture-health bookkeeping for one TCP packet (see :mod:`netcreds_ng.health`)."""
        d = int(direction)
        flow.packets[d] += 1
        if pkt.flags & TCP_SYN:
            flow.handshake = True
        if pkt.payload or pkt.flags & TCP_ACK:  # anything but a bare SYN answers or follows a reply
            flow.beyond_syn[d] = True
        if not pkt.payload:
            return
        flow.data[d] = True
        st = self.stats
        st.tcp_data_segments += 1
        st.tcp_payload_bytes += len(pkt.payload)
        sig = (pkt.seq, pkt.ack, pkt.flags, len(pkt.payload), pkt.ip.ident)
        window = DUP_WINDOW if pkt.ip.ident else DUP_WINDOW_NO_ID
        recent = flow.recent[d]
        for old_sig, old_ts in recent:
            if old_sig == sig and 0 <= pkt.timestamp - old_ts <= window:
                st.tcp_duplicate_segments += 1
                return
        recent.append((sig, pkt.timestamp))
        if len(recent) > DUP_HISTORY:
            del recent[0]

    def _health_close(self, flow: _Flow) -> None:
        st = self.stats
        if not flow.handshake and (flow.data[0] or flow.data[1]):
            st.tcp_no_handshake_flows += 1  # a data-less straggler (late ACK after RST/close) is not a pickup
        sent = [n > 0 for n in flow.packets]
        if sent[0] != sent[1]:
            side = 0 if sent[0] else 1
            if flow.data[side]:
                st.tcp_one_sided_flows += 1  # the sender sent data in reply to or awaiting a side we never saw
            elif not flow.beyond_syn[side]:
                st.tcp_unanswered_syn_flows += 1  # a connection attempt nobody answered: not a capture problem

    def _is_new_connection(self, flow: _Flow, pkt: Packet) -> bool:
        """A SYN on a known 4-tuple starts a new connection unless it repeats the original SYN."""
        if flow.closing or flow.rst:
            return True
        assert flow.streams is not None
        stream = flow.streams[self._direction(flow, pkt)]
        if stream.isn is not None:
            return pkt.seq != stream.isn
        # No SYN seen from this side yet: a SYN after data from it means the old connection is gone.
        return stream.offset > 0 or stream.next_seq is not None or stream.warming

    def _flush_stream(self, flow: _Flow, direction: Direction, step: Any, pkt: Packet | None) -> None:
        """Run ``step`` (a stream operation returning chunks), account for it and deliver the chunks."""
        assert flow.streams is not None
        stream = flow.streams[direction]
        before = stream.retransmitted, stream.gaps, stream.gap_bytes
        chunks = step()
        self._account(stream, *before)
        self._deliver(flow, direction, chunks, pkt)

    def _account(self, stream: TCPStream, retx: int, gaps: int, gap_bytes: int) -> None:
        self.stats.tcp_retransmitted_bytes += stream.retransmitted - retx
        self.stats.tcp_gaps += stream.gaps - gaps
        self.stats.tcp_gap_bytes += stream.gap_bytes - gap_bytes

    def _udp(self, pkt: Packet) -> None:
        key = (PROTO_UDP, *_canonical(pkt.src, pkt.sport, pkt.dst, pkt.dport))
        flow = self._flows.get(key)
        if flow is None:
            flow = self._new_flow(key, pkt, Transport.UDP)
        else:
            self._flows.move_to_end(key)
        flow.last_ts = pkt.timestamp
        direction = self._direction(flow, pkt)
        for slot in flow.contexts:
            ctx = slot.ctx
            if ctx.detached:
                continue
            ctx.timestamp, ctx.frame = pkt.timestamp, pkt.index
            try:
                slot.plugin.on_datagram(ctx, direction.other if slot.swapped else direction, pkt.payload)
            except Exception as exc:  # noqa: BLE001
                self._slot_error(slot, exc)

    def _tls_filter(self, flow: _Flow, direction: Direction, chunks: list[Chunk]) -> list[Chunk]:
        """Replace TLS record bytes by the decrypted application data (or nothing without keys).

        A session starts at a ClientHello: at the start of the connection or after STARTTLS.
        """
        assert self.tls is not None
        out: list[Chunk] = []
        d = int(direction)
        for chunk in chunks:
            if flow.tls is None:
                # Either side may send the ClientHello when the roles were only guessed (review M2).
                if direction is not Direction.CLIENT_TO_SERVER and flow.certain:
                    out.append(chunk)
                    continue
                probe = flow.tls_probe[d]
                if probe and chunk.gap_before:
                    out.append(Chunk(probe))  # bytes before a hole cannot start a ClientHello with it
                    probe = b""
                data = probe + chunk.data
                flow.tls_probe[d] = b""
                if 0 < len(data) < 6 and could_start_client_hello(data):
                    flow.tls_probe[d] = data  # too short to decide: wait for the next bytes (E-8)
                    continue
                if not looks_like_client_hello(data):
                    out.append(Chunk(data, chunk.gap_before, chunk.frame, chunk.timestamp))
                    continue
                flow.tls = self.tls.new_session()
                flow.tls_client = direction
                self.stats.tls_sessions += 1
                chunk = Chunk(data, 0, chunk.frame, chunk.timestamp)
            side = 0 if direction is flow.tls_client else 1  # TLS side 0 is whoever sent the ClientHello
            if chunk.gap_before:
                flow.tls.gap(side)
                out.append(Chunk(b"", chunk.gap_before, chunk.frame, chunk.timestamp, decrypted=True))
                continue
            out.extend(Chunk(plain, 0, chunk.frame, chunk.timestamp, decrypted=True)
                       for plain in flow.tls.feed(side, chunk.data) if plain)  # fmt: skip
        return out

    def _deliver(self, flow: _Flow, direction: Direction, chunks: list[Chunk], pkt: Packet | None) -> None:
        if self.tls is not None and flow.streams is not None and chunks:
            chunks = self._tls_filter(flow, direction, chunks)
        if not chunks:
            return
        try:
            self._deliver_to_plugins(flow, direction, chunks, pkt)
        finally:
            self._decrypted_context = False

    def _deliver_to_plugins(self, flow: _Flow, direction: Direction, chunks: list[Chunk], pkt: Packet | None) -> None:
        for slot in flow.contexts:
            ctx, plugin = slot.ctx, slot.plugin
            if ctx.detached:
                continue
            d = direction.other if slot.swapped else direction
            try:
                for chunk in chunks:
                    # Cite the packet that carried these bytes, not the one that released them (review M4).
                    if chunk.frame:
                        ctx.timestamp, ctx.frame = chunk.timestamp, chunk.frame
                    elif pkt is not None:
                        ctx.timestamp, ctx.frame = pkt.timestamp, pkt.index
                    self._decrypted_context = slot.decrypted = chunk.decrypted
                    if chunk.gap_before:
                        plugin.on_gap(ctx, d, chunk.gap_before)
                    if ctx.detached:
                        break
                    plugin.on_data(ctx, d, chunk.data)
                    if ctx.detached:
                        break
            except Exception as exc:  # noqa: BLE001
                self._slot_error(slot, exc)

    def _slot_error(self, slot: _Slot, exc: BaseException) -> None:
        slot.ctx.detach()
        if slot.sibling is not None and not slot.sibling.lost:
            # A plugin choking on a guessed orientation is expected; the other orientation carries on.
            # The error is kept and reported at close unless the other orientation wins (review M3).
            slot.lost = True
            slot.suppressed = exc
            slot.sibling.sibling = None
            slot.sibling = None
            self.stats.suppressed_orientation_errors[slot.plugin.name] += 1
            log.debug("plugin %s failed in a guessed orientation: %s", slot.plugin.name, exc)
            return
        self._plugin_error(slot.plugin, slot.ctx.flow, exc)

    def _close(self, key: tuple[Any, ...]) -> None:
        flow = self._flows.pop(key, None)
        if flow is None:
            return
        if flow.streams is not None:
            self._health_close(flow)
            for direction in (Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT):
                self._flush_stream(flow, direction, flow.streams[direction].flush, None)
            for direction in (Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT):
                probe = flow.tls_probe[direction]
                if probe:  # held bytes that never became a ClientHello still reach the plugins
                    flow.tls_probe[direction] = b""
                    self._deliver_to_plugins(flow, direction, [Chunk(probe)], None)
        try:
            for slot in flow.contexts:
                if slot.lost:  # checked per slot: an earlier on_close may have just resolved the orientation
                    continue
                # Tag on_close findings only if this slot's last data was decrypted (review L3).
                self._decrypted_context = slot.decrypted
                try:
                    slot.plugin.on_close(slot.ctx)
                except Exception as exc:  # noqa: BLE001
                    self._slot_error(slot, exc)
        finally:
            self._decrypted_context = False
        for slot in flow.contexts:
            if slot.suppressed is not None and not (slot.twin is not None and slot.twin.won):
                # Neither orientation won: the swallowed error may have hidden real findings.
                self._plugin_error(slot.plugin, slot.ctx.flow, slot.suppressed)
        if flow.tls is not None:
            self._tls_stats(flow.tls)

    def _sweep(self) -> None:
        for key, flow in list(self._flows.items()):
            timeout = self.idle_timeout if flow.streams is not None else UDP_IDLE_TIMEOUT
            if flow.closing or self._now - flow.last_ts > timeout:
                self._close(key)

    # plumbing --------------------------------------------------------------

    def _emit(self, finding: Finding) -> None:
        if self._decrypted_context and "tls-decrypted" not in finding.tags:
            # Seen only after decrypting with a key log: not exposed in cleartext on the wire.
            finding.tags.append("tls-decrypted")
        self.pipeline.publish(finding)

    def _tls_stats(self, session: TLSSession) -> None:
        st = self.stats
        if session.status == "decrypting" or session.decrypted:
            st.tls_decrypted += 1
        elif session.status == "no-key":
            st.tls_no_key += 1
        elif session.status == "unsupported":
            st.tls_unsupported += 1
            if len(self.pipeline.errors) < 100:
                self.pipeline.errors.append(f"TLS not decrypted: {session.reason}")
        else:
            st.tls_failed += 1

    def _plugin_error(self, plugin: ProtocolPlugin, flow: FlowInfo, exc: BaseException) -> None:
        self.stats.plugin_errors[plugin.name] += 1
        msg = f"plugin {plugin.name} failed on flow {flow.client} -> {flow.server}: {type(exc).__name__}: {exc}"
        if len(self.pipeline.errors) < 100:
            self.pipeline.errors.append(msg)
        log.warning(msg)
        log.debug("plugin traceback", exc_info=exc)
