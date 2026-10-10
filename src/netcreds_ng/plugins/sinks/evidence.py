"""Evidence capture: the original packets behind each finding, written to a pcapng file.

The sink keeps a small rolling buffer of recent frames per flow. When a finding is
published, the buffered frames of its flow are selected, plus the next ``after`` frames
of that flow (so the server's verdict is included). At the end of the run the selected
frames are written in their original order; each carries a packet comment naming its
original frame number and the finding(s) it supports, so an auditor can open the file
in Wireshark and see exactly what crossed the wire.

The file holds raw packets, cleartext secrets included: that is the evidence. Treat it
like the capture it came from.

Options: ``frames_per_flow`` (default 64), ``bytes_per_flow`` (default 512 KiB),
``after`` (default 16), ``max_flows`` (default 20000).
"""

from __future__ import annotations

import os
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.engine.decode import Packet
from netcreds_ng.engine.pcapio import PcapngWriter, RawFrame
from netcreds_ng.model import Endpoint, Finding, Kind, RunStats
from netcreds_ng.plugins.api import SinkContext, SinkPlugin

FlowKey = tuple[tuple[str, int], tuple[str, int]]


def flow_key(a: Endpoint | tuple[str, int], b: Endpoint | tuple[str, int]) -> FlowKey:
    x = (a.ip, a.port) if isinstance(a, Endpoint) else a
    y = (b.ip, b.port) if isinstance(b, Endpoint) else b
    return (x, y) if x <= y else (y, x)


@dataclass(frozen=True)
class _Held:
    """A frame seen during the run. ``seq`` orders frames across input files, whose own frame
    numbers restart at 1; ``source`` is the input file (empty for live capture)."""

    seq: int
    source: str
    frame: RawFrame


@dataclass
class _FlowBuffer:
    frames: deque[_Held] = field(default_factory=deque)
    size: int = 0
    follow: int = 0  # frames still to select after the latest finding


def describe(f: Finding) -> str:
    """A finding label for packet comments. Never includes the secret itself."""
    who = f"{f.domain}\\{f.username}" if f.domain and f.username else (f.username or "")
    label = f"{f.protocol} {f.kind.value.replace('_', ' ')}"
    if f.kind in (Kind.AUTH_RESULT, Kind.ALERT, Kind.AUTH_EVENT, Kind.INFO) and f.value:
        label += f": {f.value[:120]}"
    elif who:
        label += f" for {who}"
    return label


class EvidenceSink(SinkPlugin):
    name = "evidence"
    description = "Write the packets behind each finding to a pcapng file with Wireshark comments (raw packets)"
    wants_packets = True

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.frames_per_flow = int(self.options.get("frames_per_flow", 64))
        self.bytes_per_flow = int(self.options.get("bytes_per_flow", 512 * 1024))
        self.after = int(self.options.get("after", 16))
        self.max_flows = int(self.options.get("max_flows", 20_000))
        self._flows: OrderedDict[FlowKey, _FlowBuffer] = OrderedDict()
        self.selected: dict[int, tuple[_Held, list[str]]] = {}
        self._seq = 0
        self._source = ""
        self._sources: list[str] = []

    def on_source(self, path: str) -> None:
        """Called by the session when a new input file starts."""
        self._source = path
        if path not in self._sources:
            self._sources.append(path)

    def open(self, ctx: SinkContext) -> None:
        if not self.target:
            raise ValueError("evidence output needs a file path")

    # packets -----------------------------------------------------------------------------

    def on_packet(self, pkt: Packet) -> None:
        key = flow_key((pkt.src, pkt.sport), (pkt.dst, pkt.dport))
        buf = self._flows.get(key)
        if buf is None:
            if len(self._flows) >= self.max_flows:
                self._flows.popitem(last=False)
            buf = self._flows[key] = _FlowBuffer()
        else:
            self._flows.move_to_end(key)
        frames = [f for f in pkt.fragment_frames if f is not pkt.frame] + [pkt.frame]  # all IP fragments
        added = []
        for frame in frames:
            self._seq += 1
            held = _Held(self._seq, self._source, frame)
            buf.frames.append(held)
            buf.size += len(frame.data)
            added.append(held)
        while buf.frames and (len(buf.frames) > self.frames_per_flow or buf.size > self.bytes_per_flow):
            buf.size -= len(buf.frames.popleft().frame.data)
        if buf.follow > 0:
            buf.follow -= 1
            for held in added:
                self._select(held, None)

    # findings ----------------------------------------------------------------------------

    def write(self, finding: Finding) -> None:
        buf = self._flows.get(flow_key(finding.src, finding.dst))
        if buf is None:
            return
        label = describe(finding)
        # The finding comes from the file being read now; the frame numbers of earlier files
        # (a flow continuing across rotated captures) must not match its frame number.
        trigger = [h for h in buf.frames if h.frame.index == finding.frame and h.source == self._source]
        for held in buf.frames:
            self._select(held, label if trigger and held is trigger[-1] else None)
        if finding.frame and not trigger and buf.frames:
            # The trigger frame left the rolling buffer (very long flow): still note the finding.
            self._select(buf.frames[-1], f"{label} (trigger frame {finding.frame} not retained)")
        buf.follow = self.after

    def _select(self, held: _Held, label: str | None) -> None:
        entry = self.selected.get(held.seq)
        if entry is None:
            entry = self.selected[held.seq] = (held, [])
        if label and label not in entry[1]:
            entry[1].append(label)

    def close(self, stats: RunStats) -> None:
        assert self.target is not None
        with open(self.target, "wb") as fh:
            writer = PcapngWriter(fh)
            many = len(self._sources) > 1
            for seq in sorted(self.selected):
                held, labels = self.selected[seq]
                frame = held.frame
                where = f" of {os.path.basename(held.source)}" if many and held.source else ""
                comment = f"netcreds-ng: original frame {frame.index}{where}"
                if labels:
                    comment += "; " + "; ".join(labels)
                writer.write(frame.data, frame.timestamp, frame.linktype, frame.wirelen, comment)
