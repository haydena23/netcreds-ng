"""IPv4/IPv6 fragment reassembly (first-fragment-wins on overlap).

Coverage is tracked as a sorted list of disjoint ``[start, end)`` intervals, so
adding a fragment costs O(fragments) rather than O(bytes). Completed datagrams
are remembered briefly so late duplicate fragments are dropped instead of
opening a new entry that lingers until the timeout.
"""

from __future__ import annotations

import zlib
from collections import OrderedDict
from dataclasses import dataclass, field

from netcreds_ng.engine.decode import IPLayer

MAX_DATAGRAM = 65535 + 40
MAX_PENDING = 4096
MAX_BUFFERED = 4 * MAX_DATAGRAM  # bytes held per datagram, duplicates included
TIMEOUT = 60.0
RECENT_KEEP = 4096

Interval = tuple[int, int]


def _subtract(start: int, end: int, covered: list[Interval]) -> list[Interval]:
    """Parts of ``[start, end)`` not inside any interval of ``covered`` (sorted, disjoint)."""
    out: list[Interval] = []
    pos = start
    for cs, ce in covered:
        if ce <= pos:
            continue
        if cs >= end:
            break
        if cs > pos:
            out.append((pos, cs))
        pos = max(pos, ce)
        if pos >= end:
            break
    if pos < end:
        out.append((pos, end))
    return out


def _insert(covered: list[Interval], start: int, end: int) -> None:
    """Merge ``[start, end)`` into ``covered`` in place."""
    if start >= end:
        return
    merged: list[Interval] = []
    placed = False
    for cs, ce in covered:
        if ce < start:
            merged.append((cs, ce))
        elif cs > end:
            if not placed:
                merged.append((start, end))
                placed = True
            merged.append((cs, ce))
        else:
            start, end = min(start, cs), max(end, ce)
    if not placed:
        merged.append((start, end))
    covered[:] = merged


@dataclass
class _Pending:
    first_seen: float
    total: int | None = None
    pieces: list[tuple[int, bytes]] = field(default_factory=list)
    covered: list[Interval] = field(default_factory=list)
    size: int = 0
    frames: list[object] = field(default_factory=list)  # the frames that carried the fragments


class Defragmenter:
    def __init__(self, max_pending: int = MAX_PENDING, timeout: float = TIMEOUT) -> None:
        self._pending: OrderedDict[tuple[object, ...], _Pending] = OrderedDict()
        # key -> (completion time, {(offset, length, crc32)} of the pieces that formed it)
        self._recent: OrderedDict[tuple[object, ...], tuple[float, set[tuple[int, int, int]]]] = OrderedDict()
        self.max_pending = max_pending
        self.timeout = timeout
        self.expired = 0
        self.duplicates = 0
        #: Frames of the datagram most recently completed by :meth:`add` (for evidence capture).
        self.last_frames: list[object] = []

    def add(self, ip: IPLayer, now: float, frame: object = None) -> bytes | None:
        """Add a fragment; return the reassembled L4 payload when complete."""
        self._expire(now)
        key = (ip.version, ip.src, ip.dst, ip.proto, ip.ident)
        recent = self._recent.get(key)
        if recent is not None:
            if (ip.frag_offset, len(ip.payload), zlib.crc32(ip.payload)) in recent[1]:
                self.duplicates += 1  # late copy of a fragment of an already reassembled datagram
                return None
            del self._recent[key]  # same ident, different content: a new datagram
        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self.max_pending:
                self._pending.popitem(last=False)
                self.expired += 1
            entry = _Pending(first_seen=now)
            self._pending[key] = entry
        end = ip.frag_offset + len(ip.payload)
        if end > MAX_DATAGRAM or entry.size + len(ip.payload) > MAX_BUFFERED:
            del self._pending[key]
            self.expired += 1
            return None
        if not ip.more_fragments and entry.total is None:
            entry.total = end
        entry.pieces.append((ip.frag_offset, ip.payload))
        if frame is not None:
            entry.frames.append(frame)
        entry.size += len(ip.payload)
        _insert(entry.covered, ip.frag_offset, end)
        total = entry.total
        if total is None or not entry.covered or entry.covered[0][0] > 0 or entry.covered[0][1] < total:
            return None
        buf = bytearray(total)
        filled: list[Interval] = []
        for offset, data in entry.pieces:  # arrival order: earlier pieces win
            stop = min(offset + len(data), total)
            for s, e in _subtract(offset, stop, filled):
                buf[s:e] = data[s - offset : e - offset]
            _insert(filled, offset, stop)
        del self._pending[key]
        self.last_frames = entry.frames
        self._recent[key] = (now, {(o, len(d), zlib.crc32(d)) for o, d in entry.pieces})
        if len(self._recent) > RECENT_KEEP:
            self._recent.popitem(last=False)
        return bytes(buf)

    def expire_all(self) -> None:
        """End of input: every incomplete datagram is lost."""
        self.expired += len(self._pending)
        self._pending.clear()

    @property
    def pending(self) -> int:
        return len(self._pending)

    def _expire(self, now: float) -> None:
        while self._pending:
            key, entry = next(iter(self._pending.items()))
            if now - entry.first_seen <= self.timeout:
                break
            del self._pending[key]
            self.expired += 1
        while self._recent:
            key, (seen, _) = next(iter(self._recent.items()))
            if now - seen <= self.timeout:
                break
            del self._recent[key]
