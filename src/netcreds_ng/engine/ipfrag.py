"""IPv4/IPv6 fragment reassembly (first-fragment-wins on overlap)."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from netcreds_ng.engine.decode import IPLayer

MAX_DATAGRAM = 65535 + 40
MAX_PENDING = 4096
TIMEOUT = 60.0


@dataclass
class _Pending:
    first_seen: float
    total: int | None = None
    pieces: list[tuple[int, bytes]] = field(default_factory=list)
    size: int = 0


class Defragmenter:
    def __init__(self, max_pending: int = MAX_PENDING, timeout: float = TIMEOUT) -> None:
        self._pending: OrderedDict[tuple[object, ...], _Pending] = OrderedDict()
        self.max_pending = max_pending
        self.timeout = timeout
        self.expired = 0

    def add(self, ip: IPLayer, now: float) -> bytes | None:
        """Add a fragment; return the reassembled L4 payload when complete."""
        self._expire(now)
        key = (ip.version, ip.src, ip.dst, ip.proto, ip.ident)
        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self.max_pending:
                self._pending.popitem(last=False)
                self.expired += 1
            entry = _Pending(first_seen=now)
            self._pending[key] = entry
        end = ip.frag_offset + len(ip.payload)
        if end > MAX_DATAGRAM:
            del self._pending[key]
            self.expired += 1
            return None
        if not ip.more_fragments:
            entry.total = end
        entry.pieces.append((ip.frag_offset, ip.payload))
        entry.size += len(ip.payload)
        if entry.total is None:
            return None
        buf = bytearray(entry.total)
        filled = bytearray(entry.total)
        for offset, data in entry.pieces:  # arrival order: earlier pieces win
            for i, b in enumerate(data[: max(0, entry.total - offset)]):
                if not filled[offset + i]:
                    buf[offset + i] = b
                    filled[offset + i] = 1
        if all(filled):
            del self._pending[key]
            return bytes(buf)
        return None

    def _expire(self, now: float) -> None:
        while self._pending:
            key, entry = next(iter(self._pending.items()))
            if now - entry.first_seen <= self.timeout:
                break
            del self._pending[key]
            self.expired += 1
