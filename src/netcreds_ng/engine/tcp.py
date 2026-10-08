"""Unidirectional TCP stream reassembly.

Delivers bytes in sequence order. Handles 32-bit sequence wraparound,
retransmissions, overlaps (first copy wins), out-of-order segments and
bounded buffering. When data is missing the stream eventually skips ahead and
reports an explicit gap so consumers can resynchronise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MOD = 1 << 32
HALF = 1 << 31

DEFAULT_MAX_PENDING = 1 << 20  # bytes buffered out of order before forcing a gap


def seq_delta(a: int, b: int) -> int:
    """Signed distance a - b in sequence space."""
    return ((a - b + HALF) % MOD) - HALF


@dataclass
class Chunk:
    data: bytes
    gap_before: int = 0  # bytes missing immediately before this chunk


@dataclass
class TCPStream:
    max_pending: int = DEFAULT_MAX_PENDING
    next_seq: int | None = None
    offset: int = 0  # stream bytes consumed (delivered + skipped)
    pending: dict[int, bytes] = field(default_factory=dict)
    pending_bytes: int = 0
    retransmitted: int = 0
    gaps: int = 0
    gap_bytes: int = 0
    fin: bool = False
    syn_seen: bool = False
    isn: int | None = None

    def add(self, seq: int, data: bytes, syn: bool = False, fin: bool = False) -> list[Chunk]:
        out: list[Chunk] = []
        if syn:
            self.syn_seen = True
            if self.isn is None:
                self.isn = seq
            if self.next_seq is None or self.offset == 0:
                self.next_seq = (seq + 1) % MOD
            seq = (seq + 1) % MOD  # SYN occupies one sequence number
        if fin:
            self.fin = True
        if not data:
            return out
        if self.next_seq is None:
            self.next_seq = seq  # picked up mid-stream
        delta = seq_delta(seq, self.next_seq)
        if delta < 0:
            overlap = -delta
            if overlap >= len(data):
                self.retransmitted += len(data)
                return out
            self.retransmitted += overlap
            data = data[overlap:]
            delta = 0
        if delta == 0:
            self._deliver(data, out)
            self._drain(out)
            return out
        start = self.offset + delta
        existing = self.pending.get(start)
        if existing is None or len(existing) < len(data):
            self.pending_bytes += len(data) - (len(existing) if existing else 0)
            self.pending[start] = data
        else:
            self.retransmitted += len(data)
        if self.pending_bytes > self.max_pending:
            self._skip_to_pending(out)
        return out

    def flush(self) -> list[Chunk]:
        """Deliver everything still buffered, reporting gaps. Call when the flow ends."""
        out: list[Chunk] = []
        while self.pending:
            self._skip_to_pending(out)
        return out

    # internals -------------------------------------------------------------

    def _deliver(self, data: bytes, out: list[Chunk], gap: int = 0) -> None:
        out.append(Chunk(data, gap))
        self.offset += len(data)
        assert self.next_seq is not None
        self.next_seq = (self.next_seq + len(data)) % MOD

    def _drain(self, out: list[Chunk]) -> None:
        while self.pending:
            start = min(self.pending)
            if start > self.offset:
                return
            data = self.pending.pop(start)
            self.pending_bytes -= len(data)
            skip = self.offset - start
            if skip >= len(data):
                self.retransmitted += len(data)
                continue
            self.retransmitted += skip
            self._deliver(data[skip:], out)

    def _skip_to_pending(self, out: list[Chunk]) -> None:
        if not self.pending:
            return
        start = min(self.pending)
        gap = start - self.offset
        if gap > 0:
            self.gaps += 1
            self.gap_bytes += gap
            self.offset = start
            assert self.next_seq is not None
            self.next_seq = (self.next_seq + gap) % MOD
            data = self.pending.pop(start)
            self.pending_bytes -= len(data)
            self._deliver(data, out, gap)
        self._drain(out)
