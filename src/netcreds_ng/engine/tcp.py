"""Unidirectional TCP stream reassembly.

Delivers bytes in sequence order. Handles 32-bit sequence wraparound,
retransmissions, overlaps (first copy wins), out-of-order segments and
bounded buffering. When data is missing the stream eventually skips ahead and
reports an explicit gap so consumers can resynchronise.

Every delivered chunk remembers the frame number and timestamp of the packet that
carried its bytes, so findings cite the right packet even when delivery is triggered
later (out-of-order data, warm-up release, a reply that ends a hole, flow close).
"""

from __future__ import annotations

from dataclasses import dataclass, field

MOD = 1 << 32
HALF = 1 << 31

DEFAULT_MAX_PENDING = 1 << 20  # bytes buffered out of order before forcing a gap
DEFAULT_WARMUP = 4  # segments held for a stream picked up without its SYN
MAX_WARM_BYTES = 64 * 1024

Origin = tuple[int, float]  # (frame number, timestamp) of the packet that carried the bytes
NO_ORIGIN: Origin = (0, 0.0)


def seq_delta(a: int, b: int) -> int:
    """Signed distance a - b in sequence space."""
    return ((a - b + HALF) % MOD) - HALF


@dataclass
class Chunk:
    data: bytes
    gap_before: int = 0  # bytes missing immediately before this chunk
    frame: int = 0  # frame that carried these bytes (0: unknown)
    timestamp: float = 0.0
    decrypted: bool = False  # plaintext recovered from TLS with a key log


@dataclass
class TCPStream:
    max_pending: int = DEFAULT_MAX_PENDING
    next_seq: int | None = None
    offset: int = 0  # stream bytes consumed (delivered + skipped)
    pending: dict[int, bytes] = field(default_factory=dict)
    origins: dict[int, Origin] = field(default_factory=dict)  # same keys as ``pending``
    pending_bytes: int = 0
    retransmitted: int = 0
    gaps: int = 0
    gap_bytes: int = 0
    fin: bool = False
    syn_seen: bool = False
    isn: int | None = None
    #: Segments held when a stream is picked up without its SYN, so a segment reordered
    #: ahead of the first captured one is not mistaken for a retransmission. 0 disables.
    warmup: int = DEFAULT_WARMUP
    warm: list[tuple[int, bytes, Origin]] = field(default_factory=list)
    warm_bytes: int = 0

    @property
    def warming(self) -> bool:
        return bool(self.warm)

    def release(self) -> list[Chunk]:
        """End the warm-up: start the stream at the lowest held sequence number and deliver."""
        if not self.warm:
            return []
        warm, self.warm, self.warm_bytes = self.warm, [], 0
        base = warm[0][0]
        warm.sort(key=lambda s: seq_delta(s[0], base))
        self.next_seq = warm[0][0]
        out: list[Chunk] = []
        for seq, data, origin in warm:
            out.extend(self.add(seq, data, origin=origin))
        return out

    def add(self, seq: int, data: bytes, syn: bool = False, fin: bool = False,
            origin: Origin = NO_ORIGIN) -> list[Chunk]:  # fmt: skip
        out: list[Chunk] = []
        if syn:
            if self.warm:
                out.extend(self.release())
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
        if self.next_seq is None:  # picked up mid-stream
            if self.warmup:
                self.warm.append((seq, data, origin))
                self.warm_bytes += len(data)
                if len(self.warm) >= self.warmup or self.warm_bytes >= MAX_WARM_BYTES:
                    out.extend(self.release())
                return out
            self.next_seq = seq
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
            self._deliver(data, out, origin=origin)
            self._drain(out)
            return out
        start = self.offset + delta
        existing = self.pending.get(start)
        if existing is None or len(existing) < len(data):
            self.pending_bytes += len(data) - (len(existing) if existing else 0)
            self.pending[start] = data
            self.origins[start] = origin
        else:
            self.retransmitted += len(data)
        if self.pending_bytes > self.max_pending:
            self._skip_to_pending(out)
        return out

    def acknowledged(self, ack: int) -> list[Chunk]:
        """The peer acknowledged up to ``ack`` in a packet carrying data. Holes below it were lost
        by the capture, not the network (the receiver got those bytes), so waiting for a
        retransmission is pointless: skip them now and deliver the buffered data, keeping
        request/response order."""
        out: list[Chunk] = []
        if not self.pending or self.next_seq is None:
            return out
        acked = self.offset + seq_delta(ack, self.next_seq)
        while self.pending and min(self.pending) < acked:
            self._skip_to_pending(out)
        return out

    def flush(self) -> list[Chunk]:
        """Deliver everything still buffered, reporting gaps. Call when the flow ends."""
        out = self.release()
        while self.pending:
            self._skip_to_pending(out)
        return out

    # internals -------------------------------------------------------------

    def _pop(self, start: int) -> tuple[bytes, Origin]:
        data = self.pending.pop(start)
        self.pending_bytes -= len(data)
        return data, self.origins.pop(start, NO_ORIGIN)

    def _deliver(self, data: bytes, out: list[Chunk], gap: int = 0, origin: Origin = NO_ORIGIN) -> None:
        out.append(Chunk(data, gap, origin[0], origin[1]))
        self.offset += len(data)
        assert self.next_seq is not None
        self.next_seq = (self.next_seq + len(data)) % MOD

    def _drain(self, out: list[Chunk]) -> None:
        while self.pending:
            start = min(self.pending)
            if start > self.offset:
                return
            data, origin = self._pop(start)
            skip = self.offset - start
            if skip >= len(data):
                self.retransmitted += len(data)
                continue
            self.retransmitted += skip
            self._deliver(data[skip:], out, origin=origin)

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
            data, origin = self._pop(start)
            self._deliver(data, out, gap, origin)
        self._drain(out)
