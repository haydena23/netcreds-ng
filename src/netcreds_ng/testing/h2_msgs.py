"""Builders for HTTP/2 frames and HPACK header blocks used in tests and fixtures.

The encoder is deliberately explicit: each header is encoded with the
representation the test asks for (indexed, literal with/without indexing,
never indexed, optional Huffman), so tests control exactly what crosses the wire.
Values are obviously fake.
"""

from __future__ import annotations

import struct
from collections import deque

from netcreds_ng.proto.hpack import ENTRY_OVERHEAD, HUFFMAN_CODES, STATIC_TABLE

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = range(10)
END_STREAM, ACK, END_HEADERS, PADDED, PRIORITY_FLAG = 0x1, 0x1, 0x4, 0x8, 0x20
SETTINGS_HEADER_TABLE_SIZE = 0x1


# ---------------------------------------------------------------------------- HPACK


def encode_integer(value: int, prefix: int, first: int = 0) -> bytes:
    mask = (1 << prefix) - 1
    if value < mask:
        return bytes([first | value])
    out = bytearray([first | mask])
    value -= mask
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def huffman_encode(data: bytes) -> bytes:
    acc = nbits = 0
    for b in data:
        code, length = HUFFMAN_CODES[b]
        acc = (acc << length) | code
        nbits += length
    pad = -nbits % 8
    acc = (acc << pad) | ((1 << pad) - 1)
    nbits += pad
    return acc.to_bytes(nbits // 8, "big") if nbits else b""


def encode_string(data: bytes, huffman: bool = False) -> bytes:
    if huffman:
        data = huffman_encode(data)
        return encode_integer(len(data), 7, 0x80) + data
    return encode_integer(len(data), 7) + data


class Encoder:
    """Minimal HPACK encoder that mirrors the dynamic table of the peer's decoder."""

    def __init__(self, max_table_size: int = 4096) -> None:
        self.table: deque[tuple[bytes, bytes]] = deque()
        self.size = 0
        self.max_table_size = max_table_size

    def _add(self, name: bytes, value: bytes) -> None:
        entry = len(name) + len(value) + ENTRY_OVERHEAD
        while self.table and self.size + entry > self.max_table_size:
            n, v = self.table.pop()
            self.size -= len(n) + len(v) + ENTRY_OVERHEAD
        if entry <= self.max_table_size:
            self.table.appendleft((name, value))
            self.size += entry
        else:
            self.table.clear()
            self.size = 0

    def find(self, name: bytes, value: bytes | None = None) -> int:
        """Index of an exact (name, value) match, or of a name match when ``value`` is None; 0 if absent."""
        entries = list(STATIC_TABLE) + list(self.table)
        for i, (n, v) in enumerate(entries, 1):
            if n == name and (value is None or v == value):
                return i
        return 0

    def indexed(self, name: bytes, value: bytes) -> bytes:
        index = self.find(name, value)
        if not index:
            raise KeyError((name, value))
        return encode_integer(index, 7, 0x80)

    def literal(self, name: bytes, value: bytes, mode: str = "index", huffman: bool = False,
                name_index: bool = True) -> bytes:  # fmt: skip
        """``mode``: 'index' (incremental indexing), 'plain' (without indexing) or 'never' (never indexed)."""
        prefix, first = {"index": (6, 0x40), "plain": (4, 0x00), "never": (4, 0x10)}[mode]
        index = self.find(name) if name_index else 0
        out = encode_integer(index, prefix, first)
        if not index:
            out += encode_string(name, huffman)
        out += encode_string(value, huffman)
        if mode == "index":
            self._add(name, value)
        return out

    def size_update(self, size: int) -> bytes:
        self.max_table_size = size
        while self.table and self.size > size:
            n, v = self.table.pop()
            self.size -= len(n) + len(v) + ENTRY_OVERHEAD
        return encode_integer(size, 5, 0x20)

    def encode(self, headers: list[tuple[bytes, bytes]], mode: str = "index", huffman: bool = False) -> bytes:
        """Encode a header list: exact matches as indexed fields, everything else as literals in ``mode``."""
        out = bytearray()
        for name, value in headers:
            if self.find(name, value):
                out += self.indexed(name, value)
            else:
                out += self.literal(name, value, mode, huffman)
        return bytes(out)


# ---------------------------------------------------------------------------- frames


def frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + struct.pack("!I", stream_id & 0x7FFFFFFF) + payload


def settings(values: dict[int, int] | None = None, ack: bool = False) -> bytes:
    payload = b"".join(struct.pack("!HI", k, v) for k, v in (values or {}).items())
    return frame(SETTINGS, ACK if ack else 0, 0, payload)


def headers_frame(stream_id: int, block: bytes, end_stream: bool = False, end_headers: bool = True,
                  pad: int | None = None, priority: bool = False) -> bytes:  # fmt: skip
    flags = (END_STREAM if end_stream else 0) | (END_HEADERS if end_headers else 0)
    payload = block
    if priority:
        flags |= PRIORITY_FLAG
        payload = struct.pack("!IB", 3, 15) + payload  # depends on stream 3, weight 16
    if pad is not None:
        flags |= PADDED
        payload = bytes([pad]) + payload + b"\x00" * pad
    return frame(HEADERS, flags, stream_id, payload)


def continuation(stream_id: int, block: bytes, end_headers: bool = True) -> bytes:
    return frame(CONTINUATION, END_HEADERS if end_headers else 0, stream_id, block)


def data_frame(stream_id: int, data: bytes, end_stream: bool = False, pad: int | None = None) -> bytes:
    flags = END_STREAM if end_stream else 0
    payload = data
    if pad is not None:
        flags |= PADDED
        payload = bytes([pad]) + data + b"\x00" * pad
    return frame(DATA, flags, stream_id, payload)


def rst_stream(stream_id: int, code: int = 8) -> bytes:
    return frame(RST_STREAM, 0, stream_id, struct.pack("!I", code))


def goaway(last_stream: int = 0, code: int = 0) -> bytes:
    return frame(GOAWAY, 0, 0, struct.pack("!II", last_stream, code))


def window_update(stream_id: int = 0, increment: int = 65535) -> bytes:
    return frame(WINDOW_UPDATE, 0, stream_id, struct.pack("!I", increment))


def ping(ack: bool = False) -> bytes:
    return frame(PING, ACK if ack else 0, 0, b"\x00" * 8)


def request_headers(method: bytes, path: bytes, authority: bytes = b"www.example.com", scheme: bytes = b"https",
                    extra: list[tuple[bytes, bytes]] | None = None) -> list[tuple[bytes, bytes]]:  # fmt: skip
    return [(b":method", method), (b":scheme", scheme), (b":authority", authority), (b":path", path), *(extra or [])]
