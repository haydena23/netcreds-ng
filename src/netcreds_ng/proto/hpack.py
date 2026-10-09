"""HPACK header decompression for HTTP/2 (RFC 7541), decoder side only.

Used by the ``http2`` plugin to read request/response header blocks passively.
Every header block that crosses the wire must be decoded in order, because the
dynamic table is shared state between the peer's encoder and our decoder: a
single missed block makes every later indexed reference unreliable.

Names and values stay ``bytes`` (wire representation); callers decode for display.
Never-indexed literals (RFC 7541 §6.2.3) are decoded like any other literal and
flagged, because they are frequently exactly the sensitive headers being audited.
"""

from __future__ import annotations

from collections import deque
from typing import NamedTuple

DEFAULT_TABLE_SIZE = 4096
#: absolute ceiling on any dynamic table size we accept (memory bound for hostile input)
HARD_TABLE_LIMIT = 1 << 20
MAX_STRING = 256 * 1024
MAX_HEADER_LIST = 512 * 1024
ENTRY_OVERHEAD = 32


class HpackError(ValueError):
    """The header block is malformed; the decoding context is no longer trustworthy."""


class Header(NamedTuple):
    name: bytes
    value: bytes
    never_indexed: bool = False


# RFC 7541 Appendix A
STATIC_TABLE: tuple[tuple[bytes, bytes], ...] = (
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
)
assert len(STATIC_TABLE) == 61

# RFC 7541 Appendix B: Huffman code bit lengths for symbols 0..255 and EOS (256).
# The code is canonical (codes ascend with (length, symbol)), so the code values
# are derived from the lengths below; tests check them against values from the RFC
# table and against the Appendix C examples.
HUFFMAN_LENGTHS: tuple[int, ...] = (
    # 0-31: control characters
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    # 32-47: ' ' ! " # $ % & ' ( ) * + , - . /
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    # 48-63: 0-9 : ; < = > ?
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    # 64-79: @ A-O
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    # 80-95: P-Z [ \ ] ^ _
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    # 96-111: ` a-o
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    # 112-127: p-z { | } ~ DEL
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    # 128-255
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    # EOS
    30,
)  # fmt: skip
assert len(HUFFMAN_LENGTHS) == 257
EOS = 256


def _canonical_codes(lengths: tuple[int, ...]) -> tuple[tuple[int, int], ...]:
    order = sorted(range(len(lengths)), key=lambda s: (lengths[s], s))
    codes: list[tuple[int, int]] = [(0, 0)] * len(lengths)
    code, prev = 0, lengths[order[0]]
    for i, sym in enumerate(order):
        length = lengths[sym]
        if i:
            code = (code + 1) << (length - prev)
        prev = length
        codes[sym] = (code, length)
    return tuple(codes)


#: (code, bit length) for each symbol, as in RFC 7541 Appendix B
HUFFMAN_CODES = _canonical_codes(HUFFMAN_LENGTHS)

# Canonical decoding tables: per length, the first code, the symbol count and the
# offset of its first symbol in _SYMBOLS.
_SYMBOLS = tuple(sorted(range(257), key=lambda s: (HUFFMAN_LENGTHS[s], s)))
_MAXLEN = max(HUFFMAN_LENGTHS)
_FIRST = [0] * (_MAXLEN + 1)
_COUNT = [0] * (_MAXLEN + 1)
_OFFSET = [0] * (_MAXLEN + 1)
for _i, _s in enumerate(_SYMBOLS):
    _len = HUFFMAN_LENGTHS[_s]
    if _COUNT[_len] == 0:
        _FIRST[_len] = HUFFMAN_CODES[_s][0]
        _OFFSET[_len] = _i
    _COUNT[_len] += 1


def huffman_decode(data: bytes) -> bytes:
    """Decode a Huffman-coded string literal (RFC 7541 §5.2)."""
    out = bytearray()
    code = length = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            length += 1
            if _COUNT[length]:
                idx = code - _FIRST[length]
                if 0 <= idx < _COUNT[length]:
                    sym = _SYMBOLS[_OFFSET[length] + idx]
                    if sym == EOS:
                        raise HpackError("EOS symbol inside a Huffman string")
                    out.append(sym)
                    code = length = 0
                    continue
            if length >= _MAXLEN:
                raise HpackError("invalid Huffman code")
    # Padding: at most 7 bits, all ones (the most significant bits of EOS).
    if length > 7 or code != (1 << length) - 1:
        raise HpackError("invalid Huffman padding")
    return bytes(out)


def decode_integer(data: bytes, pos: int, prefix: int) -> tuple[int, int]:
    """Decode an N-bit prefix integer at ``data[pos]`` (RFC 7541 §5.1). Returns (value, next position)."""
    if pos >= len(data):
        raise HpackError("truncated integer")
    mask = (1 << prefix) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise HpackError("truncated integer")
        b = data[pos]
        pos += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value, pos
        if shift > 28:  # > 2**35: no legitimate HPACK integer is this large
            raise HpackError("integer too large")


class Decoder:
    """One HPACK decoding context (one per direction of an HTTP/2 connection)."""

    def __init__(self, max_table_size: int = DEFAULT_TABLE_SIZE) -> None:
        self._table: deque[tuple[bytes, bytes]] = deque()
        self.table_bytes = 0
        self.max_table_size = max_table_size  # current size, changed by dynamic table size updates
        #: largest size a dynamic table size update may request (from the peer's SETTINGS_HEADER_TABLE_SIZE)
        self.size_limit = max_table_size

    def allow_table_size(self, value: int) -> None:
        """Record a SETTINGS_HEADER_TABLE_SIZE advertised by this decoder's side.

        A passive observer cannot tell exactly when the encoder saw the SETTINGS
        acknowledgement, so the limit only ever grows (bounded by HARD_TABLE_LIMIT).
        This only relaxes validation: the table size actually in use always comes
        from the dynamic table size updates the encoder sends, so decoding stays exact.
        """
        self.size_limit = max(self.size_limit, min(value, HARD_TABLE_LIMIT))

    @property
    def table(self) -> list[tuple[bytes, bytes]]:
        """Dynamic table entries, newest first (index 62 is the first)."""
        return list(self._table)

    def _evict(self, room: int = 0) -> None:
        while self._table and self.table_bytes + room > self.max_table_size:
            name, value = self._table.pop()
            self.table_bytes -= len(name) + len(value) + ENTRY_OVERHEAD

    def _add(self, name: bytes, value: bytes) -> None:
        size = len(name) + len(value) + ENTRY_OVERHEAD
        if size > self.max_table_size:
            self._table.clear()
            self.table_bytes = 0
            return
        self._evict(size)
        self._table.appendleft((name, value))
        self.table_bytes += size

    def _entry(self, index: int) -> tuple[bytes, bytes]:
        if index <= 0:
            raise HpackError("index 0")
        if index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        dyn = index - len(STATIC_TABLE) - 1
        if dyn >= len(self._table):
            raise HpackError(f"index {index} out of range")
        return self._table[dyn]

    def _string(self, data: bytes, pos: int) -> tuple[bytes, int]:
        if pos >= len(data):
            raise HpackError("truncated string")
        huffman = bool(data[pos] & 0x80)
        length, pos = decode_integer(data, pos, 7)
        if length > MAX_STRING:
            raise HpackError("string literal too long")
        end = pos + length
        if end > len(data):
            raise HpackError("truncated string")
        raw = bytes(data[pos:end])
        return (huffman_decode(raw) if huffman else raw), end

    def decode(self, block: bytes) -> list[Header]:
        """Decode one complete header block, updating the dynamic table."""
        headers: list[Header] = []
        pos = 0
        total = 0
        n = len(block)
        while pos < n:
            b = block[pos]
            if b & 0x80:  # indexed header field
                index, pos = decode_integer(block, pos, 7)
                name, value = self._entry(index)
                header = Header(name, value)
            elif b & 0xE0 == 0x20:  # dynamic table size update
                if headers:
                    raise HpackError("table size update after a header field")
                size, pos = decode_integer(block, pos, 5)
                if size > self.size_limit:
                    raise HpackError(f"table size update {size} exceeds limit {self.size_limit}")
                self.max_table_size = size
                self._evict()
                continue
            else:
                if b & 0x40:  # literal with incremental indexing
                    prefix, indexing, never = 6, True, False
                else:  # without indexing (0000xxxx) or never indexed (0001xxxx)
                    prefix, indexing, never = 4, False, bool(b & 0x10)
                index, pos = decode_integer(block, pos, prefix)
                if index:
                    name = self._entry(index)[0]
                else:
                    name, pos = self._string(block, pos)
                value, pos = self._string(block, pos)
                if indexing:
                    self._add(name, value)
                header = Header(name, value, never)
            total += len(header.name) + len(header.value) + ENTRY_OVERHEAD
            if total > MAX_HEADER_LIST:
                raise HpackError("header list too large")
            headers.append(header)
        return headers
