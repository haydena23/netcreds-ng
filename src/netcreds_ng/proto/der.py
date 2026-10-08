"""Small, strict, bounds-checked BER/DER reader (enough for Kerberos, SNMP, LDAP)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass


class DERError(ValueError):
    pass


@dataclass(frozen=True)
class TLV:
    tag: int  # full identifier octet (class | constructed | number) for low tag numbers
    data: bytes  # whole buffer
    start: int  # value start
    end: int  # value end
    header_start: int

    @property
    def value(self) -> bytes:
        return self.data[self.start : self.end]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def cls(self) -> int:
        return self.tag >> 6

    @property
    def number(self) -> int:
        return self.tag & 0x1F

    @property
    def encoded(self) -> bytes:
        return self.data[self.header_start : self.end]

    def children(self) -> list[TLV]:
        return list(iter_tlvs(self.data, self.start, self.end))

    def child(self, context_tag: int) -> TLV | None:
        """Explicit context-specific child [n]."""
        want = 0xA0 | context_tag
        for c in self.children():
            if c.tag == want:
                return c
        return None

    def inner(self) -> TLV:
        """The single element inside an explicitly tagged wrapper."""
        kids = self.children()
        if not kids:
            raise DERError("empty explicit tag")
        return kids[0]

    def as_int(self) -> int:
        if not self.value:
            raise DERError("empty integer")
        return int.from_bytes(self.value, "big", signed=True)

    def as_bytes(self) -> bytes:
        return self.value

    def as_str(self) -> str:
        return self.value.decode("utf-8", "backslashreplace")


def read_tlv(data: bytes, pos: int = 0, end: int | None = None) -> TLV:
    end = len(data) if end is None else end
    start = pos
    if pos + 2 > end:
        raise DERError("truncated header")
    tag = data[pos]
    pos += 1
    if tag & 0x1F == 0x1F:  # high tag number form: skip continuation octets
        while True:
            if pos >= end:
                raise DERError("truncated tag")
            b = data[pos]
            pos += 1
            if not b & 0x80:
                break
    if pos >= end:
        raise DERError("truncated length")
    length = data[pos]
    pos += 1
    if length == 0x80:
        raise DERError("indefinite length not supported")
    if length & 0x80:
        n = length & 0x7F
        if n > 4 or pos + n > end:
            raise DERError("bad length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    if pos + length > end:
        raise DERError("value exceeds buffer")
    return TLV(tag, data, pos, pos + length, start)


def iter_tlvs(data: bytes, pos: int = 0, end: int | None = None) -> Iterator[TLV]:
    end = len(data) if end is None else end
    while pos < end:
        tlv = read_tlv(data, pos, end)
        yield tlv
        pos = tlv.end


def find(tlv: TLV, *path: int) -> TLV | None:
    """Follow explicit context tags: find(t, 4, 1) == t.child(4).inner().child(1)."""
    cur: TLV | None = tlv
    for i, tag in enumerate(path):
        if cur is None:
            return None
        cur = cur.child(tag)
        if cur is None:
            return None
        if i < len(path) - 1:
            cur = cur.inner()
    return cur
