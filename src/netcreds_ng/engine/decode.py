"""Link-type aware frame decoder: L2 -> IPv4/IPv6 -> TCP/UDP.

Pure functions over ``bytes``. Every length field is bounds-checked; anything
that cannot be decoded returns ``None`` (counted by the engine) rather than
raising.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from netcreds_ng.engine.pcapio import RawFrame

# libpcap link types
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101
DLT_RAW_ALT1 = 12
DLT_RAW_ALT2 = 14
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = (0x8100, 0x88A8, 0x9100)
ETH_PPPOE_SESSION = 0x8864

PROTO_TCP = 6
PROTO_UDP = 17

# IPv6 extension headers we walk through
_IPV6_EXT = {0, 43, 60, 51}
_IPV6_FRAG = 44

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


@dataclass
class IPLayer:
    version: int
    src: str
    dst: str
    proto: int
    header_len: int
    payload: bytes  # L4 bytes, trimmed to the IP length field
    ident: int = 0
    frag_offset: int = 0  # in bytes
    more_fragments: bool = False
    truncated: bool = False

    @property
    def is_fragment(self) -> bool:
        return self.more_fragments or self.frag_offset > 0


@dataclass
class Packet:
    """A decoded frame. ``payload`` is the L4 payload (TCP/UDP data)."""

    frame: RawFrame
    l3_offset: int
    ip: IPLayer
    proto: int  # PROTO_TCP / PROTO_UDP / other
    sport: int = 0
    dport: int = 0
    seq: int = 0
    ack: int = 0
    flags: int = 0
    l4_header_len: int = 0
    payload: bytes = b""
    truncated: bool = False

    @property
    def src(self) -> str:
        return self.ip.src

    @property
    def dst(self) -> str:
        return self.ip.dst

    @property
    def timestamp(self) -> float:
        return self.frame.timestamp

    @property
    def index(self) -> int:
        return self.frame.index


def _ip4(raw: bytes) -> str:
    return "%d.%d.%d.%d" % (raw[0], raw[1], raw[2], raw[3])


def _ip6(raw: bytes) -> str:
    return str(ipaddress.IPv6Address(raw))


def l3_offset(frame: RawFrame) -> tuple[int, int] | None:
    """Return (offset of the IP header, ethertype-like protocol) for a frame, or None."""
    data = frame.data
    lt = frame.linktype
    if lt == DLT_EN10MB:
        if len(data) < 14:
            return None
        off = 12
        (etype,) = struct.unpack("!H", data[off : off + 2])
        off += 2
        while etype in ETH_VLAN:
            if len(data) < off + 4:
                return None
            (etype,) = struct.unpack("!H", data[off + 2 : off + 4])
            off += 4
        if etype == ETH_PPPOE_SESSION:
            if len(data) < off + 8:
                return None
            (ppp_proto,) = struct.unpack("!H", data[off + 6 : off + 8])
            off += 8
            etype = {0x0021: ETH_IPV4, 0x0057: ETH_IPV6}.get(ppp_proto, 0)
        return off, etype
    if lt in (DLT_RAW, DLT_RAW_ALT1, DLT_RAW_ALT2, DLT_IPV4, DLT_IPV6):
        if not data:
            return None
        version = data[0] >> 4
        return 0, ETH_IPV4 if version == 4 else ETH_IPV6 if version == 6 else 0
    if lt in (DLT_NULL, DLT_LOOP):
        if len(data) < 4:
            return None
        fam_le = struct.unpack("<I", data[:4])[0]
        fam_be = struct.unpack(">I", data[:4])[0]
        fam = fam_be if lt == DLT_LOOP else (fam_le if fam_le < 0x10000 else fam_be)
        if fam == 2:
            return 4, ETH_IPV4
        if fam in (10, 23, 24, 28, 30):
            return 4, ETH_IPV6
        return None
    if lt == DLT_LINUX_SLL:
        if len(data) < 16:
            return None
        return 16, struct.unpack("!H", data[14:16])[0]
    if lt == DLT_LINUX_SLL2:
        if len(data) < 20:
            return None
        return 20, struct.unpack("!H", data[0:2])[0]
    return None


def decode_ip(data: bytes) -> IPLayer | None:
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        total_len, ident, frag = struct.unpack("!HHH", data[2:8])
        proto = data[9]
        truncated = False
        if total_len < ihl:
            # TSO/offload captures sometimes report 0; fall back to captured length.
            end = len(data)
        else:
            end = total_len
            if end > len(data):
                truncated = True
                end = len(data)
        return IPLayer(
            version=4,
            src=_ip4(data[12:16]),
            dst=_ip4(data[16:20]),
            proto=proto,
            header_len=ihl,
            payload=data[ihl:end],
            ident=ident,
            frag_offset=(frag & 0x1FFF) * 8,
            more_fragments=bool(frag & 0x2000),
            truncated=truncated,
        )
    if version == 6:
        if len(data) < 40:
            return None
        (plen,) = struct.unpack("!H", data[4:6])
        nxt = data[6]
        src, dst = _ip6(data[8:24]), _ip6(data[24:40])
        end = 40 + plen
        truncated = end > len(data)
        end = min(end, len(data))
        off = 40
        ident = frag_offset = 0
        more = False
        while nxt in _IPV6_EXT or nxt == _IPV6_FRAG:
            if off + 8 > end:
                return None
            if nxt == _IPV6_FRAG:
                fo, ident = struct.unpack("!HI", data[off + 2 : off + 8])
                frag_offset = (fo >> 3) * 8
                more = bool(fo & 1)
                nxt = data[off]
                off += 8
                continue
            hdr_len = (data[off + 1] + 2) * 4 if nxt == 51 else (data[off + 1] + 1) * 8
            nxt = data[off]
            off += hdr_len
        if off > end:
            return None
        return IPLayer(6, src, dst, nxt, off, data[off:end], ident, frag_offset, more, truncated)
    return None


def decode_l4(frame: RawFrame, l3off: int, ip: IPLayer, l4: bytes | None = None) -> Packet:
    """Decode the transport header. ``l4`` overrides ``ip.payload`` (used after defragmentation)."""
    seg = ip.payload if l4 is None else l4
    pkt = Packet(frame=frame, l3_offset=l3off, ip=ip, proto=ip.proto, truncated=ip.truncated)
    if ip.is_fragment and l4 is None:
        return pkt  # transport header is only meaningful after reassembly
    if ip.proto == PROTO_TCP:
        if len(seg) < 20:
            pkt.truncated = True
            return pkt
        sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", seg[:14])
        doff = (off_flags >> 12) * 4
        if doff < 20 or doff > len(seg):
            pkt.truncated = True
            return pkt
        pkt.sport, pkt.dport, pkt.seq, pkt.ack = sport, dport, seq, ack
        pkt.flags = off_flags & 0x1FF
        pkt.l4_header_len = doff
        pkt.payload = seg[doff:]
    elif ip.proto == PROTO_UDP:
        if len(seg) < 8:
            pkt.truncated = True
            return pkt
        sport, dport, ulen = struct.unpack("!HHH", seg[:6])
        pkt.sport, pkt.dport = sport, dport
        pkt.l4_header_len = 8
        end = ulen if 8 <= ulen <= len(seg) else len(seg)
        if ulen > len(seg):
            pkt.truncated = True
        pkt.payload = seg[8:end]
    return pkt


def decode_frame(frame: RawFrame) -> Packet | None:
    """Decode a frame down to the transport layer, or return None if it carries no IP."""
    res = l3_offset(frame)
    if res is None:
        return None
    off, etype = res
    if etype not in (ETH_IPV4, ETH_IPV6):
        return None
    ip = decode_ip(frame.data[off:])
    if ip is None:
        return None
    return decode_l4(frame, off, ip)
