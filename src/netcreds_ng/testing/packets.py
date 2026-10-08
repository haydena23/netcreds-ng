"""Deterministic packet crafting for fixtures and plugin tests (no scapy needed).

Example::

    conv = TCPConversation("192.0.2.10", 51000, "192.0.2.20", 21)
    conv.handshake()
    conv.server(b"220 ready\\r\\n")
    conv.client(b"USER alice\\r\\n")
    write_pcap("ftp.pcap", conv.frames)
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcreds_ng.engine.pcapio import PcapWriter

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _is6(ip: str) -> bool:
    return ":" in ip


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 1, frag: int = 0, ttl: int = 64) -> bytes:
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), ident & 0xFFFF, frag, ttl, proto, 0,
        ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed,
    )  # fmt: skip
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes, hop: int = 64) -> bytes:
    return (
        struct.pack("!IHBB", 6 << 28, len(payload), nxt, hop)
        + ipaddress.IPv6Address(src).packed
        + ipaddress.IPv6Address(dst).packed
        + payload
    )


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if _is6(src):
        return (
            ipaddress.IPv6Address(src).packed
            + ipaddress.IPv6Address(dst).packed
            + struct.pack("!IxxxB", length, proto)
        )
    return ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!xBH", proto, length)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", window: int = 65535) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq % (1 << 32), ack % (1 << 32), 5 << 4, flags, window, 0, 0)
    csum = checksum(_pseudo(src, dst, 6, len(hdr) + len(payload)) + hdr + payload)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:] + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = checksum(_pseudo(src, dst, 17, len(hdr) + len(payload)) + hdr + payload) or 0xFFFF
    return hdr[:6] + struct.pack("!H", csum) + payload


def ip_packet(src: str, dst: str, proto: int, l4: bytes, ident: int = 1) -> bytes:
    return ipv6(src, dst, proto, l4) if _is6(src) else ipv4(src, dst, proto, l4, ident=ident)


def ether(payload: bytes, ethertype: int, src: bytes = MAC_A, dst: bytes = MAC_B, vlan: int | None = None) -> bytes:
    if vlan is not None:
        return dst + src + struct.pack("!HHH", 0x8100, vlan & 0x0FFF, ethertype) + payload
    return dst + src + struct.pack("!H", ethertype) + payload


def frame_for(ip_bytes: bytes, linktype: int = 1, vlan: int | None = None) -> bytes:
    """Wrap an IP packet for the given link type."""
    v6 = ip_bytes[0] >> 4 == 6
    if linktype == 1:
        return ether(ip_bytes, 0x86DD if v6 else 0x0800, vlan=vlan)
    if linktype == 0:  # BSD loopback, host byte order (little endian here)
        return struct.pack("<I", 30 if v6 else 2) + ip_bytes
    if linktype == 101:
        return ip_bytes
    if linktype == 113:  # Linux cooked v1
        return struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\0\0", 0x86DD if v6 else 0x0800) + ip_bytes
    raise ValueError(f"unsupported link type {linktype}")


@dataclass
class Frame:
    data: bytes
    timestamp: float


@dataclass
class TCPConversation:
    """Builds a TCP conversation with correct sequence/ack numbers."""

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_isn: int = 1000
    server_isn: int = 5000
    linktype: int = 1
    vlan: int | None = None
    start: float = 1_700_000_000.0
    step: float = 0.01
    frames: list[Frame] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.c_seq = self.client_isn
        self.s_seq = self.server_isn
        self._t = self.start
        self._ident = 1

    def _emit(self, from_client: bool, flags: int, payload: bytes = b"", seq: int | None = None) -> bytes:
        if from_client:
            src, dst, sp, dp = self.client_ip, self.server_ip, self.client_port, self.server_port
            s, a = (self.c_seq if seq is None else seq), self.s_seq
        else:
            src, dst, sp, dp = self.server_ip, self.client_ip, self.server_port, self.client_port
            s, a = (self.s_seq if seq is None else seq), self.c_seq
        seg = tcp(src, dst, sp, dp, s, a if flags & ACK else 0, flags, payload)
        raw = frame_for(ip_packet(src, dst, 6, seg, ident=self._ident), self.linktype, self.vlan)
        self._ident += 1
        self.frames.append(Frame(raw, self._t))
        self._t += self.step
        return raw

    def handshake(self) -> TCPConversation:
        self._emit(True, SYN)
        self.c_seq += 1
        self._emit(False, SYN | ACK)
        self.s_seq += 1
        self._emit(True, ACK)
        return self

    def client(self, data: bytes, segment: int | None = None) -> TCPConversation:
        return self._send(True, data, segment)

    def server(self, data: bytes, segment: int | None = None) -> TCPConversation:
        return self._send(False, data, segment)

    def _send(self, from_client: bool, data: bytes, segment: int | None) -> TCPConversation:
        size = segment or max(1, len(data))
        for i in range(0, len(data), size):
            chunk = data[i : i + size]
            self._emit(from_client, PSH | ACK, chunk)
            if from_client:
                self.c_seq += len(chunk)
            else:
                self.s_seq += len(chunk)
        return self

    def raw_segment(self, from_client: bool, data: bytes, rel_offset: int = 0) -> TCPConversation:
        """Emit a segment at an explicit offset from the current sequence without advancing it
        (for retransmission / out-of-order fixtures)."""
        base = self.c_seq if from_client else self.s_seq
        self._emit(from_client, PSH | ACK, data, seq=base + rel_offset)
        return self

    def advance(self, from_client: bool, n: int) -> TCPConversation:
        if from_client:
            self.c_seq += n
        else:
            self.s_seq += n
        return self

    def close(self) -> TCPConversation:
        self._emit(True, FIN | ACK)
        self.c_seq += 1
        self._emit(False, FIN | ACK)
        self.s_seq += 1
        self._emit(True, ACK)
        return self


def udp_frame(src: str, sport: int, dst: str, dport: int, payload: bytes, linktype: int = 1) -> bytes:
    return frame_for(ip_packet(src, dst, 17, udp(src, dst, sport, dport, payload)), linktype)


def write_pcap(path: str, frames: Iterable[Frame | bytes], linktype: int = 1) -> None:
    with open(path, "wb") as fh:
        writer = PcapWriter(fh, linktype)
        t = 1_700_000_000.0
        for fr in frames:
            if isinstance(fr, Frame):
                writer.write(fr.data, fr.timestamp)
            else:
                writer.write(fr, t)
                t += 0.01
