"""Capture I/O, decoding, TCP reassembly and IP defragmentation."""

from __future__ import annotations

import struct

import pytest

from netcreds_ng.engine.decode import PROTO_TCP, PROTO_UDP, decode_frame, decode_ip
from netcreds_ng.engine.ipfrag import Defragmenter
from netcreds_ng.engine.pcapio import CaptureFormatError, PcapWriter, RawFrame, open_capture
from netcreds_ng.engine.tcp import TCPStream, seq_delta
from netcreds_ng.testing.packets import TCPConversation, frame_for, ip_packet, ipv4, tcp, udp, write_pcap

C, S = "192.0.2.10", "198.51.100.20"


# --- pcap / pcapng ----------------------------------------------------------------


def _frame(payload: bytes = b"x") -> bytes:
    return frame_for(ip_packet(C, S, 17, udp(C, S, 1000, 2000, payload)))


def test_pcap_roundtrip(tmp_path):
    p = tmp_path / "a.pcap"
    write_pcap(str(p), [_frame(b"one"), _frame(b"two")])
    frames = list(open_capture(str(p)))
    assert [f.index for f in frames] == [1, 2]
    assert frames[0].linktype == 1
    assert decode_frame(frames[1]).payload == b"two"


def test_pcap_big_endian_and_nanosecond(tmp_path):
    data = _frame(b"be")
    hdr = struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack(">IIII", 10, 500_000_000, len(data), len(data))
    p = tmp_path / "be.pcap"
    p.write_bytes(hdr + rec + data)
    (frame,) = open_capture(str(p))
    assert frame.timestamp == pytest.approx(10.5)
    assert decode_frame(frame).payload == b"be"


def _pcapng(blocks: list[bytes]) -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
    for b in blocks:
        out += b
    return out


def _block(btype: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)


def test_pcapng_multiple_interfaces_and_tsresol(tmp_path):
    raw_ip = ip_packet(C, S, 17, udp(C, S, 1, 2, b"raw"))
    eth = _frame(b"eth")
    tsresol_opt = struct.pack("<HHB", 9, 1, 3) + b"\0\0\0" + struct.pack("<HH", 0, 0)  # milliseconds
    blocks = [
        _block(1, struct.pack("<HHI", 1, 0, 0)),  # iface 0: ethernet
        _block(1, struct.pack("<HHI", 101, 0, 0) + tsresol_opt),  # iface 1: raw IP, ms resolution
        _block(6, struct.pack("<IIIII", 1, 0, 2500, len(raw_ip), len(raw_ip)) + raw_ip),
        _block(6, struct.pack("<IIIII", 0, 0, 0, len(eth), len(eth)) + eth),
        _block(5, b"stats are skipped"),
    ]
    p = tmp_path / "x.pcapng"
    p.write_bytes(_pcapng(blocks))
    f1, f2 = open_capture(str(p))
    assert (f1.linktype, f2.linktype) == (101, 1)
    assert f1.timestamp == pytest.approx(2.5)
    assert decode_frame(f1).payload == b"raw" and decode_frame(f2).payload == b"eth"


@pytest.mark.parametrize(
    "content,message",
    [(b"", "empty"), (b"\x01\x02", "too short"), (b"GET / HTTP/1.1\r\n\r\n", "not a pcap")],
)
def test_unreadable_files(tmp_path, content, message):
    p = tmp_path / "bad"
    p.write_bytes(content)
    with pytest.raises(CaptureFormatError, match=message):
        list(open_capture(str(p)))


def test_truncated_file_yields_complete_frames_then_errors(tmp_path):
    p = tmp_path / "t.pcap"
    write_pcap(str(p), [_frame(b"a" * 50), _frame(b"b" * 50)])
    data = p.read_bytes()
    p.write_bytes(data[:-20])
    got = []
    with pytest.raises(CaptureFormatError, match="truncated frame data in frame 2"):
        for f in open_capture(str(p)):
            got.append(f)
    assert len(got) == 1


def test_header_only_pcap_is_empty(tmp_path):
    p = tmp_path / "h.pcap"
    with open(p, "wb") as fh:
        PcapWriter(fh)
    assert list(open_capture(str(p))) == []


# --- decoding ----------------------------------------------------------------------


@pytest.mark.parametrize("linktype,vlan", [(1, None), (1, 100), (0, None), (101, None), (113, None)])
def test_link_types(linktype, vlan):
    raw = frame_for(ip_packet(C, S, 6, tcp(C, S, 5000, 80, 1, 0, 0x18, b"hello")), linktype, vlan)
    pkt = decode_frame(RawFrame(1, 0.0, linktype, raw, len(raw)))
    assert pkt is not None
    assert (pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.payload) == (C, S, 5000, 80, b"hello")


def test_ipv6_with_extension_header():
    payload = udp("2001:db8::1", "2001:db8::2", 53, 5353, b"v6")
    hop_by_hop = bytes([17, 0]) + b"\x01\x04\x00\x00\x00\x00"  # next=UDP, len 0 (8 bytes), PadN
    from netcreds_ng.testing.packets import ipv6

    raw = frame_for(ipv6("2001:db8::1", "2001:db8::2", 0, hop_by_hop + payload))
    pkt = decode_frame(RawFrame(1, 0.0, 1, raw, len(raw)))
    assert pkt.proto == PROTO_UDP and pkt.payload == b"v6" and pkt.src == "2001:db8::1"


def test_ethernet_padding_is_trimmed():
    raw = frame_for(ip_packet(C, S, 6, tcp(C, S, 1, 2, 0, 0, 0x10))) + b"\x00" * 6
    pkt = decode_frame(RawFrame(1, 0.0, 1, raw, len(raw)))
    assert pkt.proto == PROTO_TCP and pkt.payload == b""


@pytest.mark.parametrize("cut", [0, 5, 13, 20, 33, 40])
def test_truncated_frames_never_raise(cut):
    raw = frame_for(ip_packet(C, S, 6, tcp(C, S, 1, 2, 0, 0, 0x18, b"data")))[:cut]
    decode_frame(RawFrame(1, 0.0, 1, raw, 100))  # must not raise


def test_non_ip_frame_returns_none():
    arp = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 28
    assert decode_frame(RawFrame(1, 0.0, 1, arp, len(arp))) is None


# --- TCP reassembly -------------------------------------------------------------------


def _data(chunks):
    return b"".join(c.data for c in chunks)


def test_in_order_and_out_of_order():
    s = TCPStream()
    out = s.add(100, b"", syn=True)
    out += s.add(106, b"world")
    assert _data(out) == b""
    out += s.add(101, b"hello")
    assert _data(out) == b"helloworld"


def test_retransmission_and_overlap_first_copy_wins():
    s = TCPStream()
    s.add(0, b"", syn=True)
    out = s.add(1, b"abcdef")
    out += s.add(1, b"abcdef")  # full retransmission
    out += s.add(4, b"XYZghi")  # overlap: "XYZ" conflicts with delivered "def"
    assert _data(out) == b"abcdefghi"
    assert s.retransmitted == 9


def test_sequence_wraparound():
    s = TCPStream()
    s.add(0xFFFFFFFD, b"", syn=True)  # next seq = 0xFFFFFFFE
    out = s.add(0xFFFFFFFE, b"ab")
    out += s.add(0x00000000, b"cd")
    assert _data(out) == b"abcd"
    assert seq_delta(0x00000001, 0xFFFFFFFF) == 2


def test_gap_is_reported_on_flush():
    s = TCPStream()
    s.add(0, b"", syn=True)
    s.add(1, b"start")
    assert s.add(20, b"later") == []
    out = s.flush()
    assert out[0].gap_before == 14 and out[0].data == b"later"
    assert s.gaps == 1 and s.gap_bytes == 14


def test_pending_limit_forces_gap():
    s = TCPStream(max_pending=10)
    s.add(0, b"", syn=True)
    out = s.add(100, b"x" * 11)
    assert out and out[0].gap_before == 99


def test_midstream_pickup_without_syn():
    s = TCPStream()
    assert _data(s.add(5000, b"mid")) == b"mid"


# --- IP fragments ---------------------------------------------------------------------


def test_ipv4_defragmentation_out_of_order():
    l4 = udp(C, S, 1, 2, b"F" * 40)
    frag1 = ipv4(C, S, 17, l4[:24], ident=7, frag=0x2000)  # MF, offset 0
    frag2 = ipv4(C, S, 17, l4[24:], ident=7, frag=24 // 8)  # last, offset 24
    d = Defragmenter()
    assert d.add(decode_ip(frag2), 0.0) is None
    assert d.add(decode_ip(frag1), 0.1) == l4


def test_engine_reassembles_fragmented_udp():
    from netcreds_ng.testing.harness import analyze
    from netcreds_ng.testing.protocols import snmp_v1v2

    l4 = udp(C, S, 50000, 161, snmp_v1v2("frag-community-fake"))
    cut = 24
    frames = [
        frame_for(ipv4(C, S, 17, l4[cut:], ident=9, frag=cut // 8)),
        frame_for(ipv4(C, S, 17, l4[:cut], ident=9, frag=0x2000)),
    ]
    findings = analyze(frames, enrichers=[])
    assert [f.secret for f in findings] == ["frag-community-fake"]


def test_engine_handles_port_reuse_after_close():
    from netcreds_ng.testing.harness import analyze

    frames = []
    for user in ("first", "second"):
        c = TCPConversation(C, 40000, S, 21).handshake()
        c.server(b"220 hi\r\n").client(f"USER {user}\r\nPASS pw-{user}\r\n".encode()).close()
        frames += c.frames
    creds = [(f.username, f.secret) for f in analyze(frames, enrichers=[]) if f.secret]
    assert creds == [("first", "pw-first"), ("second", "pw-second")]
