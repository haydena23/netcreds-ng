"""M10: evidence pcapng export and the pcapng writer."""

from __future__ import annotations

import io

from netcreds_ng.engine.pcapio import PcapngWriter, open_capture
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig
from netcreds_ng.testing.harness import to_raw_frames
from netcreds_ng.testing.packets import TCPConversation, write_pcap

C, S = "192.0.2.10", "198.51.100.20"


def ftp_login(cport: int = 40000, user: str = "alice") -> TCPConversation:
    c = TCPConversation(C, cport, S, 21).handshake()
    c.server(b"220 ready\r\n").client(f"USER {user}\r\n".encode()).client(b"PASS Fake-Pass-1\r\n")
    return c.server(b"230 ok\r\n").close()


def noise(cport: int = 41000) -> TCPConversation:
    c = TCPConversation(C, cport, S, 8080).handshake()
    return c.client(b"\x00\x01binary\x02").server(b"\x03\x04").close()


def test_pcapng_writer_round_trip_with_multiple_linktypes(tmp_path):
    path = tmp_path / "w.pcapng"
    with open(path, "wb") as fh:
        w = PcapngWriter(fh)
        w.write(b"\x01" * 60, 1_700_000_000.25, 1, comment="first")
        w.write(b"\x45" + b"\x00" * 39, 1_700_000_001.5, 101)
        w.write(b"\x02" * 61, 1_700_000_002.0, 1, comment="third, odd length")
    frames = list(open_capture(str(path)))
    assert [(f.index, f.linktype, len(f.data)) for f in frames] == [(1, 1, 60), (2, 101, 40), (3, 1, 61)]
    assert abs(frames[0].timestamp - 1_700_000_000.25) < 1e-6
    raw = path.read_bytes()
    assert b"first" in raw and b"third, odd length" in raw


def run_session(frames, tmp_path, **opts):
    out = tmp_path / "evidence.pcapng"
    cfg = SessionConfig(outputs=[("evidence", str(out))], plugin_options={"evidence": opts} if opts else {})
    session = Session(load_registry(use_entry_points=False), cfg)
    session.open()
    session.feed(to_raw_frames(frames))
    session.close()
    assert not session.stats.plugin_errors, session.errors
    return out


def test_evidence_contains_only_flows_with_findings(tmp_path):
    login, other = ftp_login(), noise()
    frames = list(login.frames) + list(other.frames)
    out = run_session(frames, tmp_path)
    written = list(open_capture(str(out)))
    # every frame of the FTP flow (11) and nothing from the noise flow
    assert len(written) == len(login.frames)
    assert [f.data for f in written] == [f.data for f in login.frames]
    raw = out.read_bytes()
    assert b"netcreds-ng: original frame 1" in raw
    assert b"FTP credential for alice" in raw
    assert b"FTP auth result: login succeeded" in raw
    assert b"Fake-Pass-1" in raw  # the packet bytes themselves are the evidence
    assert raw.count(b"Fake-Pass-1") == 1  # ...but never repeated in a comment


def test_evidence_follow_up_frames_and_limits(tmp_path):
    c = TCPConversation(C, 40002, S, 21).handshake()
    c.server(b"220 ready\r\n").client(b"USER bob\r\nPASS Fake-Pass-2\r\n")
    for n in range(30):
        c.client(f"NOOP {n}\r\n".encode())
    c.close()
    out = run_session(list(c.frames), tmp_path, frames_per_flow=4, after=3)
    written = list(open_capture(str(out)))
    # 4 buffered frames at the time of the credential + 3 follow-ups
    assert len(written) == 7


def test_cli_evidence_flag(tmp_path):
    from netcreds_ng.cli import main

    pcap = tmp_path / "in.pcap"
    write_pcap(str(pcap), list(ftp_login().frames) + list(noise().frames))
    out = tmp_path / "ev.pcapng"
    assert main(["-p", str(pcap), "-q", "--evidence", str(out)]) == 0
    assert len(list(open_capture(str(out)))) == len(ftp_login().frames)


def test_writer_to_memory_has_valid_block_lengths():
    buf = io.BytesIO()
    w = PcapngWriter(buf)
    w.write(b"abc", 1.0, 1, comment="x")
    data = buf.getvalue()
    pos = 0
    while pos < len(data):
        total = int.from_bytes(data[pos + 4 : pos + 8], "little")
        assert total % 4 == 0 and data[pos + total - 4 : pos + total] == data[pos + 4 : pos + 8]
        pos += total
    assert pos == len(data)


def test_evidence_from_several_files_does_not_collide(tmp_path):
    # Validation D1: two files with overlapping frame numbers and endpoints.
    from netcreds_ng.cli import main

    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    first, second = ftp_login(40010, "alice"), ftp_login(40010, "bob")  # same 4-tuple, same frame numbers
    write_pcap(str(a), first.frames)
    write_pcap(str(b), second.frames)
    out = tmp_path / "ev.pcapng"
    assert main(["-p", str(a), "-p", str(b), "-q", "--evidence", str(out)]) == 0
    written = list(open_capture(str(out)))
    assert len(written) == len(first.frames) + len(second.frames)
    raw = out.read_bytes()
    assert b"FTP credential for alice" in raw and b"FTP credential for bob" in raw
    assert b"original frame 1 of a.pcap" in raw and b"original frame 1 of b.pcap" in raw


def test_evidence_includes_every_ip_fragment(tmp_path):
    # Review M5: a credential in a fragmented datagram keeps all its fragments as evidence.
    from netcreds_ng.testing.packets import frame_for, ipv4, udp
    from netcreds_ng.testing.protocols import snmp_v1v2

    l4 = udp(C, S, 50000, 161, snmp_v1v2("frag-community-fake"))
    frames = [
        frame_for(ipv4(C, S, 17, l4[:24], ident=9, frag=0x2000)),
        frame_for(ipv4(C, S, 17, l4[24:], ident=9, frag=24 // 8)),
    ]
    out = run_session(frames, tmp_path)
    written = list(open_capture(str(out)))
    assert [f.data for f in written] == frames
