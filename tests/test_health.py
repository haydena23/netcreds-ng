"""Capture health: engine counters, rates, issues and verdict (M13)."""

from __future__ import annotations

import json

from netcreds_ng.cli import EXIT_OK, main
from netcreds_ng.engine.decode import decode_frame
from netcreds_ng.engine.pcapio import RawFrame
from netcreds_ng.health import MIN_FLOWS, assess
from netcreds_ng.model import Kind, RunStats
from netcreds_ng.testing.harness import analyze, to_raw_frames
from netcreds_ng.testing.packets import SYN, Frame, TCPConversation, write_pcap

C, S = "192.0.2.10", "198.51.100.20"
LOGIN = b"USER fakeuser\r\nPASS FakePass-123\r\n"


def conv(i: int, handshake: bool = True, data: bytes = LOGIN, segment: int | None = None) -> TCPConversation:
    c = TCPConversation(C, 50000 + i, S, 21, start=1_700_000_000.0 + i)
    if handshake:
        c.handshake()
    c.server(b"220 ready\r\n").client(data, segment).server(b"230 ok\r\n")
    return c.close()


def from_client(frame: Frame) -> bool:
    raw = to_raw_frames([frame])[0]
    return decode_frame(raw).src == C


def run(frames: list[Frame] | list[RawFrame]) -> tuple[RunStats, list]:
    stats = RunStats()
    found = analyze(sorted(frames, key=lambda f: f.timestamp), stats=stats, dedup="off")
    return stats, found


def test_clean_capture_is_good():
    frames = [f for i in range(MIN_FLOWS + 5) for f in conv(i).frames]
    stats, _ = run(frames)
    health = assess(stats)
    assert health["status"] == "good"
    assert health["issues"] == []
    assert health["verdict"] == "good: no capture problems detected"
    assert stats.tcp_one_sided_flows == stats.tcp_duplicate_segments == stats.tcp_no_handshake_flows == 0
    assert stats.tcp_data_segments == 3 * (MIN_FLOWS + 5)
    assert stats.tcp_payload_bytes == (len(LOGIN) + len(b"220 ready\r\n") + len(b"230 ok\r\n")) * (MIN_FLOWS + 5)


def test_one_sided_flows_are_reported():
    frames: list[Frame] = []
    for i in range(25):
        frames += [f for f in conv(i).frames if i >= 10 or from_client(f)]  # 10 flows lose the server side
    stats, found = run(frames)
    assert stats.tcp_one_sided_flows == 10
    health = assess(stats)
    assert health["status"] == "poor"
    assert health["issues"][0]["code"] == "one-sided"
    assert health["metrics"]["one_sided_rate"] == 0.4
    assert "misses the return path for 40% of TCP flows (10 of 25)" in health["verdict"]
    # the credentials themselves are still found on the one-sided flows
    assert sum(f.kind is Kind.CREDENTIAL for f in found) == 25


def test_unanswered_syns_are_not_a_capture_problem():
    frames = [f for i in range(25) for f in conv(i).frames]
    for i in range(30):
        c = TCPConversation(C, 40000 + i, S, 22, start=1_700_000_100.0 + i)
        c._emit(True, SYN)
        frames += c.frames
    stats, _ = run(frames)
    assert stats.tcp_unanswered_syn_flows == 30
    assert stats.tcp_one_sided_flows == 0
    assert assess(stats)["status"] == "good"


def test_server_only_capture_counts_syn_ack_as_answer():
    frames = [f for i in range(25) for f in conv(i).frames if not from_client(f)]
    stats, _ = run(frames)
    assert stats.tcp_one_sided_flows == 25
    assert stats.tcp_unanswered_syn_flows == 0


def test_span_duplicates_are_counted_but_findings_are_not_doubled():
    frames: list[Frame] = []
    for i in range(30):
        for f in conv(i).frames:
            frames.append(f)
            if len(f.data) > 54:  # carries payload: the SPAN copy arrives 1 ms later
                frames.append(Frame(f.data, f.timestamp + 0.001))
    stats, found = run(frames)
    assert stats.tcp_duplicate_segments == 90
    assert stats.tcp_data_segments == 180
    health = assess(stats)
    assert health["status"] == "good", "duplicates never hide findings: informational only"
    assert [(i["code"], i["severity"]) for i in health["issues"]] == [("duplicates", "info")]
    assert health["verdict"].startswith("good, with notes: 50% of TCP data segments were captured twice")
    assert sum(f.kind is Kind.CREDENTIAL for f in found) == 30


def test_retransmission_after_timeout_is_not_a_duplicate():
    frames: list[Frame] = []
    for i in range(30):
        for f in conv(i).frames:
            frames.append(f)
            if len(f.data) > 54:
                frames.append(Frame(f.data, f.timestamp + 0.2))  # RTO-style resend
    stats, _ = run(frames)
    assert stats.tcp_duplicate_segments == 0


def test_gaps_make_the_capture_poor():
    data = b"X" * 1000 + b"\r\n"
    frames: list[Frame] = []
    for i in range(30):
        c = conv(i, data=data, segment=100)
        data_frames = [f for f in c.frames if from_client(f) and len(f.data) > 54]
        frames += [f for f in c.frames if f is not data_frames[4]]  # lose 100 of 1002 client bytes
    stats, _ = run(frames)
    assert stats.tcp_gaps == 30
    assert stats.tcp_gap_bytes == 3000
    health = assess(stats)
    assert health["status"] == "poor"
    assert health["issues"][0]["code"] == "gaps"
    assert "TCP stream bytes are missing from the capture (3,000 B in 30 gaps)" in health["verdict"]


def test_truncated_frames():
    raw = to_raw_frames([f for i in range(30) for f in conv(i).frames])
    cut = [RawFrame(r.index, r.timestamp, r.linktype, r.data, r.wirelen + 100) if r.index % 4 == 0 else r for r in raw]
    stats, _ = run(cut)
    assert stats.truncated_frames == len(raw) // 4
    health = assess(stats)
    assert health["issues"][0]["code"] == "truncated"
    assert health["status"] == "poor"
    assert "snapshot length" in health["verdict"]


def test_midstream_pickup_is_informational():
    frames = [f for i in range(25) for f in conv(i, handshake=False).frames]
    stats, _ = run(frames)
    assert stats.tcp_no_handshake_flows == 25
    health = assess(stats)
    assert health["status"] == "good"
    assert [i["code"] for i in health["issues"]] == ["no-handshake"]
    assert health["issues"][0]["severity"] == "info"


def test_small_capture_warns_only_when_most_flows_are_one_sided():
    frames = [f for f in conv(0).frames if from_client(f)]  # found in real traffic: zeek smtp-one-side-only.pcap
    stats, _ = run(frames)
    assert stats.tcp_one_sided_flows == 1
    health = assess(stats)
    assert health["status"] == "degraded"
    assert "return path for 100% of TCP flows (1 of 1)" in health["verdict"]

    frames = [f for i in range(5) for f in conv(i).frames if i > 0 or from_client(f)]
    stats, _ = run(frames)
    assert stats.tcp_one_sided_flows == 1
    health = assess(stats)
    assert health["status"] == "good"
    assert "small capture" in health["verdict"]


def test_any_gap_is_at_least_informational():
    data = b"X" * 3000 + b"\r\n"  # lose 100 of about 3,000 bytes: below the small-sample warning level
    c = conv(0, data=data, segment=100)
    lost = [f for f in c.frames if from_client(f) and len(f.data) > 54][4]
    stats, _ = run([f for f in c.frames if f is not lost])
    health = assess(stats)
    assert [(i["code"], i["severity"]) for i in health["issues"]] == [("gaps", "info")]
    assert health["status"] == "good"


def test_live_drops_are_reported():
    stats = RunStats(frames=900, dropped_packets=100)
    health = assess(stats)
    assert health["status"] == "poor"
    assert health["issues"][0]["code"] == "dropped"
    assert "100 packets (10%) were dropped" in health["verdict"]


def test_counters_merge_across_workers():
    a, b = RunStats(tcp_one_sided_flows=2, tcp_duplicate_segments=3), RunStats(tcp_one_sided_flows=1)
    a.merge(b)
    assert (a.tcp_one_sided_flows, a.tcp_duplicate_segments) == (3, 3)


def test_summary_json_and_console_line(tmp_path, capsys):
    frames: list[Frame] = []
    for i in range(25):
        frames += [f for f in conv(i).frames if i >= 10 or from_client(f)]
    cap = tmp_path / "one_sided.pcap"
    write_pcap(str(cap), sorted(frames, key=lambda f: f.timestamp))
    out = tmp_path / "summary.json"
    assert main(["-p", str(cap), "--no-tui", "--summary-json", str(out)]) == EXIT_OK
    console = capsys.readouterr().out
    assert "Capture health: poor - the capture misses the return path for 40% of TCP flows" in console
    text = out.read_text(encoding="utf-8")
    assert "FakePass-123" not in text, "the run summary must not contain secrets"
    data = json.loads(text)
    assert data["tool"] == "netcreds-ng"
    assert data["capture_health"]["status"] == "poor"
    assert data["stats"]["tcp_one_sided_flows"] == 10
    assert data["stats"]["by_protocol"]["FTP"] >= 1
    assert data["analytics"]["hosts"][0]["accounts"] == ["fakeuser"]


def test_fast_retransmit_without_ip_id_is_not_a_duplicate():
    # Protocol review F6: IPv6 has no IP ID, so a retransmit 2 ms later looks identical except for timing.
    frames: list[Frame] = []
    for i in range(30):
        c = TCPConversation("2001:db8::10", 50000 + i, "2001:db8::20", 21, start=1_700_000_000.0 + i, step=0.002)
        c.handshake().server(b"220 ready\r\n").client(LOGIN).server(b"230 ok\r\n").close()
        for f in c.frames:
            frames.append(f)
            if len(f.data) > 74:  # IPv6 + TCP headers: carries payload
                frames.append(Frame(f.data, f.timestamp + 0.002))  # fast retransmit, one round trip later
                frames.append(Frame(f.data, f.timestamp + 0.00005))  # SPAN copy, 50 microseconds later
    stats, _ = run(frames)
    assert stats.tcp_duplicate_segments == 90, "only the SPAN copies count"


def test_duplicate_window_ignores_negative_time_differences():
    frames: list[Frame] = []
    for i in range(30):
        for f in conv(i).frames:
            frames.append(f)
            if len(f.data) > 54:
                frames.append(Frame(f.data, f.timestamp - 0.001))  # merged capture, clock skew
    stats, _ = analyze_in_order(frames)
    assert stats.tcp_duplicate_segments == 0


def analyze_in_order(frames: list[Frame]) -> tuple[RunStats, list]:
    stats = RunStats()
    return stats, analyze(frames, stats=stats, dedup="off")


def test_stragglers_after_reset_are_not_capture_problems():
    # Protocol review F8: late ACKs after a RST create a data-less flow; it is neither one-sided nor a pickup.
    from netcreds_ng.testing.packets import ACK, RST

    frames: list[Frame] = []
    for i in range(25):
        c = TCPConversation(C, 50000 + i, S, 21, start=1_700_000_000.0 + i).handshake()
        c.server(b"220 ready\r\n").client(LOGIN)
        c._emit(False, RST | ACK)
        c._emit(True, ACK)  # straggler
        frames += c.frames
    stats, _ = analyze_in_order(frames)
    assert stats.tcp_one_sided_flows == 0
    assert stats.tcp_no_handshake_flows == 0
    assert assess(stats)["status"] == "good"


def test_large_gap_in_small_capture_is_a_warning():
    data = b"X" * 1000 + b"\r\n"
    c = conv(0, data=data, segment=100)
    lost = [f for f in c.frames if from_client(f) and len(f.data) > 54][2:6]
    stats, _ = run([f for f in c.frames if f not in lost])
    health = assess(stats)
    assert stats.tcp_data_segments < 100
    assert [(i["code"], i["severity"]) for i in health["issues"]] == [("gaps", "warning")]
    assert health["status"] == "degraded"


def test_time_span_is_earliest_to_latest_frame():
    # Validation gate M-1: -j and sequential runs must agree even when files or frames are out of order.
    late, early = conv(5).frames, conv(0).frames
    stats = RunStats()
    analyze(late + early, stats=stats, dedup="off")
    assert stats.first_ts == early[0].timestamp
    assert stats.last_ts == late[-1].timestamp


def test_summary_json_rejected_with_legacy(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["--legacy", "-p", "x.pcap", "--summary-json", "-"])
    assert exc.value.code == 2
    assert "--summary-json cannot be combined with --legacy" in capsys.readouterr().err
