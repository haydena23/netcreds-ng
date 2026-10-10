"""M9: behavioural detections, service inventory and host scores (DetectionEnricher)."""

from __future__ import annotations

from netcreds_ng.model import Kind
from netcreds_ng.plugins.enrichers.analytics import AnalyticsEnricher
from netcreds_ng.plugins.enrichers.detection import DetectionEnricher
from netcreds_ng.plugins.protocols.ftp import FTPPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import Frame, TCPConversation

S = "198.51.100.20"


def attempt(client: str, n: int, user: str, ok: bool = False, t0: float = 1_700_000_000.0) -> list[Frame]:
    c = TCPConversation(client, 40000 + n, S, 21, start=t0 + n * 2.0)
    c.handshake().server(b"220 ready\r\n").client(f"USER {user}\r\nPASS Fake-Guess-{n}\r\n".encode())
    c.server(b"230 welcome\r\n" if ok else b"530 Login incorrect\r\n")
    return list(c.close().frames)


def run(frames: list[Frame], **opts: object):
    det = DetectionEnricher(dict(opts))
    findings = analyze(frames, plugins=[FTPPlugin()], enrichers=[AnalyticsEnricher(), det])
    return findings, det


def alerts(findings):
    return [f for f in findings if f.kind is Kind.ALERT]


def test_brute_force_then_success():
    frames = [fr for n in range(6) for fr in attempt("192.0.2.10", n, "alice")]
    frames += attempt("192.0.2.10", 6, "alice", ok=True)
    findings, det = run(frames)
    got = alerts(findings)
    assert [a.extra["detection"] for a in got] == ["brute-force", "login-after-failures"]
    bf = got[0]
    assert bf.risk == "high" and bf.extra["attempts"] == 5 and bf.extra["users"] == ["alice"]
    assert (bf.src.ip, bf.dst.ip, bf.dst.port, bf.protocol) == ("192.0.2.10", S, 21, "FTP")
    assert "for 'alice'" in (bf.value or "")
    assert len(bf.extra["frames"]) == 5
    assert "as 'alice'" in (got[1].value or "")
    summary = det.summary()
    assert summary["alerts"][0]["detection"] == "brute-force"
    assert det.host_score("192.0.2.10") > 0


def test_password_spraying():
    frames = [fr for n in range(5) for fr in attempt("192.0.2.11", n, f"user{n}")]
    got = alerts(run(frames)[0])
    assert [a.extra["detection"] for a in got] == ["password-spraying"]
    assert got[0].extra["users"] == [f"user{n}" for n in range(5)]


def test_targeted_account_from_many_clients():
    frames = [fr for n in range(5) for fr in attempt(f"192.0.2.{20 + n}", n, "admin")]
    got = alerts(run(frames)[0])
    assert [a.extra["detection"] for a in got] == ["targeted-account"]
    assert got[0].extra["clients"] == [f"192.0.2.{20 + n}" for n in range(5)]


def test_below_threshold_and_outside_window_raise_nothing():
    frames = [fr for n in range(4) for fr in attempt("192.0.2.12", n, "bob")]
    assert alerts(run(frames)[0]) == []
    # 5 failures, but spread over more than the window
    spread = [fr for n in range(5) for fr in attempt("192.0.2.13", n, "bob", t0=1_700_000_000.0 + n * 200)]
    assert alerts(run(spread)[0]) == []


def test_thresholds_are_options_and_alert_once():
    frames = [fr for n in range(9) for fr in attempt("192.0.2.14", n, "carol")]
    got = alerts(run(frames, bruteforce=3)[0])
    assert [a.extra["attempts"] for a in got] == [3]


def test_service_inventory_and_shared_accounts():
    frames = attempt("192.0.2.15", 0, "dave", ok=True)
    c = TCPConversation("192.0.2.15", 41000, "203.0.113.5", 21)
    c.handshake().server(b"220 hi\r\n").client(b"USER dave\r\nPASS Fake-Pass-9\r\n").server(b"230 ok\r\n")
    frames += list(c.close().frames)
    _, det = run(frames)
    s = det.summary()
    servers = {(x["server"], x["protocol"]): x for x in s["services"]}
    ftp = servers[(f"{S}:21", "FTP")]
    assert ftp["cleartext"] and ftp["accounts"] == ["dave"] and ftp["successes"] == 1
    assert s["shared_accounts"] == [{"account": "dave", "services": [f"FTP@{S}:21", "FTP@203.0.113.5:21"]}]


def test_session_summary_merges_scores_into_hosts():
    from netcreds_ng.plugins.registry import load_registry
    from netcreds_ng.session import Session, SessionConfig
    from netcreds_ng.testing.harness import to_raw_frames

    frames = [fr for n in range(5) for fr in attempt("192.0.2.16", n, "erin")]
    session = Session(load_registry(use_entry_points=False), SessionConfig())
    session.open()
    session.feed(to_raw_frames(frames))
    session.close()
    summary = session.summary()
    assert summary["alerts"] and summary["services"]
    host = next(h for h in summary["hosts"] if h["ip"] == "192.0.2.16")
    assert host["score"] == summary["host_scores"]["192.0.2.16"] > 0


def test_success_long_after_a_burst_is_not_an_alert():
    # Review L1: the success must fall within the window of the burst's last failure.
    frames = [fr for n in range(5) for fr in attempt("192.0.2.40", n, "hank")]
    frames += attempt("192.0.2.40", 9, "hank", ok=True, t0=1_700_000_000.0 + 3600)
    got = [a.extra["detection"] for a in alerts(run(frames)[0])]
    assert got == ["brute-force"]


def test_account_names_are_case_and_domain_insensitive():
    names = ["Bob", "bob", "BOB", r"CORP\bob", "bob"]
    frames = [fr for n, u in enumerate(names) for fr in attempt("192.0.2.41", n, u)]
    got = alerts(run(frames)[0])
    assert [a.extra["detection"] for a in got] == ["brute-force"]  # one account, not spraying
    assert got[0].extra["users"] == ["bob"]
