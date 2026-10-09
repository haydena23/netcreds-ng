"""Dashboard analytics (related findings, accounts, timeline), the --attach store and replay tally."""

from __future__ import annotations

import json
import sqlite3

import pytest

from conftest import SYNTHETIC
from netcreds_ng.model import Endpoint, Finding, Kind, RunStats
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig
from netcreds_ng.tui.insight import Tally, accounts, reason_counts, related, spark, timeline
from netcreds_ng.tui.store import FindingStore, StoreError

C, S = "192.0.2.10", "192.0.2.20"


def _f(kind: Kind, sport: int = 50000, **kw: object) -> Finding:
    base: dict[str, object] = {"protocol": "FTP", "kind": kind, "src": Endpoint(C, sport), "dst": Endpoint(S, 21)}
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def test_related_orders_by_strongest_relation():
    findings = [
        _f(Kind.CREDENTIAL, username="alice", secret="x", frame=4, extra={"secret_fingerprint": "fp1"}),
        _f(Kind.AUTH_RESULT, username="alice", value="login failed", frame=5),       # same connection
        _f(Kind.AUTH_RESULT, sport=50001, username="Alice", value="login ok", frame=9),  # same account
        _f(Kind.CREDENTIAL, sport=50002, protocol="IMAP", username="bob", secret="x",
           extra={"secret_fingerprint": "fp1"}),                                       # same secret
        _f(Kind.ALERT, sport=0, value="Brute force", plugin="detection",
           extra={"detection": "brute-force", "frames": [5, 9], "attempts": 2}),       # alert covering idx 1, 2
        _f(Kind.URL, sport=50003, protocol="HTTP", value="http://example.test/"),     # unrelated
    ]
    rel = related(findings, 0)
    assert rel == [("same connection", 1), ("same secret", 3), ("same account", 2)]
    assert related(findings, 1)[0] == ("alert", 4)
    assert related(findings, 4) == [("alert attempt", 1), ("alert attempt", 2)]
    assert related(findings, 5) == []


def test_alert_attempts_need_matching_client_and_time():
    """Frame numbers restart per capture file: a same-numbered result elsewhere is not an attempt."""
    alert = _f(Kind.ALERT, sport=0, plugin="detection", timestamp=50.0,
               extra={"detection": "brute-force", "frames": [5], "attempts": 1})  # fmt: skip
    findings = [
        alert,
        _f(Kind.AUTH_RESULT, value="login failed", frame=5, timestamp=40.0),                     # the attempt
        _f(Kind.AUTH_RESULT, value="login failed", frame=5, timestamp=60.0),                     # after the alert
        Finding("FTP", Kind.AUTH_RESULT, Endpoint("192.0.2.99", 1), Endpoint(S, 21), frame=5,  # other client
                value="login failed", timestamp=40.0),
    ]
    assert related(findings, 0) == [("alert attempt", 1)]
    targeted = _f(Kind.ALERT, sport=0, plugin="detection", timestamp=50.0,
                  extra={"detection": "targeted-account", "frames": [5], "clients": [C, "192.0.2.99"]})  # fmt: skip
    assert [j for _, j in related([targeted, *findings[1:]], 0)] == [1, 3]


def test_accounts_rollup():
    findings = [
        _f(Kind.CREDENTIAL, username="alice", secret="x", risk="high", tags=["cleartext", "weak-password"],
           timestamp=100.0),
        _f(Kind.AUTH_RESULT, username="ALICE", value="login failed", timestamp=101.0),
        _f(Kind.AUTH_EVENT, protocol="NTLM", username="bob", domain="CORP", risk="medium", timestamp=50.0),
        _f(Kind.URL, username="carol", value="http://example.test/"),  # browsing is not an account record
    ]
    rows = accounts(findings)
    assert [r.account for r in rows] == ["alice", "CORP\\bob"]
    alice = rows[0]
    assert alice.findings == 2 and alice.cleartext and alice.weak and not alice.reused
    assert alice.failures == 1 and alice.successes == 0 and (alice.first_ts, alice.last_ts) == (100.0, 101.0)


def test_timeline_and_spark():
    findings = [_f(Kind.CREDENTIAL, risk="high", timestamp=10.0), _f(Kind.USERNAME, risk="low", timestamp=20.0),
                _f(Kind.USERNAME, risk="low", timestamp=20.0), _f(Kind.URL, timestamp=15.0)]  # fmt: skip
    tl = timeline(findings, 4)
    assert tl is not None and (tl.start, tl.end, tl.width) == (10.0, 20.0, 4)
    assert tl.buckets["high"] == [1, 0, 0, 0] and tl.buckets["low"] == [0, 0, 0, 2]
    assert timeline([_f(Kind.URL, timestamp=1.0)]) is None
    assert spark([0, 1, 2, 4]) == " ▂▄█" and spark([0, 0]) == "  "


def test_reason_counts():
    findings = [_f(Kind.CREDENTIAL, tags=["cleartext"]), _f(Kind.CREDENTIAL, tags=["cleartext", "weak-password"]),
                _f(Kind.URL, tags=["cleartext"])]  # fmt: skip
    assert reason_counts(findings) == [("cleartext", "Sent in cleartext", 2), ("weak-password", "Weak password", 1)]


def _run(captures: list[str], outputs: list[tuple[str, str]] | None = None, **cfg: object) -> tuple[Session, list[Finding]]:
    found: list[Finding] = []
    session = Session(load_registry(use_entry_points=False), SessionConfig(outputs=outputs or [], **cfg),  # type: ignore[arg-type]
                      listeners=[found.append])  # fmt: skip
    session.open()
    session.run_files(captures)
    session.close()
    return session, found


def _brute_force_capture(tmp_path) -> str:
    from netcreds_ng.testing.packets import write_pcap
    from test_detection import attempt

    capture = tmp_path / "bf.pcap"
    write_pcap(str(capture), [fr for n in range(6) for fr in attempt("192.0.2.30", n, "gina")])
    return str(capture)


def test_tally_replay_matches_live_summary(tmp_path):
    captures = [str(SYNTHETIC / "ftp_basic.pcap"), str(SYNTHETIC / "http_basic.pcap"), _brute_force_capture(tmp_path)]
    session, found = _run(captures)
    tally = Tally()
    for f in found:
        tally.observe(f)
    live, replay = session.summary(), tally.summary()
    assert live["alerts"] and replay == live


def test_store_round_trip_and_stats(tmp_path):
    db = tmp_path / "run.db"
    captures = [str(SYNTHETIC / "ftp_basic.pcap"), _brute_force_capture(tmp_path)]
    session, found = _run(captures, outputs=[("sqlite", str(db))], source_label="test captures")
    store = FindingStore(str(db))
    loaded = store.poll()
    assert [f.to_dict() for f in loaded] == [f.to_dict() for f in found]
    assert store.poll() == []  # nothing new
    stats = store.stats()
    assert stats.frames == session.stats.frames and stats.findings == session.stats.findings
    assert stats.tcp_flows == session.stats.tcp_flows and stats.by_protocol == session.stats.by_protocol
    (run,) = store.runs()
    assert run.source == "test captures" and run.finished is not None and not run.in_progress
    store.close()


def test_store_follows_a_growing_database(tmp_path):
    """A reader sees rows the writer commits while the run is still going (WAL, periodic commits)."""
    from netcreds_ng.plugins.api import SinkContext
    from netcreds_ng.plugins.sinks.sqlite import SqliteSink

    db = tmp_path / "live.db"
    stats = RunStats()
    sink = SqliteSink(str(db), {"commit_interval": 0, "source_label": "eth0"})
    sink.open(SinkContext(stats))
    store = FindingStore(str(db))
    assert store.poll() == [] and store.runs()[0].in_progress
    stats.frames = 42
    sink.write(_f(Kind.CREDENTIAL, username="alice", secret="FakePass-123", risk="high"))
    got = store.poll()
    assert [(f.username, f.secret) for f in got] == [("alice", "FakePass-123")]
    assert store.stats().frames == 42
    sink.close(stats)
    assert not store.runs()[0].in_progress and store.runs()[0].finished is not None
    store.close()


def test_store_reads_old_schema_and_masked_rows(tmp_path):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started REAL, frames INTEGER, findings INTEGER,
                           duplicates INTEGER, errors INTEGER);
        CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, ts REAL, frame INTEGER,
            protocol TEXT, kind TEXT, risk TEXT, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
            username TEXT, domain TEXT, secret TEXT, value TEXT, tags TEXT, plugin TEXT, extra TEXT);
        INSERT INTO runs VALUES (1, 0, 10, 2, 1, 0);
    """)
    con.execute("INSERT INTO findings VALUES (NULL,1,1.5,3,'FTP','credential','high','192.0.2.1',5000,"
                "'192.0.2.2',21,'alice',NULL,'F****3 (12)',NULL,'cleartext',  'ftp', ?)", (json.dumps({"a": 1}),))
    con.execute("INSERT INTO findings VALUES (NULL,1,2,4,'X','from-the-future','info','192.0.2.1',1,"
                "'192.0.2.2',2,NULL,NULL,NULL,NULL,'','x','')")
    con.commit()
    con.close()
    store = FindingStore(str(db))
    (f,) = store.poll()
    assert f.kind is Kind.CREDENTIAL and f.tags == ["cleartext"] and f.secret == "F****3 (12)" and f.extra == {"a": 1}
    assert store.skipped == 1
    st = store.stats()
    assert (st.frames, st.findings, st.duplicates) == (10, 2, 1)
    assert store.runs()[0].source == "" and not store.runs()[0].in_progress
    store.close()

    # a new run appended by the current sink upgrades the table in place
    _run([str(SYNTHETIC / "ftp_basic.pcap")], outputs=[("sqlite", str(db))])
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(runs)")}
    assert {"source", "updated", "finished", "stats"} <= cols


def test_store_rejects_other_files(tmp_path):
    with pytest.raises(StoreError, match="not found"):
        FindingStore(str(tmp_path / "missing.db"))
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE t (x)").connection.commit()
    with pytest.raises(StoreError, match="not a netcreds-ng database"):
        FindingStore(str(other))
    text = tmp_path / "notes.txt"
    text.write_text("hello " * 200, encoding="utf-8")
    with pytest.raises(StoreError):
        FindingStore(str(text))


def test_runstats_snapshot_round_trip():
    st = RunStats(frames=5, tcp_flows=2, first_ts=1.5, last_ts=9.0, source_errors=["x"])
    st.plugin_errors["ftp"] += 2
    st.by_protocol["FTP"] += 3
    back = RunStats.from_snapshot(json.loads(json.dumps(st.snapshot())))
    assert vars(back) == vars(st)
    assert RunStats.from_snapshot({"frames": 3, "unknown_future_field": 1}).frames == 3
