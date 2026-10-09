"""M12: parallel analysis of several capture files gives the same result as a sequential run."""

from __future__ import annotations

from conftest import SYNTHETIC
from netcreds_ng.model import RunStats
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig

FILES = [str(SYNTHETIC / f"{n}.pcap") for n in ("ftp_basic", "http_basic", "smtp_auth_login", "snmp_communities")]


def run(jobs: int):
    found = []
    s = Session(load_registry(use_entry_points=False), SessionConfig(jobs=jobs), listeners=[found.append])
    s.open()
    s.run_files(FILES)
    s.close()
    return [(f.protocol, f.kind.value, str(f.src), str(f.dst), f.username, f.secret, f.value) for f in found], s.stats


def test_parallel_matches_sequential():
    seq, seq_stats = run(1)
    par, par_stats = run(2)
    assert par == seq and seq
    for name in ("frames", "decoded", "tcp_flows", "udp_flows", "findings", "duplicates"):
        assert getattr(par_stats, name) == getattr(seq_stats, name), name
    assert par_stats.by_protocol == seq_stats.by_protocol


def test_runstats_merge():
    a, b = RunStats(frames=2, first_ts=5.0, last_ts=6.0), RunStats(frames=3, first_ts=4.0, last_ts=9.0, findings=7)
    b.plugin_errors["x"] += 1
    b.source_errors.append("e")
    a.merge(b)
    assert (a.frames, a.first_ts, a.last_ts, a.findings) == (5, 4.0, 9.0, 0)
    assert a.plugin_errors["x"] == 1 and a.source_errors == ["e"]
