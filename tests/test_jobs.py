"""Parallel analysis (-j N): the frames of one or more captures split across worker processes give
exactly the output of a sequential run (M12, rebuilt by the optimisation pass)."""

from __future__ import annotations

import os

import pytest

import netcreds_ng.parallel as parallel
from conftest import SYNTHETIC
from netcreds_ng.engine.pcapio import RawFrame
from netcreds_ng.model import RunStats
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig
from netcreds_ng.testing.packets import TCPConversation, udp_frame, write_pcap

FILES = [str(SYNTHETIC / f"{n}.pcap") for n in ("ftp_basic", "http_basic", "smtp_auth_login", "snmp_communities")]


CALLS: list[int] = []  # worker counts of the parallel runs, to prove the parallel path really ran


@pytest.fixture
def always_parallel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parallel, "PARALLEL_MIN_BYTES", 0)  # checked in the parent only
    monkeypatch.setattr(os, "cpu_count", lambda: 16)  # workers are capped at the CPU count (CI macOS has 3)
    original = parallel.run_parallel

    def recording(session: Session, paths: list[str], workers: int) -> None:
        CALLS.append(workers)
        original(session, paths, workers)

    monkeypatch.setattr(parallel, "run_parallel", recording)
    CALLS.clear()


def run(paths: list[str], jobs: int) -> tuple[list[dict], dict, list[str]]:
    found = []
    s = Session(load_registry(use_entry_points=False), SessionConfig(jobs=jobs), listeners=[found.append])
    s.open()
    s.run_files(paths)
    s.close()
    out = []
    for f in found:
        d = f.to_dict()
        d.get("extra", {}).pop("secret_fingerprint", None)  # keyed per run
        out.append(d)
    return out, s.stats.snapshot(), s.errors


def test_parallel_matches_sequential(always_parallel: None) -> None:
    seq = run(FILES, 1)
    assert seq[0]
    for jobs in (2, 3):
        assert run(FILES, jobs) == seq  # every finding in the same order, every counter, every error
    assert CALLS == [2, 3]


def test_connection_continues_across_files(tmp_path, always_parallel: None) -> None:
    """Rotated captures (tcpdump -C): a login whose USER and PASS are in different files is still paired."""
    frames = []
    for i in range(12):  # several host pairs, so the work is really split
        c = TCPConversation(f"192.0.2.{10 + i}", 40000 + i, f"198.51.100.{20 + i}", 21, start=1_700_000_000.0 + i)
        c.handshake().server(b"220 ftp\r\n").client(f"USER rot{i}\r\n".encode())
        c.server(b"331 pw\r\n").client(f"PASS FakePass-{i}\r\n".encode()).server(b"230 ok\r\n")
        c.close()
        frames += c.frames
    frames.sort(key=lambda f: f.timestamp)
    half = len(frames) // 2
    first, second = str(tmp_path / "a.pcap"), str(tmp_path / "b.pcap")
    write_pcap(first, frames[:half])
    write_pcap(second, frames[half:])
    seq = run([first, second], 1)
    assert run([first, second], 4) == seq
    assert CALLS == [4]
    creds = [f for f in seq[0] if f["kind"] == "credential"]
    assert len(creds) == 12 and all(f["username"] for f in creds)


def test_source_errors_reported_once(tmp_path, always_parallel: None) -> None:
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture at all")
    seq = run([FILES[0], str(bad), FILES[1]], 1)
    par = run([FILES[0], str(bad), FILES[1]], 3)
    assert par == seq and CALLS == [3]
    assert len(par[1]["source_errors"]) == 1


def test_when_parallel_mode_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    s = Session(load_registry(use_entry_points=False), SessionConfig(jobs=4))
    assert s.parallel_workers(FILES) == 1  # far below PARALLEL_MIN_BYTES
    monkeypatch.setattr(parallel, "PARALLEL_MIN_BYTES", 0)
    assert s.parallel_workers(FILES) == 4
    s.config.jobs = 32
    assert s.parallel_workers(FILES) == 8  # at most one per CPU
    s.engine.packet_observers.append(lambda pkt: None)  # e.g. --evidence: needs every packet, in order
    assert s.parallel_workers(FILES) == 1


def _frame(data: bytes, linktype: int = 1) -> RawFrame:
    return RawFrame(1, 1.0, linktype, data, len(data))


def test_route_is_symmetric_and_keeps_host_pairs_together() -> None:
    out = udp_frame("192.0.2.1", 5000, "198.51.100.7", 53, b"q")
    back = udp_frame("198.51.100.7", 53, "192.0.2.1", 5000, b"r")
    other_port = udp_frame("192.0.2.1", 6000, "198.51.100.7", 161, b"x")
    for n in (2, 3, 8):
        assert parallel.route(_frame(out), n) == parallel.route(_frame(back), n) == parallel.route(_frame(other_port), n)
    assert parallel.route(_frame(b"\x00" * 10), 8) == 0  # unreadable frames: worker 0
    raw = out[14:]  # the same IP packet without Ethernet (DLT_RAW): routed by the same addresses
    assert parallel.route(_frame(raw, 101), 8) == parallel.route(_frame(out), 8)


def test_runstats_merge() -> None:
    a, b = RunStats(frames=2, first_ts=5.0, last_ts=6.0), RunStats(frames=3, first_ts=4.0, last_ts=9.0, findings=7)
    b.plugin_errors["x"] += 1
    b.source_errors.append("e")
    a.merge(b)
    assert (a.frames, a.first_ts, a.last_ts, a.findings) == (5, 4.0, 9.0, 0)
    assert a.plugin_errors["x"] == 1 and a.source_errors == ["e"]


CRASHING_PLUGIN = '''
import multiprocessing
from netcreds_ng.plugins.api import ProtocolPlugin

class CrashInWorker(ProtocolPlugin):
    name = "crash_in_worker"
    description = "raises SystemExit in parallel workers only"

    def new_state(self, flow):
        if multiprocessing.parent_process() is not None:
            raise SystemExit(3)
'''


def test_worker_failure_is_a_clean_cli_error(tmp_path, capsys, always_parallel: None) -> None:
    from netcreds_ng.cli import EXIT_ERROR, main

    (tmp_path / "crash.py").write_text(CRASHING_PLUGIN, encoding="utf-8")
    code = main(["-p", FILES[0], "--no-tui", "-q", "-j", "2", "--plugin-dir", str(tmp_path)])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR and CALLS == [2]
    assert "[ERROR] parallel worker" in err and "SystemExit: 3" in err
    assert "Traceback" not in err
