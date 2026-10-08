"""Registry, plugin isolation, pipeline/dedup, enrichers, masking and robustness."""

from __future__ import annotations

import random

from hypothesis import given, settings
from hypothesis import strategies as st

from netcreds_ng.engine.engine import Engine
from netcreds_ng.engine.pcapio import RawFrame
from netcreds_ng.engine.pipeline import Deduplicator, Pipeline
from netcreds_ng.model import Endpoint, Finding, Kind, RunStats
from netcreds_ng.output.masking import mask_value
from netcreds_ng.plugins.api import PLUGIN_API, ProtocolPlugin
from netcreds_ng.plugins.enrichers.analytics import AnalyticsEnricher
from netcreds_ng.plugins.registry import Registry, load_registry
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation, frame_for, ip_packet, tcp, udp

C, S = "192.0.2.10", "198.51.100.20"

PLUGIN_SOURCE = '''
from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import ProtocolPlugin, Direction

class EchoPlugin(ProtocolPlugin):
    name = "echo-test"
    description = "test plugin"
    def on_data(self, ctx, direction, data):
        if b"SECRET=" in data:
            ctx.emit(direction, Kind.PASSWORD, protocol="Echo", secret=data.split(b"SECRET=")[1].strip().decode(),
                     plugin=self.name)
'''


def test_plugin_directory_loading(tmp_path):
    (tmp_path / "echo.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
    (tmp_path / "broken.py").write_text("raise RuntimeError('boom')", encoding="utf-8")
    reg = load_registry(plugin_dirs=[str(tmp_path)], use_entry_points=False)
    assert "echo-test" in reg.plugins and reg.plugins["echo-test"].source.startswith("file:")
    assert any("broken.py" in e for e in reg.load_errors)
    c = TCPConversation(C, 50000, S, 7777).handshake()
    c.client(b"SECRET=dir-plugin-value\n").close()
    found = analyze(c.frames, plugins=reg.select_protocols(enable=["echo-test"], disable=[]), enrichers=[])
    assert [f.secret for f in found if f.plugin == "echo-test"] == ["dir-plugin-value"]


def test_api_version_mismatch_rejected():
    class Old(ProtocolPlugin):
        name = "old"
        api_version = PLUGIN_API + 1

    reg = Registry()
    reg.add(Old, "test")
    assert "old" not in reg.plugins and "targets API" in reg.load_errors[0]


def test_opt_in_and_unknown_selection():
    class OptIn(ProtocolPlugin):
        name = "optin-test"
        opt_in = True

    reg = Registry()
    reg.add(OptIn, "test")
    assert reg.select_protocols() == []
    assert [p.name for p in reg.select_protocols(enable=["optin-test"])] == ["optin-test"]
    assert [p.name for p in reg.select_protocols(enable=["all"])] == ["optin-test"]
    try:
        reg.select_protocols(enable=["nope"])
    except KeyError as exc:
        assert "nope" in str(exc)
    else:
        raise AssertionError("unknown plugin accepted")


def test_failing_plugin_is_isolated_and_counted():
    class Boom(ProtocolPlugin):
        name = "boom"

        def on_data(self, ctx, direction, data):
            raise ValueError("synthetic failure")

    from netcreds_ng.plugins.protocols.ftp import FTPPlugin

    c = TCPConversation(C, 50000, S, 21).handshake()
    c.server(b"220 hi\r\n").client(b"USER u\r\nPASS isolated-pass\r\n").close()
    stats = RunStats()
    found: list[Finding] = []
    pipe = Pipeline(stats, listeners=[found.append])
    eng = Engine([Boom(), FTPPlugin()], pipe, stats)
    from netcreds_ng.testing.harness import to_raw_frames

    eng.process(to_raw_frames(c.frames))
    eng.finish()
    assert stats.plugin_errors["boom"] == 1, "error counted once, then the plugin is detached for that flow"
    assert any(f.secret == "isolated-pass" for f in found), "other plugins keep working"
    assert "synthetic failure" in pipe.errors[0]


def _finding(secret="s3cret-fake", user="u", proto="FTP", dst="198.51.100.20") -> Finding:
    return Finding(proto, Kind.CREDENTIAL, Endpoint(C, 1), Endpoint(dst, 21), username=user, secret=secret)


def test_dedup_modes(tmp_path):
    run = Deduplicator("run")
    assert run.is_new(_finding()) and not run.is_new(_finding())
    off = Deduplicator("off")
    assert off.is_new(_finding()) and off.is_new(_finding())
    db = str(tmp_path / "state.sqlite3")
    p1 = Deduplicator("persistent", db)
    assert p1.is_new(_finding())
    p1.close()
    p2 = Deduplicator("persistent", db)
    assert not p2.is_new(_finding()), "persistent dedup survives across runs"
    p2.close()


def test_analytics_weak_and_reused_passwords():
    an = AnalyticsEnricher()
    f1, f2, f3 = _finding("password", "alice"), _finding("Uniq-Fake-77", "bob"), _finding("Uniq-Fake-77", "carol", "HTTP", "198.51.100.99")
    for f in (f1, f2, f3):
        list(an.enrich(f))
    assert "weak-password" in f1.tags and f1.risk == "high"
    assert "password-reuse" in f3.tags and "password-reuse" not in f1.tags
    assert f2.extra["secret_fingerprint"] == f3.extra["secret_fingerprint"]
    assert "Uniq-Fake-77" not in repr(an.summary())
    assert an.summary()["weak_passwords"] == 1 and an.summary()["reused_secrets"] == 1


def test_mask_value():
    assert mask_value("FakePass-123") == "F**********3 (12)"
    assert mask_value("ab") == "** (2)"
    assert mask_value("") == ""


# --- robustness ------------------------------------------------------------------


def _engine_all() -> tuple[Engine, RunStats]:
    reg = load_registry(use_entry_points=False)
    stats = RunStats()
    pipe = Pipeline(stats, enrichers=reg.select_enrichers(enable=["all"]))
    return Engine(reg.select_protocols(enable=["all"]), pipe, stats), stats


@settings(max_examples=300, deadline=None)
@given(st.lists(st.binary(max_size=300), max_size=20), st.sampled_from([0, 1, 101, 113, 276, 999]))
def test_random_frames_never_crash_engine(frames, linktype):
    eng, stats = _engine_all()
    for i, data in enumerate(frames, 1):
        eng.process_frame(RawFrame(i, float(i), linktype, data, len(data)))
    eng.finish()
    assert stats.total_plugin_errors == 0


@settings(max_examples=300, deadline=None)
@given(st.lists(st.binary(min_size=1, max_size=400), min_size=1, max_size=12), st.sampled_from(
    [21, 23, 25, 80, 88, 110, 143, 161, 389, 445, 1883, 3306, 5060, 5432, 5900, 6379, 6667, 31337]))
def test_random_payloads_on_protocol_ports_never_error(payloads, port):
    eng, stats = _engine_all()
    c = TCPConversation(C, 40000, S, port).handshake()
    for i, p in enumerate(payloads):
        (c.client if i % 2 == 0 else c.server)(p)
    c.close()
    frames = list(c.frames)
    frames.append(type(c.frames[0])(frame_for(ip_packet(C, S, 17, udp(C, S, 40001, port, payloads[0]))), 2e9))
    from netcreds_ng.testing.harness import to_raw_frames

    eng.process(to_raw_frames(frames))
    eng.finish()
    assert stats.total_plugin_errors == 0


def test_random_segment_order_is_reassembled():
    rng = random.Random(1234)
    data = b"USER shuffle-user\r\nPASS Shuffle-Fake-Pass\r\n"
    c = TCPConversation(C, 40002, S, 21).handshake()
    c.server(b"220 ready\r\n")
    pieces = [(i, data[i : i + 5]) for i in range(0, len(data), 5)]
    rng.shuffle(pieces)
    for off, piece in pieces:
        c.raw_segment(True, piece, rel_offset=off)
    c.advance(True, len(data)).close()
    found = analyze(c.frames, enrichers=[])
    assert [(f.username, f.secret) for f in found if f.kind is Kind.CREDENTIAL] == [("shuffle-user", "Shuffle-Fake-Pass")]


def test_large_capture_memory_is_bounded():
    eng, stats = _engine_all()
    from netcreds_ng.testing.harness import to_raw_frames

    frames = []
    for n in range(3000):  # many short flows
        frames.append(frame_for(ip_packet(C, S, 6, tcp(C, S, 10000 + n % 50000, 80, n, 0, 0x18, b"x" * 10))))
    eng.process(to_raw_frames(frames))
    assert eng.active_flows <= 3000
    eng.finish()
    assert eng.active_flows == 0 and stats.total_plugin_errors == 0
