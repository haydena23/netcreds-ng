"""The optimisation pass's shortcuts give exactly the results of the code they skip."""

from __future__ import annotations

import gc
import random

from netcreds_ng.engine.engine import SWEEP_EVERY, Engine, relaxed_gc
from netcreds_ng.engine.pcapio import RawFrame
from netcreds_ng.engine.pipeline import Pipeline
from netcreds_ng.model import RunStats
from netcreds_ng.plugins.protocols import keyvalue
from netcreds_ng.plugins.protocols._util import LineBuffer
from netcreds_ng.plugins.protocols.http import PASS_FIELDS, _Parser
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.testing.packets import TCPConversation


class _OldLineBuffer:
    """LineBuffer.feed as it was before the optimisation pass (the reference)."""

    def __init__(self, max_line: int = 64 * 1024) -> None:
        self.buf, self.max_line, self.skip = bytearray(), max_line, False

    def feed(self, data: bytes) -> list[bytes]:
        if self.skip:
            idx = data.find(b"\n")
            if idx < 0:
                return []
            data, self.skip = data[idx + 1 :], False
        self.buf += data
        lines = []
        while (idx := self.buf.find(b"\n")) >= 0:
            line = bytes(self.buf[:idx])
            del self.buf[: idx + 1]
            lines.append(line[:-1] if line.endswith(b"\r") else line)
        if len(self.buf) > self.max_line:
            self.buf.clear()
        return lines


def test_line_buffer_matches_reference() -> None:
    rnd = random.Random(5)
    alphabet = b"ab\r\n\n=\r"
    for _ in range(300):
        new, old = LineBuffer(max_line=40), _OldLineBuffer(max_line=40)
        for _ in range(rnd.randint(1, 12)):
            if rnd.random() < 0.1:
                new.gap()
                old.buf.clear()
                old.skip = True
            chunk = bytes(rnd.choice(alphabet) for _ in range(rnd.randint(0, 60)))
            assert new.feed(chunk) == old.feed(chunk)
            assert new.pending == bytes(old.buf)
            assert all(isinstance(line, bytes) for line in new.feed(b""))


def test_keyvalue_hints_cover_every_password_field() -> None:
    for name in PASS_FIELDS:
        assert any(h.decode() in name for h in keyvalue._PASS_HINTS), name
        line = f"x {name.upper()}=FakeValue1".encode()
        assert keyvalue._candidate(line) and keyvalue._PASS.search(line)
    assert not keyvalue._candidate(b"user=alice&session=1")  # no password field: the regex is skipped


def test_http_response_search_resumes_across_chunks() -> None:
    p = _Parser(is_request=False)
    noise = bytes(range(256)) * 4
    for cut in range(1, 8):  # the start line split at every offset of the 7-byte marker
        p = _Parser(is_request=False)
        assert p.feed(noise + b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[:cut]) == []
        out = p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[cut:])
        assert len(out) == 1 and out[0][0][0] == "200", cut
    p = _Parser(is_request=False)
    p.feed(noise)
    assert p.searched == len(noise) - 6
    p.resync()
    assert p.searched == 0


def _engine() -> Engine:
    reg = load_registry(use_entry_points=False)
    stats = RunStats()
    return Engine(reg.select_protocols(), Pipeline(stats), stats)


def _frames(conv: TCPConversation, start: int = 1) -> list[RawFrame]:
    return [RawFrame(start + i, f.timestamp, 1, f.data, len(f.data)) for i, f in enumerate(conv.frames)]


def test_sweep_counts_every_frame_read() -> None:
    """Undecodable frames advance the sweep schedule too, so parallel workers sweep at the same frames."""
    e = _engine()
    c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 9000)
    c.handshake().client(b"hello").close()
    for f in _frames(c):
        e.process_frame(f)
    assert e.active_flows == 1  # closed (FIN both ways) but not swept yet
    junk = RawFrame(0, c.frames[-1].timestamp, 1, b"\x00" * 10, 10)
    for _ in range(SWEEP_EVERY - len(c.frames)):
        e.process_frame(junk)
    assert e.active_flows == 0
    e2 = _engine()
    for f in _frames(c):
        e2.process_frame(f)
    for _ in range(SWEEP_EVERY - len(c.frames)):
        e2.skip_frame(junk.timestamp)  # what a parallel worker does for frames it does not own
    assert e2.active_flows == 0 and e2.position == SWEEP_EVERY


def test_emit_order_and_finish() -> None:
    e = _engine()
    tags = []
    e.pipeline.listeners.append(lambda f: tags.append(e.emit_order))
    c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 21)
    c.handshake().server(b"220 ftp\r\n").client(b"USER u\r\nPASS FakePass-9\r\n")  # no close: reported at finish
    for f in _frames(c):
        e.process_frame(f)
    e.finish()
    assert tags and all(t[0] <= e.position for t in tags)
    e.stats.ip_fragments_expired = 5  # e.g. merged from parallel workers
    e.finish()
    assert e.stats.ip_fragments_expired == 5  # added to, not overwritten


def test_closed_flows_leave_no_reference_cycles() -> None:
    e = _engine()
    for i in range(20):
        c = TCPConversation(f"192.0.2.{i + 1}", 40000, "198.51.100.2", 21, start=1_700_000_000.0 + i)
        c.handshake().server(b"220 ftp\r\n").client(b"USER u\r\nPASS FakePass-9\r\n").close()
        for f in _frames(c):
            e.process_frame(f)
    gc.collect()
    gc.disable()
    try:
        e.finish()
        assert gc.collect() == 0  # every flow's slots, contexts and states were freed by reference counting
    finally:
        gc.enable()


def test_relaxed_gc_restores_the_threshold() -> None:
    before = gc.get_threshold()
    with relaxed_gc():
        assert gc.get_threshold()[0] >= 50_000
    assert gc.get_threshold() == before


def test_idle_flow_swept_during_non_ip_traffic() -> None:
    """I-17: frames that do not decode still advance the sweep, so a flow idle past the timeout is
    closed even when only non-IP traffic (ARP, LLDP) arrives meanwhile; a login across the idle
    period is then two findings (user name, then password on a new flow)."""
    e = _engine()
    found = []
    e.pipeline.listeners.append(found.append)
    c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 21, start=1_700_000_000.0)
    c.handshake().server(b"220 ftp\r\n").client(b"USER idle\r\n")
    for f in _frames(c):
        e.process_frame(f)
    late = c.frames[-1].timestamp + 700  # past IDLE_TIMEOUT (600 s)
    junk = RawFrame(0, late, 1, b"\x00" * 10, 10)
    for _ in range(SWEEP_EVERY):
        e.process_frame(junk)
    assert e.active_flows == 0
    c2 = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 21, start=late + 1)
    c2.client(b"PASS FakePass-1\r\n")
    for f in _frames(c2):
        e.process_frame(f)
    e.finish()
    kinds = [f.kind.value for f in found]
    assert "credential" not in kinds and "username" in kinds and "password" in kinds
