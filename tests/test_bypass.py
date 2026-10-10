"""M16 encrypted-flow bypass: connections opening with TLS (no key log) or SSH skip cleartext-only plugins."""

from __future__ import annotations

import base64
import struct

import pytest

from netcreds_ng.engine.engine import SSH_BANNERS, Engine
from netcreds_ng.engine.pipeline import Pipeline
from netcreds_ng.model import Kind, RunStats
from netcreds_ng.plugins.api import Context, Direction, ProtocolPlugin
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.testing.harness import to_raw_frames
from netcreds_ng.testing.packets import TCPConversation


class Recorder(ProtocolPlugin):
    """Counts the bytes it receives; ``wants_encrypted`` keeps the default (True), like third-party plugins."""

    name = "recorder"

    def __init__(self) -> None:
        super().__init__()
        self.received = 0

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        self.received += len(data)


class CleartextRecorder(Recorder):
    name = "cleartext_recorder"
    wants_encrypted = False


def client_hello() -> bytes:
    body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00\x00\x00"
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def run(conv: TCPConversation, plugins: list[ProtocolPlugin], tls=None):
    stats = RunStats()
    found = []
    engine = Engine(plugins, Pipeline(stats, listeners=[found.append]), stats, tls=tls)
    engine.process(to_raw_frames(conv.close().frames))
    engine.finish()
    return found, stats


def test_tls_without_keys_skips_cleartext_plugins() -> None:
    c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 443)
    c.handshake().client(client_hello()).server(b"\x16\x03\x03\x00\x02\x02\x00" + bytes(3000))
    c.client(b"\x17\x03\x03\x00\x20" + b"USER x\r\nPASS FakePass-1\r\nuser=a&pass=b\r\n"[:32])
    rec, clear = Recorder(), CleartextRecorder()
    _, stats = run(c, [rec, clear])
    assert stats.encrypted_flows == 1
    assert rec.received > 3000 and clear.received == 0


def test_builtin_plugins_find_nothing_but_mssql_still_reads_the_client_hello() -> None:
    reg = load_registry(use_entry_points=False)
    plugins = reg.select_protocols()
    assert [p.name for p in plugins if p.wants_encrypted] == ["mssql"]  # it reports TDS 8 strict TLS from the ALPN
    c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 4433)
    c.handshake().client(client_hello() + b"USER alice\r\nPASS FakePass-2\r\n")  # cleartext-looking bytes after it
    found, stats = run(c, plugins)
    assert stats.encrypted_flows == 1 and found == []


@pytest.mark.parametrize("first", ["server", "client"])
def test_ssh_banner_from_either_side(first: str) -> None:
    clear = CleartextRecorder()
    c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 22)
    c.handshake()
    if first == "server":
        c.server(b"SSH-2.0-OpenSSH_9.6\r\n").client(b"SSH-2.0-PuTTY\r\nlogin: root\r\n")
    else:
        c.client(b"SSH-2.0-PuTTY\r\n").server(b"SSH-2.0-OpenSSH_9.6\r\nPassword: \r\n")
    _, stats = run(c, [clear])
    assert stats.encrypted_flows == 1 and clear.received == 0


def test_cleartext_and_starttls_are_not_bypassed() -> None:
    reg = load_registry(use_entry_points=False)
    c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 21)
    c.handshake().server(b"220 ftp\r\n").client(b"USER u\r\nPASS FakePass-3\r\n").server(b"230 ok\r\n")
    c.client(b"AUTH TLS\r\n").server(b"234 go\r\n").client(client_hello())  # TLS later in the stream
    found, stats = run(c, reg.select_protocols())
    assert stats.encrypted_flows == 0
    assert any(f.kind is Kind.CREDENTIAL and f.secret == "FakePass-3" for f in found)


def test_key_log_keeps_tls_for_decryption(tmp_path) -> None:
    pytest.importorskip("cryptography")
    from netcreds_ng.engine.tls import KeyLog, TLSDecryptor
    from netcreds_ng.testing.tls_lab import tls_conversation

    basic = base64.b64encode(b"alice:Fake-Pass-4").decode()
    req = f"GET / HTTP/1.1\r\nHost: t.example\r\nAuthorization: Basic {basic}\r\n\r\n".encode()
    keylog = tmp_path / "keys.log"
    conv, _ = tls_conversation(tmp_path, [(req, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")], keylog=str(keylog))
    reg = load_registry(use_entry_points=False)
    found, stats = run(conv, reg.select_protocols(), tls=TLSDecryptor(KeyLog(str(keylog))))
    assert stats.encrypted_flows == 0 and stats.tls_decrypted == 1
    assert any(f.secret == "Fake-Pass-4" for f in found)


@pytest.mark.parametrize("cut", range(1, 9))
def test_split_first_segment_is_still_recognised(cut: int) -> None:
    """A ClientHello or SSH banner whose first segment is too short to decide is held until it can be."""
    for opening in (client_hello(), b"SSH-2.0-PuTTY\r\n"):
        if opening.startswith(b"\x16") and cut > 5:
            continue  # 6 bytes decide a ClientHello
        rec = CleartextRecorder()
        c = TCPConversation("192.0.2.1", 40000, "198.51.100.2", 443)
        c.handshake().client(opening[:cut]).client(opening[cut:] + b"x" * 40)
        _, stats = run(c, [rec])
        assert stats.encrypted_flows == 1, (opening[:8], cut)
        decisive = opening[:cut].startswith(SSH_BANNERS)
        assert rec.received == (0 if decisive else cut)  # only an undecidable prefix is delivered
