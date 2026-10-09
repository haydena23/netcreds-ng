"""M8: TLS decryption with a key-log file, checked against real OpenSSL sessions (in memory, no sockets)."""

from __future__ import annotations

import base64

import pytest

pytest.importorskip("cryptography")

from netcreds_ng.engine.engine import Engine
from netcreds_ng.engine.pipeline import Pipeline
from netcreds_ng.engine.tls import KeyLog, TLSDecryptor, hkdf_expand_label, prf12
from netcreds_ng.model import Kind, RunStats
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.testing.harness import to_raw_frames
from netcreds_ng.testing.packets import TCPConversation
from netcreds_ng.testing.tls_lab import tls_conversation

BASIC = base64.b64encode(b"alice:Fake-Pass-1").decode()
REQUEST = f"GET /admin HTTP/1.1\r\nHost: test.example\r\nAuthorization: Basic {BASIC}\r\n\r\n".encode()
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def analyse(conv: TCPConversation, keylog: KeyLog | None):
    stats = RunStats()
    found = []
    reg = load_registry(use_entry_points=False)
    pipe = Pipeline(stats, listeners=[found.append])
    engine = Engine(reg.select_protocols(), pipe, stats, tls=TLSDecryptor(keylog) if keylog is not None else None)
    engine.process(to_raw_frames(conv.close().frames))
    engine.finish()
    assert not stats.plugin_errors, pipe.errors
    return found, stats


def creds(found):
    return [(f.protocol, f.username, f.secret, "tls-decrypted" in f.tags) for f in found if f.kind is Kind.CREDENTIAL]


def session(tmp_path, **kw):
    keylog = tmp_path / "keys.log"
    conv, cipher = tls_conversation(tmp_path, [(REQUEST, RESPONSE)], keylog=str(keylog), **kw)
    return conv, cipher, KeyLog(str(keylog))


def test_tls13_default_suite(tmp_path):
    conv, cipher, keylog = session(tmp_path)
    assert cipher.startswith("TLS_")
    found, stats = analyse(conv, keylog)
    assert creds(found) == [("HTTP", "alice", "Fake-Pass-1", True)]
    assert stats.tls_sessions == 1 and stats.tls_decrypted == 1


@pytest.mark.parametrize(
    "ciphers",
    [
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-SHA",  # CBC + HMAC-SHA1
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-ECDSA-AES256-SHA384",
    ],
)
def test_tls12_suites(tmp_path, ciphers):
    conv, cipher, keylog = session(tmp_path, version="1.2", ciphers=ciphers)
    assert cipher == ciphers
    found, stats = analyse(conv, keylog)
    assert creds(found) == [("HTTP", "alice", "Fake-Pass-1", True)]
    assert stats.tls_decrypted == 1


@pytest.mark.parametrize("ciphers", ["ECDHE-ECDSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA384"])
def test_tls12_cbc_without_encrypt_then_mac(tmp_path, ciphers):
    conv, _, keylog = session(tmp_path, version="1.2", ciphers=ciphers, no_etm=True)
    assert creds(analyse(conv, keylog)[0]) == [("HTTP", "alice", "Fake-Pass-1", True)]


def test_tls12_rsa_certificate(tmp_path):
    conv, _, keylog = session(tmp_path, version="1.2", ciphers="ECDHE-RSA-AES256-GCM-SHA384", rsa=True)
    assert creds(analyse(conv, keylog)[0]) == [("HTTP", "alice", "Fake-Pass-1", True)]


def test_without_matching_key_nothing_leaks(tmp_path):
    conv, _, _ = session(tmp_path)
    found, stats = analyse(conv, KeyLog(text=""))
    assert creds(found) == []
    assert stats.tls_no_key == 1


def test_without_keylog_the_engine_is_unchanged(tmp_path):
    conv, _, _ = session(tmp_path)
    found, stats = analyse(conv, None)
    assert creds(found) == [] and stats.tls_sessions == 0


def test_multiple_requests_on_one_session(tmp_path):
    keylog = tmp_path / "keys.log"
    second = REQUEST.replace(BASIC.encode(), base64.b64encode(b"bob:Fake-Pass-2"))
    conv, _ = tls_conversation(tmp_path, [(REQUEST, RESPONSE), (second, RESPONSE)], keylog=str(keylog))
    got = creds(analyse(conv, KeyLog(str(keylog)))[0])
    assert got == [("HTTP", "alice", "Fake-Pass-1", True), ("HTTP", "bob", "Fake-Pass-2", True)]


def test_starttls_smtp_auth_inside_tls(tmp_path):
    keylog = tmp_path / "keys.log"
    c = TCPConversation("192.0.2.10", 50025, "198.51.100.20", 25).handshake()
    c.server(b"220 mail.example ESMTP\r\n").client(b"EHLO ws\r\n")
    c.server(b"250-mail.example\r\n250 STARTTLS\r\n").client(b"STARTTLS\r\n").server(b"220 go ahead\r\n")
    auth = b"AUTH PLAIN " + base64.b64encode(b"\0carol\0Fake-Pass-3") + b"\r\n"
    conv, _ = tls_conversation(tmp_path, [(b"EHLO ws\r\n", b"250 AUTH PLAIN\r\n"), (auth, b"235 ok\r\n")],
                               keylog=str(keylog), conv=c)  # fmt: skip
    found, stats = analyse(conv, KeyLog(str(keylog)))
    assert ("SMTP", "carol", "Fake-Pass-3", True) in creds(found)
    assert stats.tls_decrypted == 1


def test_decrypted_findings_are_not_counted_as_cleartext(tmp_path):
    from netcreds_ng.plugins.enrichers.analytics import AnalyticsEnricher
    from netcreds_ng.plugins.enrichers.detection import DetectionEnricher

    conv, _, keylog = session(tmp_path)
    stats = RunStats()
    found = []
    det = DetectionEnricher()
    pipe = Pipeline(stats, enrichers=[AnalyticsEnricher(), det], listeners=[found.append])
    engine = Engine(load_registry(use_entry_points=False).select_protocols(), pipe, stats, tls=TLSDecryptor(keylog))
    engine.process(to_raw_frames(conv.close().frames))
    engine.finish()
    (cred,) = [f for f in found if f.kind is Kind.CREDENTIAL]
    assert "cleartext" not in cred.tags and "tls-decrypted" in cred.tags
    assert not any(s["cleartext"] for s in det.summary()["services"])


def test_capture_gap_stops_that_direction_safely(tmp_path):
    conv, _, keylog = session(tmp_path)
    frames = conv.close().frames
    # drop the client's application-data segment (the 4th client data segment from the end region)
    data_frames = [i for i, f in enumerate(frames) if len(f.data) > 200]
    del frames[data_frames[-2]]
    stats = RunStats()
    pipe = Pipeline(stats)
    engine = Engine(load_registry(use_entry_points=False).select_protocols(), pipe, stats, tls=TLSDecryptor(keylog))
    engine.process(to_raw_frames(frames))
    engine.finish()
    assert not stats.plugin_errors


def test_keylog_parsing_and_reload(tmp_path):
    path = tmp_path / "k.log"
    path.write_text("# comment\nCLIENT_RANDOM " + "aa" * 32 + " " + "bb" * 48 + "\nJUNK line\n", encoding="ascii")
    log = KeyLog(str(path))
    assert log.lookup(bytes.fromhex("aa" * 32)) == {"CLIENT_RANDOM": bytes.fromhex("bb" * 48)}
    with open(path, "a", encoding="ascii") as fh:
        fh.write("CLIENT_TRAFFIC_SECRET_0 " + "cc" * 32 + " " + "dd" * 32 + "\n")
    assert log.lookup(bytes.fromhex("cc" * 32)) is not None  # picked up on a miss


def test_prf_and_hkdf_shapes():
    assert len(prf12("sha256", b"k", b"label", b"seed", 100)) == 100
    assert prf12("sha256", b"k", b"label", b"seed", 32) == prf12("sha256", b"k", b"label", b"seed", 64)[:32]
    # RFC 8448 section 3: client handshake key derived from the client handshake traffic secret
    secret = bytes.fromhex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    assert hkdf_expand_label("sha256", secret, b"key", b"", 16).hex() == "dbfaa693d1762c5b666af5d950258d01"
    assert hkdf_expand_label("sha256", secret, b"iv", b"", 12).hex() == "5bd3c71b836e0b76bb73265f"


def test_cli_tls_keylog(tmp_path, capsys):
    from netcreds_ng.cli import main
    from netcreds_ng.testing.packets import write_pcap

    conv, _, _ = session(tmp_path)
    pcap = tmp_path / "tls.pcap"
    write_pcap(str(pcap), conv.close().frames)
    out = tmp_path / "f.jsonl"
    assert main(["-p", str(pcap), "--jsonl", str(out), "--tls-keylog", str(tmp_path / "keys.log")]) == 0
    text = out.read_text(encoding="utf-8")
    assert "Fake-Pass-1" in text and "tls-decrypted" in text
    assert "TLS sessions" in capsys.readouterr().out
    assert main(["-p", str(pcap), "-q", "--tls-keylog", str(tmp_path / "missing.log")]) == 1


def test_http2_inside_tls_with_alpn(tmp_path):
    from netcreds_ng.testing import h2_msgs as h2

    enc, senc = h2.Encoder(), h2.Encoder()
    req = h2.request_headers(b"GET", b"/admin", authority=b"test.example", extra=[(b"authorization", f"Basic {BASIC}".encode())])
    client = h2.PREFACE + h2.settings() + h2.headers_frame(1, enc.encode(req), end_stream=True)
    server = h2.settings() + h2.settings(ack=True) + h2.headers_frame(1, senc.encode([(b":status", b"401")]), end_stream=True)
    keylog = tmp_path / "keys.log"
    conv, _ = tls_conversation(tmp_path, [(client, server)], keylog=str(keylog), alpn=["h2"])
    found, _ = analyse(conv, KeyLog(str(keylog)))
    assert creds(found) == [("HTTP/2", "alice", "Fake-Pass-1", True)]
    results = [f for f in found if f.kind is Kind.AUTH_RESULT]
    assert [r.outcome for r in results] == ["failure"] and "tls-decrypted" in results[0].tags


def test_client_hello_split_after_one_byte(tmp_path):
    # E-8: the client's first TCP segment carries a single byte of the ClientHello
    keylog = tmp_path / "keys.log"
    conv = TCPConversation("192.0.2.10", 50444, "198.51.100.20", 443).handshake()
    tls_conversation(tmp_path, [(REQUEST, RESPONSE)], keylog=str(keylog), conv=_SplitFirst(conv))
    assert len(conv.frames[3].data) == 54 + 1  # Ethernet/IP/TCP headers + 1 payload byte
    found, stats = analyse(conv, KeyLog(str(keylog)))
    assert creds(found) == [("HTTP", "alice", "Fake-Pass-1", True)]
    assert stats.tls_sessions == 1


class _SplitFirst:
    """Proxy for TCPConversation whose first client() call is sent as 1 byte + the rest."""

    def __init__(self, conv):
        self._conv, self._split = conv, True

    def client(self, data, segment=None):
        if self._split and len(data) > 1:
            self._split = False
            self._conv.client(data[:1])
            return self._conv.client(data[1:])
        return self._conv.client(data, segment)

    def __getattr__(self, name):
        return getattr(self._conv, name)


def test_short_non_tls_start_is_released():
    from netcreds_ng.engine.tls import could_start_client_hello

    assert could_start_client_hello(b"\x16") and could_start_client_hello(b"\x16\x03\x01")
    assert not could_start_client_hello(b"\x16\x02") and not could_start_client_hello(b"US")


def _seal13(keys, inner_type: int, payload: bytes) -> bytes:
    """Encrypt one TLS 1.3 record with ``keys`` (test helper mirroring RFC 8446 section 5.2)."""
    import struct

    from netcreds_ng.engine.tls import _xor_nonce

    inner = payload + bytes([inner_type])
    header = struct.pack("!BHH", 23, 0x0303, len(inner) + 16)
    sealed = keys.aead.encrypt(_xor_nonce(keys.iv, keys.seq), inner, header)
    keys.seq += 1
    return header + sealed


def test_tls13_split_handshake_message_and_key_update():
    # Review L2: a handshake message continued in a record starting with byte 24 is not a KeyUpdate.
    from netcreds_ng.engine.tls import SUITES13, TLS13, TLSSession, hkdf_expand_label, keys13

    suite = SUITES13[0x1301]
    secret = bytes(range(32))
    session = TLSSession(KeyLog(text=""))
    session.version, session.suite, session.status = TLS13, suite, "decrypting"
    server = session.sides[1]
    server.keys, server.encrypted = [keys13(suite, secret)], True
    sender = keys13(suite, secret)

    ticket_body = bytes([24]) + b"\x00" * 39  # the continuation will start with 0x18
    ticket = bytes([4]) + len(ticket_body).to_bytes(3, "big") + ticket_body  # NewSessionTicket
    wire = _seal13(sender, 22, ticket[:4]) + _seal13(sender, 22, ticket[4:]) + _seal13(sender, 23, b"first")
    assert session.feed(1, wire) == [b"first"]

    update = bytes([24, 0, 0, 1, 0])  # KeyUpdate(update_not_requested)
    wire = _seal13(sender, 22, update)
    nxt = hkdf_expand_label("sha256", secret, b"traffic upd", b"", 32)
    wire += _seal13(keys13(suite, nxt), 23, b"after update")
    assert session.feed(1, wire) == [b"after update"]
