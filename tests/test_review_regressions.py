"""Regression tests for findings from the independent protocol review (all values fake)."""

from __future__ import annotations

import base64

from netcreds_ng.model import Kind
from netcreds_ng.output.masking import masked
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation
from netcreds_ng.testing.protocols import ntlm_type3

C, S = "192.0.2.10", "198.51.100.20"


def creds(findings):
    return [(f.protocol, f.username, f.secret) for f in findings if f.kind in (Kind.CREDENTIAL, Kind.PASSWORD)]


def results(findings):
    return [(f.protocol, f.value) for f in findings if f.kind is Kind.AUTH_RESULT]


# --- HIGH: a gap must never be spliced into a credential ----------------------------


def test_gap_inside_ftp_password_is_not_reported_as_fact():
    c = TCPConversation(C, 50000, S, 21).handshake()
    c.server(b"220 ready\r\n").client(b"USER gapuser\r\n").server(b"331 ok\r\n")
    c.client(b"PASS pw").advance(True, 3).client(b"fake\r\n")  # 3 bytes never captured
    c.client(b"NOOP\r\n").close()
    found = analyze(c.frames, enrichers=[])
    assert not [s for _, _, s in creds(found) if s and s.startswith("pw")]


def test_gap_resynchronises_on_next_line():
    c = TCPConversation(C, 50001, S, 110).handshake()
    c.server(b"+OK\r\n").client(b"NOOP xx").advance(True, 4).client(b"yy\r\nUSER resync\r\nPASS Resync-Fake\r\n").close()
    assert creds(analyze(c.frames, enrichers=[])) == [("POP3", "resync", "Resync-Fake")]


def test_gap_in_auth_login_drops_exchange():
    c = TCPConversation(C, 50002, S, 25).handshake()
    c.server(b"220 mx ESMTP\r\n").client(b"AUTH LOGIN\r\n").server(b"334 VXNlcm5hbWU6\r\n")
    user = base64.b64encode(b"gapmailuser") + b"\r\n"
    c.client(user[:4]).advance(True, 4).client(user[8:])
    c.client(base64.b64encode(b"Gap-Mail-Pass") + b"\r\n").close()
    assert creds(analyze(c.frames, enrichers=[])) == []


def test_default_on_gap_detaches_plugins_without_override():
    from netcreds_ng.model import Endpoint
    from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin, Transport

    ctx = Context(FlowInfo(1, Transport.TCP, Endpoint(C, 1), Endpoint(S, 2)), lambda f: None, {})
    ProtocolPlugin().on_gap(ctx, Direction.CLIENT_TO_SERVER, 10)
    assert ctx.detached


# --- HIGH: port reuse without FIN/RST ----------------------------------------------


def _session(cport: int, isn: int, user: str) -> list:
    c = TCPConversation(C, cport, S, 21, client_isn=isn).handshake()
    c.server(b"220 hi\r\n").client(f"USER {user}\r\nPASS pw-{user}\r\n".encode())
    return c.frames  # no teardown


def test_port_reuse_without_fin_isn_behind():
    frames = _session(40000, 0xC0000000, "first") + _session(40000, 1000, "second")
    assert [u for _, u, _ in creds(analyze(frames, enrichers=[]))] == ["first", "second"]


def test_port_reuse_without_fin_isn_ahead():
    frames = _session(40001, 1000, "first") + _session(40001, 0x7000_0000, "second")
    assert [u for _, u, _ in creds(analyze(frames, enrichers=[]))] == ["first", "second"]


def test_duplicate_syn_does_not_reset_flow():
    c = TCPConversation(C, 40002, S, 21, client_isn=5000).handshake()
    dup_syn = c.frames[0]
    c.server(b"220 hi\r\n").client(b"USER dupsyn\r\n")
    frames = [*c.frames, dup_syn]
    c.frames = []
    c.client(b"PASS Dup-Syn-Fake\r\n")
    frames += c.frames
    assert creds(analyze(frames, enrichers=[])) == [("FTP", "dupsyn", "Dup-Syn-Fake")]


# --- MEDIUM ---------------------------------------------------------------------------


def test_pop3_without_greeting_reported_once():
    c = TCPConversation(C, 50003, S, 110).handshake()
    c.client(b"USER carol\r\nPASS Pop-No-Greeting\r\n").close()
    assert creds(analyze(c.frames, enrichers=[])) == [("POP3", "carol", "Pop-No-Greeting")]


def test_ftp_auth_tls_is_not_redis():
    c = TCPConversation(C, 50004, S, 21).handshake()
    c.client(b"AUTH TLS\r\n").close()
    assert analyze(c.frames, enrichers=[]) == []


def test_http_100_continue_is_not_a_verdict_and_form_has_no_success_claim():
    body = b"username=formuser&password=Form-Fake-Pass"
    c = TCPConversation(C, 50005, S, 80).handshake()
    c.client(b"POST /login HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Type: application/x-www-form-urlencoded"
             b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")  # fmt: skip
    c.server(b"HTTP/1.1 100 Continue\r\n\r\n").client(body).server(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
    c.client(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "
             + str(len(body)).encode() + b"\r\n\r\n" + body)  # fmt: skip
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfail").close()
    assert results(analyze(c.frames, enrichers=[])) == [("HTTP", "form login failed (HTTP 401)")]


def test_http_head_response_has_no_body():
    auth = b"Authorization: Basic " + base64.b64encode(b"headuser:Head-Fake") + b"\r\n"
    c = TCPConversation(C, 50006, S, 80).handshake()
    c.client(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n" + auth + b"\r\n")
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\nHTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
    c.close()
    assert results(analyze(c.frames, enrichers=[])) == [("HTTP", "Basic login failed (HTTP 401)")]


def test_abandoned_auth_login_yields_no_garbage_credential():
    c = TCPConversation(C, 50007, S, 25).handshake()
    c.server(b"220 mx ESMTP\r\n").client(b"AUTH LOGIN\r\n").server(b"334 VXNlcm5hbWU6\r\n")
    c.client(b"RSET\r\nNOOP\r\n").close()
    assert creds(analyze(c.frames, enrichers=[])) == []


def test_telnet_prompt_inside_http_response_ignored():
    c = TCPConversation(C, 50008, S, 8000).handshake()
    c.client(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nEnter Password:")
    c.client(b"GET /next HTTP/1.1\r\nHost: x\r\n\r\n").close()
    assert not [f for f in analyze(c.frames, enrichers=[]) if f.protocol == "Telnet"]


def test_telnet_password_for_prompt():
    c = TCPConversation(C, 50009, S, 23).handshake()
    c.server(b"Password for alice: ").client(b"Telnet-For-Fake\r\n").close()
    assert creds(analyze(c.frames, enrichers=[])) == [("Telnet", None, "Telnet-For-Fake")]


# --- LOW ------------------------------------------------------------------------------


def test_cram_md5_without_space_never_puts_digest_in_username():
    c = TCPConversation(C, 50010, S, 25).handshake()
    c.server(b"220 mx ESMTP\r\n").client(b"AUTH CRAM-MD5\r\n").server(b"334 PDEyMzQ+\r\n")
    c.client(base64.b64encode(b"DIGESTMARKNOSPACE0123456789abcdef") + b"\r\n").close()
    events = [f for f in analyze(c.frames, enrichers=[]) if f.kind is Kind.AUTH_EVENT]
    assert events and all(e.username is None for e in events)
    assert "DIGESTMARK" not in repr([e.to_dict() for e in events])


def test_ntlm_event_reported_once_regardless_of_segmentation_and_no_response_hash():
    msg = ntlm_type3("seguser", "FAKEDOM", "FAKEWS", nt_len=64)
    counts = []
    for seg in (None, 7, 13):
        c = TCPConversation(C, 50011, S, 445).handshake()
        c.client(b"\x00\x00\x01\x00" + msg, segment=seg).close()
        events = [f for f in analyze(c.frames, enrichers=[]) if f.kind is Kind.AUTH_EVENT]
        counts.append(len(events))
        assert "evidence_fingerprint" not in events[0].extra
    assert counts == [1, 1, 1]


def test_repeated_login_failures_are_not_collapsed():
    c = TCPConversation(C, 50012, S, 21).handshake()
    c.server(b"220 hi\r\n")
    for _ in range(3):
        c.client(b"USER brute\r\nPASS Same-Fake\r\n").server(b"530 Login incorrect.\r\n")
    c.close()
    assert len(results(analyze(c.frames, enrichers=[]))) == 3


# --- --mask must cover secrets embedded in free text -------------------------------------


def test_mask_redacts_post_bodies_urls_and_extras():
    c = TCPConversation(C, 50013, S, 80).handshake()
    body = b'{"user": {"email": "m@example.com", "password": "Json-Mask-Fake"}}'
    c.client(b"POST /api?api_key=Query-Mask-Fake HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
             b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)  # fmt: skip
    form = b"username=u&password=Form-Mask-Fake"
    c.client(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form)
    c.close()
    rendered = repr([masked(f).to_dict() for f in analyze(c.frames, enrichers=[])])
    for secret in ("Json-Mask-Fake", "Query-Mask-Fake", "Form-Mask-Fake"):
        assert secret not in rendered
    assert "m@example.com" in rendered  # non-secret fields stay readable


# --- round-2 protocol review (2026-10-08) ---------------------------------------------


def test_m4_finding_cites_the_frame_that_carried_the_bytes():
    from netcreds_ng.model import Kind
    from netcreds_ng.testing.harness import analyze
    from netcreds_ng.testing.packets import TCPConversation

    c = TCPConversation("192.0.2.10", 40000, "198.51.100.20", 21)  # no handshake: warm-up path
    c.client(b"USER bob\r\nPASS Fake-Pw-1\r\n").server(b"230 ok\r\n")
    (cred,) = [f for f in analyze(c.frames, enrichers=[]) if f.kind is Kind.CREDENTIAL]
    assert cred.frame == 1 and cred.timestamp == c.frames[0].timestamp


class _Raiser:
    """Protocol plugin that raises on any client data (in whichever orientation it is offered)."""

    @staticmethod
    def make():
        from netcreds_ng.plugins.api import Direction, ProtocolPlugin

        class Raiser(ProtocolPlugin):
            name = "raiser"

            def on_data(self, ctx, direction, data):
                if direction is Direction.CLIENT_TO_SERVER:
                    raise ValueError("boom")

        return Raiser()


def test_m3_errors_in_ambiguous_flows_are_surfaced():
    from netcreds_ng.engine.engine import Engine
    from netcreds_ng.engine.pipeline import Pipeline
    from netcreds_ng.model import RunStats
    from netcreds_ng.testing.harness import to_raw_frames
    from netcreds_ng.testing.packets import TCPConversation

    c = TCPConversation("192.0.2.10", 40000, "198.51.100.20", 41000)  # SYN-less, both ephemeral
    c.client(b"hello").server(b"world")
    stats = RunStats()
    engine = Engine([_Raiser.make()], Pipeline(stats), stats)
    engine.process(to_raw_frames(c.frames))
    engine.finish()
    assert stats.ambiguous_flows == 1
    assert stats.plugin_errors["raiser"] >= 1  # neither orientation won: reported, not swallowed


def test_m2_tls_detected_when_guessed_orientation_is_wrong(tmp_path):
    import base64

    import pytest

    pytest.importorskip("cryptography")
    from netcreds_ng.engine.engine import Engine
    from netcreds_ng.engine.pipeline import Pipeline
    from netcreds_ng.engine.tls import KeyLog, TLSDecryptor
    from netcreds_ng.model import Kind, RunStats
    from netcreds_ng.plugins.registry import load_registry
    from netcreds_ng.testing.harness import to_raw_frames
    from netcreds_ng.testing.packets import TCPConversation
    from netcreds_ng.testing.tls_lab import tls_conversation

    keylog = tmp_path / "k.log"
    basic = base64.b64encode(b"alice:Fake-Pass-1").decode()
    req = f"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {basic}\r\n\r\n".encode()
    conv = TCPConversation("192.0.2.10", 40000, "198.51.100.20", 50443)  # no SYN; guess picks the wrong client
    tls_conversation(tmp_path, [(req, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")], keylog=str(keylog), conv=conv)
    stats, found = RunStats(), []
    engine = Engine(load_registry(use_entry_points=False).select_protocols(), Pipeline(stats, listeners=[found.append]),
                    stats, tls=TLSDecryptor(KeyLog(str(keylog))))  # fmt: skip
    engine.process(to_raw_frames(conv.close().frames))
    engine.finish()
    assert stats.tls_sessions == 1 and stats.tls_decrypted == 1
    creds = [(f.username, f.secret, str(f.src)) for f in found if f.kind is Kind.CREDENTIAL]
    assert creds == [("alice", "Fake-Pass-1", "192.0.2.10:40000")]


def test_l3_on_close_finding_from_plaintext_is_not_tagged_decrypted(tmp_path):
    import pytest

    pytest.importorskip("cryptography")
    from netcreds_ng.engine.engine import Engine
    from netcreds_ng.engine.pipeline import Pipeline
    from netcreds_ng.engine.tls import KeyLog, TLSDecryptor
    from netcreds_ng.model import Kind, RunStats
    from netcreds_ng.plugins.api import Direction, ProtocolPlugin
    from netcreds_ng.testing.harness import to_raw_frames
    from netcreds_ng.testing.packets import TCPConversation
    from netcreds_ng.testing.tls_lab import tls_conversation

    class Greeter(ProtocolPlugin):
        """Reads one plaintext line, then stops; reports it when the flow closes."""

        name = "greeter"

        def on_data(self, ctx, direction, data):
            ctx.state = data
            ctx.detach()

        def on_close(self, ctx):
            if ctx.state:
                ctx.emit(Direction.SERVER_TO_CLIENT, Kind.INFO, protocol="X", value="greeting seen")

    keylog = tmp_path / "k.log"
    c = TCPConversation("192.0.2.10", 50025, "198.51.100.20", 25).handshake()
    c.server(b"220 hi\r\n").client(b"STARTTLS\r\n").server(b"220 go\r\n")
    tls_conversation(tmp_path, [(b"x", b"y")], keylog=str(keylog), conv=c)
    stats, found = RunStats(), []
    engine = Engine([Greeter()], Pipeline(stats, listeners=[found.append]), stats,
                    tls=TLSDecryptor(KeyLog(str(keylog))))  # fmt: skip
    engine.process(to_raw_frames(c.close().frames))
    engine.finish()
    (info,) = found
    assert "tls-decrypted" not in info.tags
