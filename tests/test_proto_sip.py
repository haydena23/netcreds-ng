"""SIP plugin: Digest metadata (never nonce/response), Basic credentials, auth results."""

from __future__ import annotations

import base64

from netcreds_ng.model import Finding, Kind
from netcreds_ng.plugins.protocols.sip import SIPPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation, udp_frame

CLIENT, SERVER = "192.0.2.10", "198.51.100.20"
NONCE = "0123456789abcdef"
RESPONSE = "fedcba9876543210fedcba9876543210"
CNONCE = "c0ffee00c0ffee00"


def sip_msg(start: str, headers: list[str], body: str = "") -> bytes:
    head = "\r\n".join([start, *headers, f"Content-Length: {len(body)}", "", ""])
    return (head + body).encode()


def register(cseq: int = 2, call_id: str = "call-1@192.0.2.10", user: str = "alice", auth: str | None = None) -> bytes:
    if auth is None:
        auth = (
            f'Digest username="{user}", realm="example.com", nonce="{NONCE}", uri="sip:example.com", '
            f'response="{RESPONSE}", cnonce="{CNONCE}", nc=00000001, qop=auth, algorithm=MD5'
        )
    return sip_msg(
        "REGISTER sip:example.com SIP/2.0",
        [
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1",
            f"From: <sip:{user}@example.com>;tag=abc",
            f"To: <sip:{user}@example.com>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} REGISTER",
            "User-Agent: FakePhone/1.0",
            f"Authorization: {auth}",
        ],
    )


def reply(code: int, text: str, cseq: int = 2, call_id: str = "call-1@192.0.2.10", method: str = "REGISTER") -> bytes:
    return sip_msg(
        f"SIP/2.0 {code} {text}",
        ["From: <sip:alice@example.com>;tag=abc", "To: <sip:alice@example.com>", f"Call-ID: {call_id}",
         f"CSeq: {cseq} {method}"],
    )  # fmt: skip


def run_udp(*msgs: tuple[bool, bytes], sport: int = 5060, dport: int = 5060) -> list[Finding]:
    frames = []
    for from_client, payload in msgs:
        if from_client:
            frames.append(udp_frame(CLIENT, sport, SERVER, dport, payload))
        else:
            frames.append(udp_frame(SERVER, dport, CLIENT, sport, payload))
    return analyze(frames, plugins=[SIPPlugin()], enrichers=[])


def run_tcp(conv: TCPConversation) -> list[Finding]:
    return analyze(conv.frames, plugins=[SIPPlugin()], enrichers=[])


def assert_no_secrets(findings: list[Finding]) -> None:
    blob = " ".join(str(f.to_dict()) for f in findings)
    for secret in (NONCE, RESPONSE, CNONCE):
        assert secret not in blob


def test_udp_digest_register_is_metadata_only() -> None:
    found = run_udp((True, register()))
    assert len(found) == 1
    f = found[0]
    assert f.kind is Kind.AUTH_EVENT
    assert f.protocol == "SIP"
    assert f.username == "alice"
    assert f.secret is None
    assert f.value == "SIP Digest authentication (REGISTER)"
    assert f.risk == "medium"
    assert f.extra == {
        "method": "REGISTER", "from_user": "alice", "to_user": "alice", "user_agent": "FakePhone/1.0",
        "realm": "example.com", "uri": "sip:example.com", "algorithm": "MD5",
    }  # fmt: skip
    assert (f.src.ip, f.dst.ip, f.dst.port) == (CLIENT, SERVER, 5060)
    assert "nonstandard-port" not in f.tags
    assert_no_secrets(found)


def test_udp_result_success_and_refresh_dedup() -> None:
    found = run_udp(
        (True, sip_msg("REGISTER sip:example.com SIP/2.0",
                       ["From: <sip:alice@example.com>", "Call-ID: call-1@192.0.2.10", "CSeq: 1 REGISTER"])),
        (False, reply(401, "Unauthorized", cseq=1)),
        (True, register(cseq=2)),
        (False, reply(100, "Trying")),
        (False, reply(200, "OK", cseq=2)),
        (True, register(cseq=3)),  # refresh
        (False, reply(200, "OK", cseq=3)),
    )  # fmt: skip
    events = [f for f in found if f.kind is Kind.AUTH_EVENT]
    results = [f for f in found if f.kind is Kind.AUTH_RESULT]
    assert len(events) == 1
    assert len(results) >= 1
    r = results[0]
    assert r.value == "SIP authentication succeeded"
    assert r.username == "alice"
    assert r.extra == {"status": "200", "realm": "example.com"}
    assert (r.src.ip, r.dst.ip) == (CLIENT, SERVER)  # reported against the client
    assert_no_secrets(found)


def test_udp_result_failure_403() -> None:
    found = run_udp((True, register(cseq=5)), (False, reply(403, "Forbidden", cseq=5)))
    results = [f for f in found if f.kind is Kind.AUTH_RESULT]
    assert len(results) == 1
    assert results[0].value == "SIP authentication failed"
    assert results[0].extra["status"] == "403"


def test_challenge_401_407_and_unmatched_responses_emit_nothing() -> None:
    found = run_udp(
        (False, reply(401, "Unauthorized", cseq=9)),
        (False, reply(407, "Proxy Authentication Required", cseq=10)),
        (False, reply(200, "OK", cseq=11)),
    )  # fmt: skip
    assert found == []


def test_result_requires_matching_call_id_and_cseq() -> None:
    found = run_udp(
        (True, register(cseq=2)),
        (False, reply(200, "OK", cseq=3)),
        (False, reply(200, "OK", cseq=2, call_id="other@host")),
    )  # fmt: skip
    assert [f.kind for f in found] == [Kind.AUTH_EVENT]


def test_401_response_to_credentialed_request_is_not_reported_as_result() -> None:
    found = run_udp((True, register(cseq=2)), (False, reply(401, "Unauthorized", cseq=2)))
    assert [f.kind for f in found] == [Kind.AUTH_EVENT]


def test_proxy_authorization_digest_invite() -> None:
    msg = sip_msg(
        "INVITE sip:bob@example.com SIP/2.0",
        ["From: \"Alice\" <sip:alice@example.com>;tag=1", "To: <sip:bob@example.com>", "Call-ID: inv-1",
         "CSeq: 1 INVITE",
         f'Proxy-Authorization: Digest username="alice", realm="proxy.example.com", nonce="{NONCE}", '
         f'uri="sip:bob@example.com", response="{RESPONSE}", algorithm=SHA-256'],
    )  # fmt: skip
    found = run_udp((True, msg))
    assert len(found) == 1
    assert found[0].value == "SIP Digest authentication (INVITE)"
    assert found[0].extra["realm"] == "proxy.example.com"
    assert found[0].extra["algorithm"] == "SHA-256"
    assert found[0].extra["to_user"] == "bob"
    assert_no_secrets(found)


def test_basic_authorization_is_cleartext_credential() -> None:
    token = base64.b64encode(b"alice:Sup3r-Fake-Pass").decode()
    found = run_udp((True, register(auth=f"Basic {token}")))
    assert len(found) == 1
    f = found[0]
    assert f.kind is Kind.CREDENTIAL
    assert (f.username, f.secret, f.risk) == ("alice", "Sup3r-Fake-Pass", "high")
    assert f.extra["method"] == "REGISTER"


def test_basic_with_garbage_base64_ignored() -> None:
    assert run_udp((True, register(auth="Basic !!!!"))) == []
    assert run_udp((True, register(auth="Basic " + base64.b64encode(b"nocolon").decode()))) == []


def test_distinct_users_not_deduplicated_and_compact_headers() -> None:
    found = run_udp((True, register(user="alice")), (True, register(user="bob", call_id="c2", cseq=1)))
    assert sorted(f.username or "" for f in found) == ["alice", "bob"]
    msg = (
        b"REGISTER sip:example.com SIP/2.0\r\nf: <sip:carol@example.com>\r\ni: compact-1\r\n"
        b'CSeq: 1 REGISTER\r\nAuthorization: Digest username="carol", realm="example.com", '
        b'uri="sip:example.com", response="' + RESPONSE.encode() + b'"\r\nl: 0\r\n\r\n'
    )
    f = run_udp((True, msg))[0]
    assert f.username == "carol"
    assert f.extra["from_user"] == "carol"


def test_nonstandard_port_udp() -> None:
    found = run_udp((True, register()), sport=40000, dport=15060)
    assert len(found) == 1
    assert found[0].dst.port == 15060
    assert "nonstandard-port" in found[0].tags


def test_tcp_digest_and_results_with_tiny_segments() -> None:
    conv = TCPConversation(CLIENT, 50000, SERVER, 5060).handshake()
    conv.client(register(cseq=2), segment=7)
    conv.server(reply(200, "OK", cseq=2), segment=5)
    conv.client(register(cseq=3))  # second message in same stream
    conv.server(reply(403, "Forbidden", cseq=3))
    conv.close()
    found = run_tcp(conv)
    assert [f.kind for f in found if f.kind is Kind.AUTH_EVENT] == [Kind.AUTH_EVENT]
    values = [f.value for f in found if f.kind is Kind.AUTH_RESULT]
    assert values == ["SIP authentication succeeded", "SIP authentication failed"]
    assert_no_secrets(found)


def test_tcp_content_length_body_framing_and_two_messages_in_one_segment() -> None:
    body = "v=0\r\ns=fake\r\n"
    first = sip_msg(
        "MESSAGE sip:bob@example.com SIP/2.0",
        ["From: <sip:alice@example.com>", "Call-ID: m1", "CSeq: 1 MESSAGE", "Content-Type: text/plain"],
        body,
    )
    conv = TCPConversation(CLIENT, 50001, SERVER, 5060).handshake()
    conv.client(first + register(cseq=2, user="dave"))
    conv.close()
    found = run_tcp(conv)
    assert [f.username for f in found] == ["dave"]


def test_tcp_nonstandard_port_and_keepalive_crlf() -> None:
    conv = TCPConversation(CLIENT, 50002, SERVER, 5555).handshake()
    conv.client(b"\r\n\r\n" + register())
    conv.close()
    found = run_tcp(conv)
    assert len(found) == 1
    assert "nonstandard-port" in found[0].tags


def test_unrelated_traffic_emits_nothing() -> None:
    conv = TCPConversation(CLIENT, 50003, SERVER, 5060).handshake()
    conv.client(b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n")
    conv.close()
    assert run_tcp(conv) == []
    assert run_udp((True, b"\x00\x01binary-noise"), (True, b"hello world")) == []


def test_malformed_and_truncated_input_no_findings_no_errors() -> None:
    full = register()
    cases = [
        full[:40],  # truncated in request line
        full[: full.index(b"Authorization") + 20],  # truncated mid-header, no blank line
        b"REGISTER sip:example.com SIP/2.0\r\nAuthorization: Digest\r\n\r\n",
        b"REGISTER sip:example.com SIP/2.0\r\nAuthorization: Digest username=\r\n\r\n",
        b"REGISTER sip:example.com SIP/2.0\r\nAuthorization: \xff\xfe\r\n\r\n",
        b"SIP/2.0 abc\r\n\r\n",
        b"\r\n\r\n",
        b"",
    ]
    for payload in cases:
        found = run_udp((True, payload))
        assert found == [], payload
    conv = TCPConversation(CLIENT, 50004, SERVER, 5060).handshake()
    conv.client(b"REGISTER sip:example.com SIP/2.0\r\nContent-Length: 99999999\r\n\r\n")
    conv.client(register())
    conv.close()
    assert run_tcp(conv) == []
    conv = TCPConversation(CLIENT, 50005, SERVER, 5060).handshake()
    conv.client(register()[:-30])  # truncated before blank line completes
    conv.close()
    assert run_tcp(conv) == []


def test_tcp_resync_after_gap_finds_next_message() -> None:
    # E-5: a long-lived SIP-over-TCP connection used to stop at the first capture gap.
    conv = TCPConversation(CLIENT, 50004, SERVER, 5060).handshake()
    conv.client(register(cseq=2)).server(reply(200, "OK", cseq=2))
    lost = register(cseq=3, user="bob")
    conv.client(lost[:40]).advance(True, 60).client(lost[100:])  # tail of a message whose head was lost
    conv.client(register(cseq=4, user="carol"), segment=11)
    conv.server(reply(100, "Trying", cseq=4)[:30]).advance(False, 25)
    conv.server(b"partial header line\r\n" + reply(403, "Forbidden", cseq=4))
    conv.close()
    found = run_tcp(conv)
    assert [(f.kind, f.username) for f in found if f.kind is Kind.AUTH_EVENT] == [
        (Kind.AUTH_EVENT, "alice"), (Kind.AUTH_EVENT, "carol")]
    assert [(f.username, f.value) for f in found if f.kind is Kind.AUTH_RESULT] == [
        ("alice", "SIP authentication succeeded"), ("carol", "SIP authentication failed")]
    assert_no_secrets(found)


def test_tcp_gap_before_first_message_detaches() -> None:
    conv = TCPConversation(CLIENT, 50005, SERVER, 5060).handshake()
    conv.advance(True, 30).client(register()).close()
    assert run_tcp(conv) == []
