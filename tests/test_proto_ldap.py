"""LDAP plugin: simple binds, SASL metadata, results, framing and non-matching input."""

from __future__ import annotations

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.ldap import LDAPPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation
from netcreds_ng.testing.protocols import der_int, der_octets, seq, tlv

CLIENT, SERVER = "192.0.2.10", "198.51.100.20"
STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"


def enum(v: int) -> bytes:
    return tlv(0x0A, bytes([v]))


def msg(msgid: int, op: bytes) -> bytes:
    return seq(der_int(msgid), op)


def simple_bind(msgid: int, dn: str, pw: str) -> bytes:
    return msg(msgid, tlv(0x60, der_int(3) + der_octets(dn.encode()) + tlv(0x80, pw.encode())))


def sasl_bind(msgid: int, dn: str, mech: str, cred: bytes | None = None) -> bytes:
    body = der_octets(mech.encode()) + (der_octets(cred) if cred is not None else b"")
    return msg(msgid, tlv(0x60, der_int(3) + der_octets(dn.encode()) + tlv(0xA3, body)))


def bind_response(msgid: int, code: int) -> bytes:
    return msg(msgid, tlv(0x61, enum(code) + der_octets(b"") + der_octets(b"")))


def conv(port: int = 389) -> TCPConversation:
    return TCPConversation(CLIENT, 50000, SERVER, port).handshake()


def run(c: TCPConversation):
    return analyze(c.frames, plugins=[LDAPPlugin()], enrichers=[])


DN = "cn=svc-fake,dc=example,dc=test"
PW = "Ldap-Fake-Pass"


def test_simple_bind_credential_and_success():
    c = conv()
    c.client(simple_bind(1, DN, PW)).server(bind_response(1, 0)).close()
    cred, res = run(c)
    assert (cred.protocol, cred.kind, cred.username, cred.secret, cred.risk) == ("LDAP", Kind.CREDENTIAL, DN, PW, "high")
    assert (cred.src.ip, cred.src.port, cred.dst.ip, cred.dst.port) == (CLIENT, 50000, SERVER, 389)
    assert cred.tags == []
    assert (res.kind, res.username, res.value) == (Kind.AUTH_RESULT, DN, "login succeeded")
    assert (res.src.ip, res.dst.ip, res.dst.port) == (CLIENT, SERVER, 389)


def test_invalid_credentials_result():
    c = conv()
    c.client(simple_bind(2, DN, PW)).server(bind_response(2, 49))
    res = run(c)[-1]
    assert (res.kind, res.value, res.extra["result_code"]) == (Kind.AUTH_RESULT, "login failed", 49)


def test_anonymous_bind_reports_nothing():
    c = conv()
    c.client(simple_bind(1, "", "")).server(bind_response(1, 0))
    assert run(c) == []


def test_unauthenticated_bind_is_username_only():
    c = conv()
    c.client(simple_bind(1, DN, ""))
    (f,) = run(c)
    assert (f.kind, f.username, f.secret) == (Kind.USERNAME, DN, None)
    assert "unauthenticated-bind" in f.tags


def test_sasl_bind_is_metadata_only():
    c = conv()
    c.client(sasl_bind(1, "", "GSSAPI", b"\x60\x82fake-token")).server(bind_response(1, 14))
    c.client(sasl_bind(2, "", "GSS-SPNEGO", b"")).server(bind_response(2, 0))
    ev1, ev2, res = run(c)
    assert (ev1.kind, ev1.value, ev1.risk, ev1.secret) == (Kind.AUTH_EVENT, "LDAP SASL bind (GSSAPI)", "low", None)
    assert ev1.extra == {"mechanism": "GSSAPI"}
    assert ev2.kind is Kind.AUTH_EVENT
    assert res.kind is Kind.AUTH_RESULT and res.value == "login succeeded"
    assert all("fake-token" not in repr(f) for f in (ev1, ev2, res))


def test_sasl_plain_is_cleartext_credential():
    c = conv()
    c.client(sasl_bind(1, "", "PLAIN", b"\x00plain-user\x00Plain-Fake-Pass"))
    (f,) = run(c)
    assert (f.kind, f.username, f.secret, f.risk) == (Kind.CREDENTIAL, "plain-user", "Plain-Fake-Pass", "high")


def test_segmented_one_byte_at_a_time():
    c = conv()
    c.client(simple_bind(1, DN, PW), segment=1).server(bind_response(1, 0), segment=1)
    cred, res = run(c)
    assert (cred.username, cred.secret) == (DN, PW)
    assert res.value == "login succeeded"


def test_multiple_messages_in_one_segment():
    c = conv()
    c.client(simple_bind(1, "cn=a-fake", "Pw-One") + simple_bind(2, "cn=b-fake", "Pw-Two"))
    c.server(bind_response(1, 49) + bind_response(2, 0))
    found = run(c)
    assert [(f.kind, f.username) for f in found] == [
        (Kind.CREDENTIAL, "cn=a-fake"), (Kind.CREDENTIAL, "cn=b-fake"),
        (Kind.AUTH_RESULT, "cn=a-fake"), (Kind.AUTH_RESULT, "cn=b-fake"),
    ]  # fmt: skip
    assert [f.value for f in found[2:]] == ["login failed", "login succeeded"]


def test_nonstandard_port():
    c = conv(port=10389)
    c.client(simple_bind(1, DN, PW))
    (f,) = run(c)
    assert f.dst.port == 10389 and "nonstandard-port" in f.tags


def test_large_message_before_bind_is_skipped():
    big = msg(1, tlv(0x63, der_octets(b"x" * 100_000)))
    c = conv()
    c.client(big, segment=1400).client(simple_bind(2, DN, PW))
    (f,) = run(c)
    assert f.secret == PW


def test_starttls_success_detaches():
    c = conv()
    c.client(msg(1, tlv(0x77, tlv(0x80, STARTTLS_OID))))
    c.server(msg(1, tlv(0x78, enum(0) + der_octets(b"") + der_octets(b""))))
    c.client(simple_bind(2, DN, PW))  # stands in for post-handshake bytes
    assert run(c) == []


def test_starttls_failure_keeps_watching():
    c = conv()
    c.client(msg(1, tlv(0x77, tlv(0x80, STARTTLS_OID))))
    c.server(msg(1, tlv(0x78, enum(2) + der_octets(b"") + der_octets(b""))))
    c.client(simple_bind(2, DN, PW))
    assert len(run(c)) == 1


def test_truncated_and_malformed_input_is_silent():
    c = conv()
    c.client(simple_bind(1, DN, PW)[:-5])  # truncated, never completed
    assert run(c) == []
    for bad in (
        msg(1, tlv(0x60, b"\xff\x01")),  # valid id, garbage BindRequest
        b"\x30\x80\x02\x01\x01",  # indefinite length
        b"\x30\x84\xff\xff\xff\xff\x02\x01\x01",  # absurd declared length
    ):
        c = conv()
        c.client(bad)
        assert run(c) == []


def test_not_ldap_streams_produce_nothing():
    c = conv()
    c.client(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").server(b"HTTP/1.1 200 OK\r\n\r\n")
    assert run(c) == []
    # SEQUENCE whose first element is not an INTEGER message id.
    c = conv()
    c.client(seq(der_octets(b"abc")) + simple_bind(1, DN, PW))
    assert run(c) == []
