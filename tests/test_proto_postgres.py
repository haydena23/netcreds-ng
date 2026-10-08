"""PostgreSQL plugin tests (synthetic traffic, documentation IPs, fake values)."""

from __future__ import annotations

import json
import struct

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.postgres import PostgresPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

DIGEST = b"md5" + b"ab" * 16  # placeholder, not a real digest
SALT = b"\x11\x22\x33\x44"
SCRAM_DATA = b"n,,n=*,r=FAKENONCE"


def startup(**params: str) -> bytes:
    params = params or {"user": "alice", "database": "appdb", "application_name": "psql"}
    body = b"".join(k.encode() + b"\x00" + v.encode() + b"\x00" for k, v in params.items()) + b"\x00"
    return struct.pack("!II", 8 + len(body), 196608) + body


def smsg(mtype: bytes, body: bytes) -> bytes:
    return mtype + struct.pack("!I", 4 + len(body)) + body


def auth(code: int, extra: bytes = b"") -> bytes:
    return smsg(b"R", struct.pack("!I", code) + extra)


def error(sqlstate: str) -> bytes:
    return smsg(b"E", b"SFATAL\x00C" + sqlstate.encode() + b"\x00Mpassword authentication failed\x00\x00")


def cmsg(body: bytes) -> bytes:
    return b"p" + struct.pack("!I", 4 + len(body)) + body


SSL_REQ = struct.pack("!II", 8, 80877103)
GSS_REQ = struct.pack("!II", 8, 80877104)


def conv(port: int = 5432) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50000, "198.51.100.20", port).handshake()


def run(c: TCPConversation):
    return analyze(c.close().frames, plugins=[PostgresPlugin()], enrichers=[])


def test_cleartext_password_credential():
    c = conv()
    c.client(startup()).server(auth(3)).client(cmsg(b"Pg-Fake-Pass\x00")).server(auth(0))
    cred, result = run(c)
    assert cred.kind is Kind.CREDENTIAL and cred.protocol == "PostgreSQL" and cred.plugin == "postgres"
    assert (cred.username, cred.secret, cred.risk) == ("alice", "Pg-Fake-Pass", "high")
    assert cred.extra == {"database": "appdb", "application_name": "psql"}
    assert cred.tags == ["cleartext-password"]
    assert result.kind is Kind.AUTH_RESULT and result.value == "login succeeded" and result.username == "alice"
    assert result.src.port == 50000 and result.dst.port == 5432


def test_md5_is_metadata_only():
    c = conv()
    c.client(startup()).server(auth(5, SALT)).client(cmsg(DIGEST + b"\x00")).server(auth(0))
    event, result = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.value == "PostgreSQL MD5 password authentication"
    assert event.secret is None and event.risk == "medium" and event.username == "alice"
    assert event.extra == {"database": "appdb", "application_name": "psql", "method": "md5"}
    dumped = repr(event.to_dict()) + json.dumps(event.to_dict())
    assert "abab" not in dumped and "md5ab" not in dumped and "\\x11" not in dumped
    assert result.value == "login succeeded"


def test_scram_is_metadata_only():
    c = conv()
    c.client(startup())
    c.server(auth(10, b"SCRAM-SHA-256\x00\x00"))
    c.client(cmsg(b"SCRAM-SHA-256\x00" + struct.pack("!i", len(SCRAM_DATA)) + SCRAM_DATA))
    c.server(auth(11, b"r=FAKESERVERNONCE,s=c2FsdA==,i=4096"))
    c.client(cmsg(b"c=biws,r=FAKESERVERNONCE,p=ZmFrZXByb29m"))
    c.server(auth(12, b"v=ZmFrZQ==")).server(auth(0))
    event, result = run(c)  # exactly one event despite two client 'p' messages
    assert event.kind is Kind.AUTH_EVENT and event.value == "PostgreSQL SCRAM authentication"
    assert event.risk == "low" and event.secret is None
    assert event.extra == {"database": "appdb", "application_name": "psql", "method": "sasl", "mechanism": "SCRAM-SHA-256"}
    dumped = repr(event.to_dict())
    for needle in ("FAKENONCE", "FAKESERVERNONCE", "ZmFrZ", "c2FsdA"):
        assert needle not in dumped
    assert result.kind is Kind.AUTH_RESULT and result.value == "login succeeded"


def test_trust_authentication():
    c = conv()
    c.client(startup(user="bob")).server(auth(0))
    (event,) = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.value == "PostgreSQL login without password (trust)"
    assert event.risk == "high" and event.tags == ["no-authentication"] and event.username == "bob"
    assert event.src.port == 50000 and event.dst.port == 5432  # server reply, attributed to the client's login


@pytest.mark.parametrize("sqlstate", ["28P01", "28000"])
def test_login_failure(sqlstate):
    c = conv()
    c.client(startup()).server(auth(5, SALT)).client(cmsg(DIGEST + b"\x00")).server(error(sqlstate))
    event, result = run(c)
    assert event.kind is Kind.AUTH_EVENT
    assert result.kind is Kind.AUTH_RESULT and result.value == "login failed"
    assert result.username == "alice" and result.extra == {"sqlstate": sqlstate}


def test_unrelated_error_not_reported():
    c = conv()
    c.client(startup()).server(error("3D000"))
    assert run(c) == []


@pytest.mark.parametrize("req", [SSL_REQ, GSS_REQ])
def test_encryption_accepted_detaches(req):
    c = conv()
    c.client(req).server(b"S")
    c.client(b"\x16\x03\x01\x00\x10" + b"\x00" * 16).server(b"\x16\x03\x03\x00\x10" + b"\x00" * 16)
    assert run(c) == []


def test_encryption_refused_then_cleartext_login():
    c = conv()
    c.client(SSL_REQ).server(b"N").client(startup()).server(auth(3)).client(cmsg(b"Pg-Fake-Pass\x00"))
    (cred,) = run(c)
    assert (cred.username, cred.secret) == ("alice", "Pg-Fake-Pass")


def test_gssenc_then_ssl_refused_both():
    c = conv()
    c.client(GSS_REQ).server(b"N").client(SSL_REQ).server(b"N").client(startup()).server(auth(3))
    c.client(cmsg(b"Pg-Fake-Pass\x00"))
    assert [f.secret for f in run(c)] == ["Pg-Fake-Pass"]


def test_tiny_segments():
    c = conv()
    c.client(startup(), segment=1).server(auth(3), segment=1).client(cmsg(b"Pg-Fake-Pass\x00"), segment=2)
    c.server(auth(0), segment=3)
    cred, result = run(c)
    assert cred.secret == "Pg-Fake-Pass" and result.value == "login succeeded"


def test_ssl_request_in_tiny_segments():
    c = conv()
    c.client(SSL_REQ, segment=1).server(b"S")
    assert run(c) == []


def test_several_messages_in_one_segment():
    c = conv()
    c.client(startup() + b"")
    c.server(auth(3) + auth(3))  # duplicate request: only one password is reported
    c.client(cmsg(b"Pg-Fake-Pass\x00")).server(auth(0) + smsg(b"Z", b"I"))
    assert [f.kind for f in run(c)] == [Kind.CREDENTIAL, Kind.AUTH_RESULT]


def test_nonstandard_port():
    c = conv(6543)
    c.client(startup()).server(auth(3)).client(cmsg(b"Pg-Fake-Pass\x00")).server(auth(0))
    cred, result = run(c)
    assert cred.tags == ["cleartext-password", "nonstandard-port"]
    assert result.tags == ["nonstandard-port"]
    assert cred.dst.port == 6543


def test_trust_on_nonstandard_port_tags():
    c = conv(6543)
    c.client(startup()).server(auth(0))
    assert run(c)[0].tags == ["no-authentication", "nonstandard-port"]


@pytest.mark.parametrize(
    "client_bytes, server_bytes",
    [
        (startup()[:-3], b""),  # truncated startup
        (struct.pack("!II", 4, 196608), b""),  # length too small
        (struct.pack("!II", 0x7FFFFFFF, 196608), b""),  # absurd length
        (struct.pack("!II", 16, 80877102) + b"\x00" * 8, b""),  # CancelRequest
        (struct.pack("!II", 8, 12345), b""),  # unknown protocol
        (startup(), auth(3)[:-2]),  # truncated server message
        (startup(), b"R" + struct.pack("!I", 2)),  # bad length
        (startup(), b"\x00\xff\xff\xff\xff"),  # garbage
        (startup(), b"Rzzzz"),  # garbage length
        (startup() + b"p" + struct.pack("!I", 3), auth(3)),  # bad client message length
    ],
)
def test_malformed_input_no_findings_no_errors(client_bytes, server_bytes):
    c = conv()
    c.client(client_bytes)
    if server_bytes:
        c.server(server_bytes)
    assert run(c) == []


def test_unterminated_cleartext_password_still_bounded():
    c = conv()
    c.client(startup()).server(auth(3)).client(cmsg(b"Pg-Fake-Pass"))
    (cred,) = run(c)
    assert cred.secret == "Pg-Fake-Pass"


def test_password_message_without_request_ignored():
    c = conv()
    c.client(startup()).client(cmsg(b"Pg-Fake-Pass\x00"))
    assert run(c) == []


def test_server_speaks_first_detaches():
    c = conv()
    c.server(auth(3)).client(startup()).client(cmsg(b"Pg-Fake-Pass\x00"))
    assert run(c) == []


def test_http_traffic_ignored():
    c = conv(80)
    c.client(b"GET /login?user=a&pass=b HTTP/1.1\r\nHost: example.test\r\n\r\n")
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    assert run(c) == []
