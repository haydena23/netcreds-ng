"""MySQL / MariaDB plugin tests (synthetic traffic, documentation IPs, fake values)."""

from __future__ import annotations

import json
import struct

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.mysql import MySQLPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

SCRAMBLE = b"\x11" * 20  # placeholder for a challenge-response digest

SSL = 0x800
PROTO41 = 0x200
SECURE = 0x8000
WITH_DB = 0x8
PLUGIN_AUTH = 0x80000
LENENC = 0x200000
FULL = PROTO41 | SECURE | WITH_DB | PLUGIN_AUTH


def pkt(seq: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "little") + bytes([seq]) + payload


def server_hello(version: bytes = b"8.0.99-fake", plugin: bytes = b"caching_sha2_password") -> bytes:
    caps = FULL | LENENC
    body = b"\x0a" + version + b"\x00" + struct.pack("<I", 7) + b"\x22" * 8 + b"\x00"
    body += struct.pack("<H", caps & 0xFFFF) + b"\x2d" + struct.pack("<H", 2) + struct.pack("<H", caps >> 16)
    body += bytes([21]) + b"\x00" * 10 + b"\x33" * 12 + b"\x00" + plugin + b"\x00"
    return pkt(0, body)


def response(caps: int, user: bytes, auth: bytes, db: bytes | None = b"appdb", plugin: bytes | None = b"mysql_native_password") -> bytes:
    body = struct.pack("<IIB", caps, 1 << 24, 0x2D) + b"\x00" * 23 + user + b"\x00"
    if caps & LENENC:
        body += bytes([len(auth)]) + auth
    elif caps & SECURE:
        body += bytes([len(auth)]) + auth
    else:
        body += auth + b"\x00"
    if caps & WITH_DB and db is not None:
        body += db + b"\x00"
    if caps & PLUGIN_AUTH and plugin is not None:
        body += plugin + b"\x00"
    return pkt(1, body)


OK = pkt(2, b"\x00\x00\x00\x02\x00\x00\x00")
ERR = pkt(2, b"\xff" + struct.pack("<H", 1045) + b"#28000Access denied for user")


def conv(port: int = 3306) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50000, "198.51.100.20", port).handshake()


def run(c: TCPConversation):
    return analyze(c.close().frames, plugins=[MySQLPlugin()], enrichers=[])


def assert_no_digest(finding) -> None:
    dumped = repr(finding.to_dict()) + json.dumps(finding.to_dict())
    assert "\\x11" not in dumped and "\\u0011" not in dumped and "\x11" not in dumped
    assert "\\x33" not in dumped and "\\x22" not in dumped


def test_native_password_is_metadata_only():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    event, result = run(c)
    assert event.kind is Kind.AUTH_EVENT
    assert (event.protocol, event.plugin, event.username) == ("MySQL", "mysql", "alice")
    assert event.value == "MySQL login (mysql_native_password)"
    assert event.secret is None and event.risk == "medium" and event.tags == []
    assert event.extra == {"plugin": "mysql_native_password", "database": "appdb", "server_version": "8.0.99-fake"}
    assert event.dst.port == 3306
    assert_no_digest(event)
    assert result.kind is Kind.AUTH_RESULT and result.value == "login succeeded" and result.username == "alice"
    assert result.src.port == 50000 and result.dst.port == 3306  # reverse=True: attributed to the client's login


def test_caching_sha2_lenenc_and_more_data_ignored():
    c = conv()
    caps = FULL | LENENC
    c.server(server_hello()).client(response(caps, b"bob", SCRAMBLE, plugin=b"caching_sha2_password"))
    c.server(pkt(2, b"\x01\x03")).server(pkt(3, b"\x00\x00\x00\x02\x00\x00\x00"))
    event, result = run(c)
    assert event.value == "MySQL login (caching_sha2_password)" and event.secret is None
    assert event.extra["plugin"] == "caching_sha2_password"
    assert_no_digest(event)
    assert result.value == "login succeeded"


def test_no_plugin_auth_defaults_to_native_and_no_db():
    caps = PROTO41 | SECURE
    c = conv()
    c.server(server_hello()).client(response(caps, b"carol", SCRAMBLE)).server(OK)
    event = run(c)[0]
    assert event.value == "MySQL login (mysql_native_password)"
    assert "database" not in event.extra


def test_empty_auth_response_flagged_high():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"root", b"")).server(OK)
    event = run(c)[0]
    assert event.kind is Kind.AUTH_EVENT and event.risk == "high" and event.tags == ["empty-password"]


def test_clear_password_in_handshake_response():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"dave", b"My-Fake-Pass\x00", plugin=b"mysql_clear_password")).server(OK)
    cred, result = run(c)
    assert cred.kind is Kind.CREDENTIAL
    assert (cred.username, cred.secret, cred.risk) == ("dave", "My-Fake-Pass", "high")
    assert cred.tags == ["cleartext-password"]
    assert cred.extra["plugin"] == "mysql_clear_password" and cred.extra["database"] == "appdb"
    assert result.value == "login succeeded"


def test_auth_switch_to_clear_password():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"erin", SCRAMBLE))
    c.server(pkt(2, b"\xfemysql_clear_password\x00")).client(pkt(3, b"Fake-Switch-Pw\x00")).server(pkt(4, b"\x00\x00\x00\x02\x00\x00\x00"))
    event, cred, result = run(c)
    assert event.kind is Kind.AUTH_EVENT
    assert cred.kind is Kind.CREDENTIAL and (cred.username, cred.secret) == ("erin", "Fake-Switch-Pw")
    assert cred.risk == "high" and cred.extra["plugin"] == "mysql_clear_password"
    assert result.kind is Kind.AUTH_RESULT


def test_auth_switch_to_other_plugin_is_metadata():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"erin", SCRAMBLE))
    c.server(pkt(2, b"\xfesha256_password\x00" + b"\x44" * 20)).client(pkt(3, b"\x55" * 32)).server(OK)
    event, switched, result = run(c)
    assert switched.kind is Kind.AUTH_EVENT and switched.value == "MySQL login (sha256_password)"
    assert switched.secret is None
    for f in (event, switched, result):
        assert "\\x44" not in repr(f.to_dict()) and "\\x55" not in repr(f.to_dict())


def test_access_denied_error():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"mallory", SCRAMBLE)).server(ERR)
    _, result = run(c)
    assert result.kind is Kind.AUTH_RESULT and result.value == "login failed" and result.username == "mallory"
    assert result.extra == {"error_code": 1045, "message": "Access denied for user"}


def test_pre41_response_is_not_reported_as_cleartext():
    body = struct.pack("<H", 0x0001) + b"\x00\x00\x01" + b"frank\x00" + b"\x66" * 8 + b"\x00"
    c = conv()
    c.server(server_hello()).client(pkt(1, body)).server(OK)
    event, _ = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.username == "frank" and event.secret is None
    assert event.value == "MySQL login (pre-4.1 authentication)"


def test_ssl_request_detaches():
    ssl_req = pkt(1, struct.pack("<IIB", FULL | SSL, 1 << 24, 0x2D) + b"\x00" * 23)
    assert len(ssl_req) == 36
    c = conv()
    c.server(server_hello()).client(ssl_req).client(b"\x16\x03\x01\x00\x20" + b"\x00" * 32).server(b"\x16\x03\x03" + b"\x00" * 40)
    assert run(c) == []


def test_tiny_segments():
    c = conv()
    c.server(server_hello(), segment=3).client(response(FULL, b"gina", b"Fake\x00", plugin=b"mysql_clear_password"), segment=1)
    c.server(OK, segment=2)
    cred, result = run(c)
    assert (cred.username, cred.secret) == ("gina", "Fake")
    assert result.value == "login succeeded"


def test_several_packets_in_one_segment():
    c = conv()
    c.server(server_hello() + b"")  # one segment
    c.client(response(FULL, b"hank", SCRAMBLE)).server(OK)
    assert [f.kind for f in run(c)] == [Kind.AUTH_EVENT, Kind.AUTH_RESULT]


def test_nonstandard_port():
    c = conv(33060)
    c.server(server_hello()).client(response(FULL, b"ivy", b"Fake\x00", plugin=b"mysql_clear_password")).server(OK)
    cred, result = run(c)
    assert cred.tags == ["cleartext-password", "nonstandard-port"]
    assert result.tags == ["nonstandard-port"]
    assert cred.dst.port == 33060


@pytest.mark.parametrize(
    "server_bytes, client_bytes",
    [
        (server_hello()[:-9], b""),  # truncated handshake, never completes
        (server_hello(), response(FULL, b"jim", b"x")[:-6]),  # truncated response, never completes
        (server_hello(), pkt(1, b"\x01\x02")),  # too short response
        (server_hello(), pkt(1, struct.pack("<IIB", FULL, 0, 0) + b"\x00" * 23 + b"nouser")),  # no NUL
        (server_hello(), pkt(1, struct.pack("<IIB", FULL | LENENC, 0, 0) + b"\x00" * 23 + b"u\x00\xfc\xff")),
        (server_hello(), pkt(1, struct.pack("<IIB", FULL, 0, 0) + b"\x00" * 23 + b"u\x00\x40abc")),  # auth len overrun
        (b"\x00\x00\x00\x00", b"\xff\xff\xff\x01junk"),  # zero length, oversize length
        (pkt(0, b"\x0a" + b"\x01\x02"), b""),  # bad version string
        (pkt(0, b"\x0a8.0\x00\x01"), b""),  # short handshake body
    ],
)
def test_malformed_input_no_findings_no_errors(server_bytes, client_bytes):
    c = conv()
    c.server(server_bytes)
    if client_bytes:
        c.client(client_bytes)
    assert run(c) == []


def test_non_handshake_server_packet_detaches():
    c = conv()
    c.server(pkt(0, b"\xff" + struct.pack("<H", 1129) + b"#HY000Host blocked")).client(response(FULL, b"kim", b"x\x00", plugin=b"mysql_clear_password"))
    assert run(c) == []


def test_http_traffic_ignored():
    c = conv(80)
    c.client(b"GET /login?user=a&pass=b HTTP/1.1\r\nHost: example.test\r\n\r\n")
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    assert run(c) == []


def test_client_before_server_handshake_detaches():
    c = conv()
    c.client(response(FULL, b"lee", b"x\x00", plugin=b"mysql_clear_password")).server(server_hello())
    assert run(c) == []


# --- COM_CHANGE_USER (found in real captures: zeek mysql/change-user-*.pcap) ---------------


def change_user(user: bytes, auth: bytes, db: bytes = b"appdb", plugin: bytes = b"mysql_native_password") -> bytes:
    body = b"\x11" + user + b"\x00" + bytes([len(auth)]) + auth + db + b"\x00" + struct.pack("<H", 0x2D) + plugin + b"\x00"
    return pkt(0, body)


QUERY = pkt(0, b"\x03SELECT 1")
RESULT = pkt(1, b"\x01") + pkt(2, b"\x03def\x00\x00\x00\x011\x00\x0c\x3f\x00\x01\x00\x00\x00\x08\x81\x00\x00\x00\x00") + pkt(3, b"\x011")


def test_change_user_after_login_is_reported():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    c.client(QUERY).server(RESULT)
    c.client(change_user(b"bob", SCRAMBLE)).server(pkt(1, b"\x00\x00\x00\x02\x00\x00\x00"))
    first, first_ok, event, result = run(c)
    assert (first.username, first_ok.value) == ("alice", "login succeeded")
    assert event.kind is Kind.AUTH_EVENT and event.username == "bob"
    assert event.value == "MySQL change user (mysql_native_password)"
    assert event.tags == ["change-user"] and event.extra["database"] == "appdb"
    assert result.kind is Kind.AUTH_RESULT and (result.username, result.value) == ("bob", "login succeeded")
    assert_no_digest(event)


def test_change_user_failure_and_empty_password():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    c.client(change_user(b"root2", b"")).server(pkt(1, ERR[4:]))
    _, _, event, result = run(c)
    assert (event.username, event.risk, event.tags) == ("root2", "high", ["empty-password", "change-user"])
    assert (result.username, result.value) == ("root2", "login failed")


def test_change_user_switch_to_clear_password():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    c.client(change_user(b"carol", SCRAMBLE)).server(pkt(1, b"\xfemysql_clear_password\x00"))
    c.client(pkt(2, b"Fake-Change-Pw\x00")).server(pkt(3, b"\x00\x00\x00\x02\x00\x00\x00"))
    findings = run(c)
    cred = next(f for f in findings if f.kind is Kind.CREDENTIAL)
    assert (cred.username, cred.secret) == ("carol", "Fake-Change-Pw")


def test_load_data_contents_starting_with_0x11_are_not_a_change_user():
    # Protocol review F1: LOAD DATA LOCAL file contents are client packets with sequence id >= 2.
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    c.client(pkt(0, b"\x03LOAD DATA LOCAL INFILE 'x' INTO TABLE t")).server(pkt(1, b"\xfbx"))
    c.client(pkt(2, b"\x11eve\x00\x04abcdappdb\x00")).client(pkt(3, b""))
    c.server(pkt(4, b"\x00\x01\x00\x02\x00\x00\x00"))
    assert [f.username for f in run(c)] == ["alice", "alice"]


def test_compressed_protocol_stops_after_login():
    # Protocol review F2: CLIENT_COMPRESS changes the framing after the login.
    c = conv()
    c.server(server_hello()).client(response(FULL | 0x20, b"alice", SCRAMBLE)).server(OK)
    c.client(change_user(b"bob", SCRAMBLE))
    assert [f.username for f in run(c)] == ["alice", "alice"]


def test_change_user_without_plugin_name_is_never_cleartext():
    # Protocol review F4: inherit the login's plugin for the label, but never report the bytes as a password.
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", b"Fake-Login-Pw\x00", plugin=b"mysql_clear_password"))
    c.server(OK)
    body = b"\x11" + b"bob\x00" + bytes([len(SCRAMBLE)]) + SCRAMBLE + b"appdb\x00"
    c.client(pkt(0, body))
    findings = run(c)
    assert [f.kind for f in findings if f.username == "bob"] == [Kind.AUTH_EVENT]
    assert all(f.secret is None for f in findings if f.username == "bob")


def test_large_query_does_not_stop_change_user_detection():
    # Protocol review F3: packets over 64 KiB in the command phase are skipped, not a reason to stop.
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    c.client(pkt(0, b"\x03INSERT INTO t VALUES ('" + b"A" * 70_000 + b"')"), segment=1400)
    c.server(OK.replace(b"\x02", b"\x01", 1))
    c.client(change_user(b"bob", SCRAMBLE)).server(pkt(1, b"\x00\x00\x00\x02\x00\x00\x00"))
    assert [f.username for f in run(c)] == ["alice", "alice", "bob", "bob"]


def test_lost_change_user_reply_recovers_on_next_command():
    # Protocol review F5: without the server's reply, the next command (sequence id 0) resumes the command phase.
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    c.client(change_user(b"bob", SCRAMBLE))  # reply not captured
    c.client(QUERY).server(pkt(1, b"\x00" + b"\x00" * 6))  # OK to the query: not a login result
    c.client(change_user(b"carol", SCRAMBLE)).server(pkt(1, b"\x00\x00\x00\x02\x00\x00\x00"))
    assert [(f.kind.value, f.username) for f in run(c)][2:] == [
        ("auth_event", "bob"), ("auth_event", "carol"), ("auth_result", "carol")]


def test_queries_after_login_are_not_reported():
    c = conv()
    c.server(server_hello()).client(response(FULL, b"alice", SCRAMBLE)).server(OK)
    for _ in range(3):
        c.client(QUERY).server(RESULT)
    assert len(run(c)) == 2
