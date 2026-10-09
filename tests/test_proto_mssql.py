"""MSSQL (TDS) plugin tests (synthetic traffic, documentation IPs, fake values)."""

from __future__ import annotations

import json
import os

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.mssql import MSSQLPlugin, deobfuscate_password
from netcreds_ng.testing import db_msgs as m
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation


def conv(port: int = 1433) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50000, "198.51.100.20", port).handshake()


def run(c: TCPConversation):
    return analyze(c.close().frames, plugins=[MSSQLPlugin()], enrichers=[])


def prelogin_exchange(c: TCPConversation, client_enc: int, server_enc: int) -> None:
    c.client(m.tds_packets(m.TDS_PRELOGIN, m.prelogin(client_enc)))
    c.server(m.tds_packets(m.TDS_TABULAR, m.prelogin(server_enc, client=False)))


def test_obfuscation_round_trip():
    raw = m.obfuscate_password("Fake-Pass-1")
    assert raw != "Fake-Pass-1".encode("utf-16-le")
    assert deobfuscate_password(raw).decode("utf-16-le") == "Fake-Pass-1"
    # Known vector from MS-TDS: 'a' (0x61) -> 0x16 ^ 0xA5 = 0xB3
    assert m.obfuscate_password("a")[0] == 0xB3


def test_cleartext_login7_without_encryption():
    c = conv()
    prelogin_exchange(c, m.ENCRYPT_NOT_SUP, m.ENCRYPT_NOT_SUP)
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7()))
    c.server(m.tds_packets(m.TDS_TABULAR, m.login_ok_response()))
    cred, result = run(c)
    assert cred.kind is Kind.CREDENTIAL
    assert (cred.protocol, cred.plugin, cred.username, cred.secret) == ("MSSQL", "mssql", "alice", "Fake-Pass-1")
    assert cred.risk == "high" and cred.tags == ["cleartext-password"]
    assert cred.extra["database"] == "appdb" and cred.extra["app_name"] == "FakeApp"
    assert cred.extra["client_host"] == "WS1" and cred.extra["server_name"] == "db.example.test"
    assert cred.extra["server_version"] == "16.0.4100" and cred.extra["encryption"] == "none"
    assert result.kind is Kind.AUTH_RESULT and result.value == "login succeeded" and result.username == "alice"
    assert result.extra["server_program"] == "Microsoft SQL Server"
    assert result.src.port == 50000 and result.dst.port == 1433


def test_login7_without_prelogin_and_tiny_segments():
    c = conv()
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7(user="bob")), segment=7)
    c.server(m.tds_packets(m.TDS_TABULAR, m.login_ok_response()), segment=5)
    cred, result = run(c)
    assert (cred.username, cred.secret) == ("bob", "Fake-Pass-1")
    assert "encryption" not in cred.extra
    assert result.value == "login succeeded"


def test_multi_packet_login7_reassembly():
    payload = m.login7(app="A" * 300)
    wire = m.tds_packets(m.TDS_LOGIN7, payload, packet_size=128)
    assert wire.count(b"\x10\x00") >= 3  # several non-EOM packets
    c = conv()
    c.client(wire, segment=50).server(m.tds_packets(m.TDS_TABULAR, m.login_ok_response()))
    cred, _ = run(c)
    assert cred.secret == "Fake-Pass-1" and cred.extra["app_name"] == "A" * 128  # display values are capped


def test_login_failed_18456():
    c = conv()
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7(password="Wrong-Fake-2")))
    long_msg = "Login failed for user 'alice'. " + "x" * 200
    c.server(m.tds_packets(m.TDS_TABULAR, m.login_failed_response(long_msg)))
    cred, result = run(c)
    assert cred.secret == "Wrong-Fake-2"
    assert result.value == "login failed" and result.extra["error_code"] == 18456
    assert result.extra["message"].startswith("Login failed for user 'alice'.")
    assert len(result.extra["message"]) == 120


def test_other_error_is_not_a_login_failure():
    c = conv()
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7()))
    c.server(m.tds_packets(m.TDS_TABULAR, m.error_token(4060, "Cannot open database") + m.done(2)))
    (cred,) = run(c)
    assert cred.kind is Kind.CREDENTIAL


def test_empty_password_and_password_change():
    c = conv()
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7(password="", new_password="New-Fake-3")))
    cred, change = run(c)
    assert cred.secret == "" and "empty-password" in cred.tags
    assert change.secret == "New-Fake-3" and change.tags == ["cleartext-password", "password-change"]


def test_encrypted_login_full_tls_is_metadata_and_detaches():
    c = conv()
    prelogin_exchange(c, m.ENCRYPT_ON, m.ENCRYPT_ON)
    c.client(m.tds_packets(m.TDS_PRELOGIN, b"\x16\x03\x01\x00\x30" + b"\x00" * 48))
    c.server(m.tds_packets(m.TDS_PRELOGIN, b"\x16\x03\x03\x00\x30" + b"\x00" * 48))
    c.client(b"\x17\x03\x03\x00\x40" + os.urandom(64))
    (event,) = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.value == "MSSQL login (TLS)"
    assert event.risk == "info" and event.tags == ["encrypted"]
    assert event.extra == {"encryption": "full", "server_version": "16.0.4100"}
    assert event.secret is None and event.username is None


def test_login_only_encryption_then_cleartext_result():
    c = conv()
    prelogin_exchange(c, m.ENCRYPT_OFF, m.ENCRYPT_OFF)
    c.client(m.tds_packets(m.TDS_PRELOGIN, b"\x16\x03\x01\x00\x30" + b"\x00" * 48))
    c.server(m.tds_packets(m.TDS_PRELOGIN, b"\x16\x03\x03\x00\x30" + b"\x00" * 48))
    c.client(b"\x17\x03\x03\x00\x40" + b"\x99" * 64, segment=9)  # TLS-wrapped LOGIN7
    c.server(m.tds_packets(m.TDS_TABULAR, m.login_ok_response()))
    event, result = run(c)
    assert event.value == "MSSQL login (TLS, login packet only)" and event.extra["encryption"] == "login-only"
    assert result.kind is Kind.AUTH_RESULT and result.value == "login succeeded" and result.username is None


def test_tds8_strict_tls():
    hello = b"\x16\x03\x01\x00\x40" + b"\x01\x00\x00\x3c" + b"\x00" * 40 + b"\x00\x07tds/8.0" + b"\x00" * 11
    c = conv()
    c.client(hello)
    (event,) = run(c)
    assert event.value == "MSSQL login (TLS, TDS 8 strict)"


def test_windows_authentication_ntlm_metadata_only():
    c = conv()
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7(user="", password="", integrated=True, sspi=m.ntlm_negotiate())))
    c.server(m.tds_packets(m.TDS_TABULAR, m.sspi_token(b"NTLMSSP\x00\x02\x00\x00\x00" + b"\x22" * 40)))
    c.client(m.tds_packets(m.TDS_SSPI, m.ntlm_authenticate()))
    c.server(m.tds_packets(m.TDS_TABULAR, m.login_ok_response()))
    event, result = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.value == "MSSQL Windows authentication"
    assert (event.username, event.domain, event.secret) == ("alice", "EXAMPLE", None)
    assert event.extra["mechanism"] == "NTLM" and event.risk == "medium"
    dumped = json.dumps(event.to_dict()) + repr(event.to_dict())
    assert "\\u0011" not in dumped and "\\x11" not in dumped and "\\x22" not in dumped
    assert result.value == "login succeeded" and result.username == "alice"


def test_windows_authentication_kerberos_flushed_on_close():
    c = conv()
    c.client(
        m.tds_packets(
            m.TDS_LOGIN7, m.login7(user="", password="", integrated=True, sspi=b"\x60\x82\x01\x00" + b"\x33" * 32)
        )
    )
    (event,) = run(c)
    assert event.value == "MSSQL Windows authentication" and event.extra["mechanism"] == "Negotiate"
    assert event.username is None and event.risk == "low"


def test_nonstandard_port():
    c = conv(14330)
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7()))
    (cred,) = run(c)
    assert cred.tags == ["cleartext-password", "nonstandard-port"]


def test_incompatible_encryption_detaches():
    c = conv()
    prelogin_exchange(c, m.ENCRYPT_REQ, m.ENCRYPT_NOT_SUP)
    c.client(m.tds_packets(m.TDS_LOGIN7, m.login7()))
    assert run(c) == []


@pytest.mark.parametrize(
    "client_bytes, server_bytes",
    [
        (os.urandom(0) + bytes(range(256)) * 4, b""),  # random-ish bytes
        (b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"),
        (m.tds_packets(m.TDS_LOGIN7, m.login7())[:-10], b""),  # truncated LOGIN7, never completes
        (m.tds_packets(m.TDS_LOGIN7, m.login7()[:60]), b""),  # LOGIN7 too short
        (m.tds_packets(m.TDS_SQL_BATCH, "select 1".encode("utf-16-le")), b""),  # mid-session batch
        (b"\x12\x01\x00\x04\x00\x00\x01\x00", b""),  # length < 8
        (b"\x12\x01\x00\x10\x00\x00\x01\x05" + b"\x00" * 8, b""),  # window byte non-zero
        (b"\x16\x03\x01\x00\x05" + b"\x01" * 5, b""),  # TLS that is not TDS 8
    ],
)
def test_malformed_or_foreign_input_no_findings(client_bytes, server_bytes):
    c = conv()
    c.client(client_bytes)
    if server_bytes:
        c.server(server_bytes)
    assert run(c) == []


def test_login7_with_field_overrun_detaches():
    payload = bytearray(m.login7())
    payload[44:46] = (5000).to_bytes(2, "little")  # ibPassword beyond the packet
    c = conv()
    c.client(m.tds_packets(m.TDS_LOGIN7, bytes(payload)))
    assert run(c) == []


def test_server_speaking_first_detaches():
    c = conv()
    c.server(m.tds_packets(m.TDS_TABULAR, m.login_ok_response())).client(m.tds_packets(m.TDS_LOGIN7, m.login7()))
    assert run(c) == []


def test_mysql_handshake_on_port_ignored():
    c = conv()
    c.server(b"\x4a\x00\x00\x00\x0a8.0.99-fake\x00" + b"\x00" * 60)
    assert run(c) == []
