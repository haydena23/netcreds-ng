"""Oracle Net (TNS) plugin tests (synthetic traffic, documentation IPs, fake values)."""

from __future__ import annotations

import json

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.oracle import OraclePlugin, descriptor_pairs
from netcreds_ng.testing import db_msgs as m
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation


def conv(port: int = 1521) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50000, "198.51.100.20", port).handshake()


def run(c: TCPConversation):
    return analyze(c.close().frames, plugins=[OraclePlugin()], enrichers=[])


def assert_no_challenge_material(findings) -> None:
    for f in findings:
        dumped = json.dumps(f.to_dict()) + repr(f.to_dict())
        for secret in (m.PLACEHOLDER_SESSKEY, m.PLACEHOLDER_PASSWORD, m.PLACEHOLDER_VFR):
            assert secret.decode() not in dumped
        assert "AUTH_SESSKEY" not in dumped and "AUTH_PASSWORD" not in dumped


def full_login(c: TCPConversation, style: str = "thin", ok: bool = True, segment: int | None = None) -> None:
    c.client(m.tns_connect(), segment=segment).server(m.tns_accept(), segment=segment)
    c.client(m.auth_phase_one(style=style), segment=segment).server(m.auth_phase_one_response(), segment=segment)
    c.client(m.auth_phase_two(style=style), segment=segment)
    c.server(m.auth_ok_response() if ok else m.auth_failed_response(), segment=segment)


def test_descriptor_pairs():
    pairs = dict(descriptor_pairs(m.DESCRIPTOR.decode()))
    assert pairs[("DESCRIPTION", "CONNECT_DATA", "SERVICE_NAME")] == "ORCL"
    assert pairs[("DESCRIPTION", "CONNECT_DATA", "CID", "USER")] == "alice"
    assert pairs[("DESCRIPTION", "ADDRESS", "PORT")] == "1521"


@pytest.mark.parametrize("style", ["thin", "oci"])
def test_full_o5logon_login(style):
    c = conv()
    full_login(c, style=style)
    findings = run(c)
    info, event, result = findings
    assert info.kind is Kind.INFO and info.value == "Oracle TNS connect (service ORCL)" and info.risk == "low"
    assert info.extra == {
        "service_name": "ORCL",
        "program": "sqlplus",
        "client_host": "ws1",
        "os_user": "alice",
        "tns_version": 314,
    }
    assert event.kind is Kind.AUTH_EVENT and event.value == "Oracle O5LOGON login"
    assert (event.protocol, event.plugin, event.username, event.secret) == ("Oracle", "oracle", "alice", None)
    assert event.extra == {
        "service_name": "ORCL", "terminal": "pts/0", "program": "sqlplus@ws1 (TNS V1-V3)",
        "machine": "ws1.example.test", "pid": "4242", "os_user": "alice", "phase": "auth-phase-one",
    }  # fmt: skip
    assert event.risk == "medium"
    assert result.kind is Kind.AUTH_RESULT and result.value == "login succeeded" and result.username == "alice"
    assert result.src.port == 50000 and result.dst.port == 1521
    assert_no_challenge_material(findings)


def test_failed_login_ora_01017_and_tiny_segments():
    c = conv()
    full_login(c, ok=False, segment=7)
    findings = run(c)
    _, event, result = findings
    assert event.username == "alice"
    assert result.value == "login failed" and result.extra["error_code"] == "ORA-01017"
    assert result.extra["message"].startswith("ORA-01017: invalid username/password")
    assert_no_challenge_material(findings)


def test_phase_two_only_reports_user_but_no_values():
    c = conv()
    c.client(m.tns_connect()).server(m.tns_accept()).client(m.auth_phase_two()).server(m.auth_ok_response())
    findings = run(c)
    _, event, result = findings
    assert event.username == "alice" and event.extra["phase"] == "auth-phase-two"
    assert event.extra["terminal"] == "pts/0"
    assert result.value == "login succeeded"
    assert_no_challenge_material(findings)


def test_long_descriptor_in_separate_data_packet_and_large_sdu():
    desc = m.DESCRIPTOR.replace(b"(SERVICE_NAME=ORCL)", b"(SERVICE_NAME=" + b"S" * 200 + b")")
    c = conv()
    c.client(m.tns_connect(desc)).server(m.tns_accept(version=318))
    c.client(m.tns_data(m.auth_phase_one()[10:], large=True))
    findings = run(c)
    info, event = findings
    assert info.extra["service_name"] == "S" * 128 and info.value.startswith("Oracle TNS connect (service SSS")
    assert event.username == "alice"


def test_sid_and_tcps_tag_and_resend():
    desc = b"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db)(PORT=2484))(CONNECT_DATA=(SID=FAKE)(CID=(PROGRAM=app)(HOST=h)(USER=u))))"
    c = conv(2484)
    c.client(m.tns_connect(desc)).server(m.tns_packet(m.TNS_RESEND, b"")).client(m.tns_connect(desc))
    (info,) = run(c)
    assert info.value == "Oracle TNS connect (SID FAKE)" and info.tags == ["tcps", "nonstandard-port"]


def test_refuse_reports_reason():
    c = conv()
    c.client(m.tns_connect()).server(m.tns_refuse(12514))
    _, refused = run(c)
    assert refused.kind is Kind.INFO and refused.value == "Oracle TNS connect refused (ORA-12514)"
    assert refused.extra["error_code"] == 12514 and refused.extra["service_name"] == "ORCL"
    assert refused.src.port == 50000


def test_ano_encryption_negotiated():
    c = conv()
    c.client(m.tns_connect()).server(m.tns_accept())
    c.client(m.tns_data(b"\xde\xad\xbe\xef" + b"\x00" * 20)).server(m.ano_response(algorithm=17))
    c.client(m.tns_data(b"\x8f" * 100))
    _, event = run(c)
    assert event.value == "Oracle login (native network encryption)"
    assert "ano-encryption" in event.tags and "encrypted" in event.tags
    assert event.extra == {"ano_algorithm_id": 17}


def test_ano_without_encryption_continues():
    c = conv()
    c.client(m.tns_connect()).server(m.tns_accept()).server(m.ano_response(algorithm=0))
    c.client(m.auth_phase_one())
    _, event = run(c)
    assert event.username == "alice"


@pytest.mark.parametrize(
    "client_bytes, server_bytes",
    [
        (bytes(range(256)) * 4, b""),  # random-ish bytes
        (b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n"),
        (m.tns_connect()[:-20], b""),  # truncated CONNECT
        (m.tns_packet(m.TNS_CONNECT, b"\x01\x3a" + b"\x00" * 30), b""),  # bad version
        (m.tns_packet(m.TNS_CONNECT, b"\x00" * 10), b""),  # too short
        (m.tns_data(b"hello"), b""),  # DATA before CONNECT
        (m.tns_connect(b"not-a-descriptor"), b""),
        (b"\x00\x04\x00\x00\x01\x00\x00\x00", b""),  # length < 8
        (m.tns_packet(8, b"\x00" * 10), b""),  # invalid type
    ],
)
def test_malformed_or_foreign_input_no_findings(client_bytes, server_bytes):
    c = conv()
    c.client(client_bytes)
    if server_bytes:
        c.server(server_bytes)
    assert run(c) == []


def test_connect_data_overrun_detaches():
    pkt = bytearray(m.tns_connect())
    pkt[24:26] = (len(pkt) + 50 - 58).to_bytes(2, "big")  # length runs past the packet end
    c = conv()
    c.client(bytes(pkt))
    assert run(c) == []


def test_server_speaking_first_detaches():
    c = conv()
    c.server(m.tns_accept()).client(m.tns_connect())
    assert run(c) == []


def test_mssql_prelogin_on_port_ignored():
    c = conv()
    c.client(b"\x12\x01\x00\x2f\x00\x00\x01\x00" + b"\x00" * 39)
    assert run(c) == []
