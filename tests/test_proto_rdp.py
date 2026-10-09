"""RDP negotiation plugin tests (synthetic traffic, documentation IPs, fake values)."""

from __future__ import annotations

import random

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.rdp import RDPPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation
from netcreds_ng.testing.rdp_msgs import (
    PROTOCOL_HYBRID,
    PROTOCOL_HYBRID_EX,
    PROTOCOL_RDP,
    PROTOCOL_RDSTLS,
    PROTOCOL_SSL,
    connection_confirm,
    connection_request,
    tpkt,
    x224,
)

TLS_HELLO = b"\x16\x03\x01\x00\x05" + b"\x01\x00\x00\x01\x00"


def conv(port: int = 3389) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50123, "198.51.100.20", port).handshake()


def run(c: TCPConversation):
    return analyze(c.close().frames, plugins=[RDPPlugin()], enrichers=[])


def by_kind(findings, kind):
    return [f for f in findings if f.kind is kind]


def test_cookie_username_and_nla():
    c = conv()
    c.client(connection_request(b"fakeuser", PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX))
    c.server(connection_confirm(PROTOCOL_HYBRID))
    c.client(TLS_HELLO)
    user, event = run(c)
    assert user.kind is Kind.USERNAME and user.protocol == "RDP" and user.plugin == "rdp"
    assert (user.username, user.domain, user.risk, user.tags) == ("fakeuser", None, "low", ["rdp-cookie"])
    assert user.src.ip == "192.0.2.10" and user.dst.port == 3389
    assert event.kind is Kind.AUTH_EVENT and event.username == "fakeuser"
    assert (event.risk, event.tags) == ("low", ["nla"])
    assert event.extra["requested"] == ["TLS", "CredSSP", "CredSSP-EX"]
    assert event.extra["selected"] == "CredSSP"
    assert event.src.ip == "192.0.2.10" and event.dst.ip == "198.51.100.20"
    assert event.secret is None


def test_domain_in_cookie_is_split():
    c = conv()
    c.client(connection_request(b"EXAMPLE\\fakeuser", PROTOCOL_HYBRID)).server(connection_confirm(PROTOCOL_HYBRID_EX))
    user, event = run(c)
    assert (user.domain, user.username) == ("EXAMPLE", "fakeuser")
    assert event.tags == ["nla"] and event.extra["selected"] == "CredSSP-EX"


def test_tls_without_nla_is_medium():
    c = conv()
    c.client(connection_request(None, PROTOCOL_SSL)).server(connection_confirm(PROTOCOL_SSL))
    (event,) = run(c)
    assert (event.kind, event.risk, event.username) == (Kind.AUTH_EVENT, "medium", None)
    assert "no-nla" in event.tags and "tls" in event.tags


def test_standard_rdp_security_selected_is_high():
    c = conv()
    c.client(connection_request(b"fakeuser", PROTOCOL_SSL | PROTOCOL_HYBRID)).server(connection_confirm(PROTOCOL_RDP))
    _user, event = run(c)
    assert event.risk == "high" and "no-nla" in event.tags
    assert event.extra["selected"] == "RDP"


def test_legacy_client_without_negotiation_request():
    c = conv()
    c.client(connection_request(b"olduser")).server(connection_confirm())
    user, event = run(c)
    assert user.username == "olduser"
    assert event.risk == "high" and "no-nla" in event.tags
    assert event.extra["negotiation_request"] is False and event.extra["requested"] == ["RDP"]


def test_rdstls_selected_is_low():
    c = conv()
    c.client(connection_request(None, PROTOCOL_RDSTLS | PROTOCOL_SSL)).server(connection_confirm(PROTOCOL_RDSTLS))
    (event,) = run(c)
    assert event.risk == "low" and "no-nla" not in event.tags


def test_negotiation_failure():
    c = conv()
    c.client(connection_request(b"fakeuser", PROTOCOL_SSL)).server(connection_confirm(failure=5))
    _user, event = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.risk == "info"
    assert event.tags == ["negotiation-failed"] and event.extra["failure"] == "HYBRID_REQUIRED_BY_SERVER"


def test_routing_token_is_not_a_username():
    c = conv()
    c.client(connection_request(routing_token=b"3640205228.15629.0000", protocols=PROTOCOL_HYBRID))
    c.server(connection_confirm(PROTOCOL_HYBRID))
    (event,) = run(c)
    assert event.username is None and event.extra["routing_token"] is True


def test_no_server_response_standard_only_offered():
    c = conv()
    c.client(connection_request(b"fakeuser", PROTOCOL_RDP))
    _user, event = run(c)
    assert event.risk == "low" and event.tags == ["no-nla", "no-response"]


def test_no_server_response_nla_offered_is_info():
    c = conv()
    c.client(connection_request(None, PROTOCOL_HYBRID))
    (event,) = run(c)
    assert event.risk == "info" and event.tags == ["no-response"]


@pytest.mark.parametrize("segment", [1, 3, 5])
def test_split_across_segments(segment):
    c = conv()
    c.client(connection_request(b"fakeuser", PROTOCOL_HYBRID), segment=segment)
    c.server(connection_confirm(PROTOCOL_SSL), segment=segment)
    user, event = run(c)
    assert user.username == "fakeuser" and event.risk == "medium"


def test_non_standard_port_is_detected():
    c = conv(port=13389)
    c.client(connection_request(b"fakeuser", PROTOCOL_HYBRID)).server(connection_confirm(PROTOCOL_HYBRID))
    assert len(run(c)) == 2


def test_truncated_tpkt_reports_nothing():
    c = conv()
    c.client(connection_request(b"fakeuser", PROTOCOL_HYBRID)[:9])
    assert run(c) == []


def test_bad_li_or_wrong_code_detaches():
    bad_li = bytearray(connection_request(b"fakeuser", PROTOCOL_HYBRID))
    bad_li[4] += 1
    c = conv()
    c.client(bytes(bad_li)).server(connection_confirm(PROTOCOL_HYBRID))
    assert run(c) == []
    c = conv()
    c.client(tpkt(x224(0xF0, b"Cookie: mstshash=fakeuser\r\n"))).server(connection_confirm(PROTOCOL_HYBRID))
    assert run(c) == []


def test_server_speaks_first_is_ignored():
    c = conv()
    c.server(connection_confirm(PROTOCOL_RDP)).client(connection_request(b"fakeuser", PROTOCOL_RDP))
    assert run(c) == []


def test_oversized_tpkt_length_rejected():
    c = conv()
    c.client(b"\x03\x00\xff\xff" + b"\x00" * 64)
    assert run(c) == []


def test_tls_and_random_bytes_ignored():
    rng = random.Random(3389)
    for payload in (TLS_HELLO, rng.randbytes(4096), b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"):
        c = conv()
        c.client(payload, segment=500).server(rng.randbytes(300))
        assert run(c) == []


def test_unknown_server_reply_is_ignored():
    c = conv()
    c.client(connection_request(b"fakeuser", PROTOCOL_HYBRID)).server(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    findings = run(c)
    assert [f.kind for f in findings] == [Kind.USERNAME]


def test_iso_tsap_s7comm_is_not_rdp():
    # Review M1: S7comm connection request/confirm on port 102 must not look like RDP.
    c = TCPConversation("192.0.2.10", 50000, "198.51.100.20", 102).handshake()
    c.client(bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a"))
    c.server(bytes.fromhex("0300001611d00001000c00c0010ac1020100c2020102"))
    assert run(c) == []


def test_bare_request_without_reply_off_port_is_silent_and_low_on_port():
    off = TCPConversation("192.0.2.10", 50000, "198.51.100.20", 3390).handshake()
    off.client(connection_request())
    assert run(off) == []
    on = conv()
    on.client(connection_request())
    (event,) = run(on)
    assert event.risk == "low" and "no-response" in event.tags
