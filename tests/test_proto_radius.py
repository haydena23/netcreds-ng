"""RADIUS plugin tests (synthetic traffic, documentation IPs, fake values, placeholder obfuscated fields)."""

from __future__ import annotations

import json
import random

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.radius import RadiusPlugin
from netcreds_ng.testing.aaa_msgs import (
    PLACEHOLDER,
    eap_attrs,
    eap_packet,
    radius_attr,
    radius_nas_attrs,
    radius_packet,
    radius_vsa,
)
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import udp_frame

NAS, SERVER = "192.0.2.10", "198.51.100.20"
USER = radius_attr(1, b"alice")


def req(payload: bytes, sport: int = 40000, dport: int = 1812) -> bytes:
    return udp_frame(NAS, sport, SERVER, dport, payload)


def rsp(payload: bytes, sport: int = 40000, dport: int = 1812) -> bytes:
    return udp_frame(SERVER, dport, NAS, sport, payload)


def run(frames: list[bytes]):
    return analyze(frames, plugins=[RadiusPlugin()], enrichers=[])


def assert_no_placeholder(finding) -> None:
    dumped = repr(finding.to_dict()) + json.dumps(finding.to_dict())
    for marker in ("\\xee", "\\u00ee", "\xee", "\\xaa", "\xaa", "eeee", "aaaa"):
        assert marker not in dumped


def test_pap_login_and_accept():
    frames = [
        req(radius_packet(1, 7, [USER, radius_attr(2, PLACEHOLDER), *radius_nas_attrs()])),
        rsp(radius_packet(2, 7)),
    ]
    event, result = run(frames)
    assert event.kind is Kind.AUTH_EVENT
    assert (event.protocol, event.plugin, event.username) == ("RADIUS", "radius", "alice")
    assert event.value == "RADIUS PAP login"
    assert event.risk == "medium" and event.tags == ["pap"] and event.secret is None
    assert event.extra == {
        "mechanism": "PAP", "nas_ip": "192.0.2.1", "nas_identifier": "nas-fake-1",
        "called_station_id": "00-00-5E-00-53-01:FakeSSID",
    }  # fmt: skip
    assert (event.src.ip, event.dst.ip, event.dst.port) == (NAS, SERVER, 1812)
    assert result.kind is Kind.AUTH_RESULT
    assert (result.username, result.value) == ("alice", "login succeeded")
    assert (result.src.ip, result.dst.ip) == (NAS, SERVER)  # reverse=True keeps client -> server
    assert result.extra == {"mechanism": "PAP"}
    for f in (event, result):
        assert_no_placeholder(f)


def test_reject_with_reply_message():
    frames = [
        req(radius_packet(1, 9, [USER, radius_attr(2, PLACEHOLDER)])),
        rsp(radius_packet(3, 9, [radius_attr(18, b"Authentication failed")])),
    ]
    _, result = run(frames)
    assert (result.value, result.username) == ("login failed", "alice")
    assert result.extra == {"mechanism": "PAP", "message": "Authentication failed"}


def test_chap_is_metadata_only():
    chap = radius_attr(3, b"\x01" + PLACEHOLDER)
    challenge = radius_attr(60, PLACEHOLDER)
    (event,) = run([req(radius_packet(1, 1, [USER, chap, challenge]))])
    assert event.value == "RADIUS CHAP login" and event.tags == ["chap"] and event.risk == "medium"
    assert event.extra == {"mechanism": "CHAP"}
    assert_no_placeholder(event)


def test_ms_chapv2_vendor_attribute():
    attrs = [USER, radius_vsa(311, 11, PLACEHOLDER), radius_vsa(311, 25, b"\x01\x00" + PLACEHOLDER * 3)]
    (event,) = run([req(radius_packet(1, 2, attrs))])
    assert event.value == "RADIUS MS-CHAPv2 login" and event.tags == ["ms-chapv2"]
    assert_no_placeholder(event)


def test_eap_identity_then_method_then_accept():
    ident = eap_packet(2, 1, 1, b"alice@example.test")
    method = eap_packet(2, 2, 25, b"\x00" + PLACEHOLDER)
    frames = [
        req(radius_packet(1, 10, [radius_attr(1, b"alice@example.test"), *eap_attrs(ident)])),
        rsp(radius_packet(11, 10, eap_attrs(eap_packet(1, 2, 25, b"\x20")))),
        req(radius_packet(1, 11, [radius_attr(1, b"alice@example.test"), *eap_attrs(method)])),
        rsp(radius_packet(11, 11, eap_attrs(eap_packet(1, 3, 25, PLACEHOLDER)))),
        req(radius_packet(1, 12, [radius_attr(1, b"alice@example.test"), *eap_attrs(method)], b"\xab" * 16)),
        rsp(radius_packet(2, 12)),
    ]
    user, event, result = run(frames)
    assert user.kind is Kind.USERNAME and user.username == "alice@example.test"
    assert user.value == "EAP-Response/Identity" and user.tags == ["eap-identity"]
    assert event.kind is Kind.AUTH_EVENT and event.value == "RADIUS EAP (PEAP) login"
    assert event.risk == "info" and event.tags == ["eap"]  # tunneled method
    assert result.value == "login succeeded" and result.username == "alice@example.test"
    assert result.extra == {"mechanism": "EAP (PEAP)"}


def test_eap_md5_is_medium_and_fragmented_eap_reassembled():
    eap = eap_packet(2, 5, 4, bytes([16]) + PLACEHOLDER + b"x" * 300)
    attrs = eap_attrs(eap, chunk=100)
    assert len(attrs) > 1
    (event,) = run([req(radius_packet(1, 3, [USER, *attrs]))])
    assert event.value == "RADIUS EAP (EAP-MD5) login" and event.risk == "medium"
    assert_no_placeholder(event)


def test_retransmitted_request_and_response_reported_once():
    pkt = radius_packet(1, 4, [USER, radius_attr(2, PLACEHOLDER)])
    frames = [req(pkt), req(pkt), rsp(radius_packet(3, 4)), rsp(radius_packet(3, 4))]
    kinds = [f.kind for f in run(frames)]
    assert kinds == [Kind.AUTH_EVENT, Kind.AUTH_RESULT]


def test_unknown_method_and_legacy_port():
    (event,) = run([req(radius_packet(1, 5, [USER]), dport=1645)])
    assert event.value == "RADIUS login (unknown method)" and event.risk == "info"
    assert event.dst.port == 1645


def test_accounting_start():
    attrs = [USER, radius_attr(40, (1).to_bytes(4, "big")), radius_attr(44, b"sess-1")]
    (info,) = run([req(radius_packet(4, 6, attrs), dport=1813)])
    assert info.kind is Kind.INFO and info.value == "RADIUS accounting Start" and info.username == "alice"


def test_nonstandard_port_requires_exact_length():
    pkt = radius_packet(1, 7, [USER, radius_attr(2, PLACEHOLDER)])
    (event,) = run([req(pkt, dport=31812)])
    assert "nonstandard-port" in event.tags
    assert run([req(pkt + b"\x00\x00", sport=40001, dport=31812)]) == []
    # on the standard port trailing octets are padding (RFC 2865 section 3)
    assert len(run([req(pkt + b"\x00\x00", sport=40002)])) == 1


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x01\x07\x00",  # truncated header
        radius_packet(1, 7, [USER])[:-2],  # length field larger than datagram
        radius_packet(99, 7, [USER]),  # unknown code
        radius_packet(1, 7, b"\x01\x10alice"),  # attribute overruns packet
        radius_packet(1, 7, b"\x01\x01alice"),  # attribute length < 2
        radius_packet(1, 7, [USER])[:2] + b"\x00\x13" + radius_packet(1, 7, [USER])[4:],  # length < 20
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  # DNS
    ],
)
def test_malformed_or_foreign_payloads_produce_nothing(payload):
    assert run([req(payload)]) == []


def test_detaches_after_garbage():
    frames = [req(b"not radius at all, just text"), req(radius_packet(1, 7, [USER, radius_attr(2, PLACEHOLDER)]))]
    assert run(frames) == []


def test_random_bytes_never_raise():
    rng = random.Random(1812)
    frames = []
    for i in range(300):
        size = rng.randrange(0, 120)
        data = bytearray(rng.randbytes(size))
        if size >= 4 and i % 2:
            data[0] = rng.choice([1, 2, 3, 4, 11])
            data[2:4] = size.to_bytes(2, "big")
        frames.append(req(bytes(data), sport=20000 + i))
    run(frames)  # the harness raises on any plugin error
