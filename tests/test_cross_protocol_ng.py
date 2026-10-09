"""Cross-protocol matrix for the protocols netcreds-ng added (no Python 2 goldens exist for them).

With every plugin enabled, each conversation must only trigger the plugins that own it,
including when the traffic is moved to a non-standard port.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from netcreds_ng.testing import aaa_msgs as aaa
from netcreds_ng.testing import db_msgs as db
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import Frame, TCPConversation, udp_frame
from netcreds_ng.testing.rdp_msgs import PROTOCOL_RDP, connection_confirm, connection_request

C, S = "192.0.2.10", "198.51.100.20"


def tcp(port: int) -> TCPConversation:
    return TCPConversation(C, 50000, S, port).handshake()


def radius(port: int = 1812) -> list[Frame | bytes]:
    req = aaa.radius_packet(1, 7, [aaa.radius_attr(1, b"alice"), aaa.radius_attr(2, b"\xee" * 16)])
    acc = aaa.radius_packet(2, 7, [])
    return [udp_frame(C, 50001, S, port, req), udp_frame(S, port, C, 50001, acc)]


def tacacs(port: int = 49) -> list[Frame | bytes]:
    c = tcp(port)
    c.client(aaa.tacacs_packet(1, 1, aaa.tacacs_authen_start(b"alice", b"Fake-Pass-1", authen_type=2), version=0xC1))
    c.server(aaa.tacacs_packet(1, 2, aaa.tacacs_authen_reply(1), version=0xC1))
    return list(c.close().frames)


def mssql(port: int = 1433) -> list[Frame | bytes]:
    c = tcp(port)
    c.client(db.tds_packets(db.TDS_PRELOGIN, db.prelogin(2)))
    c.server(db.tds_packets(db.TDS_TABULAR, db.prelogin(2, client=False)))
    c.client(db.tds_packets(db.TDS_LOGIN7, db.login7()))
    c.server(db.tds_packets(db.TDS_TABULAR, db.login_ok_response()))
    return list(c.close().frames)


def oracle(port: int = 1521) -> list[Frame | bytes]:
    c = tcp(port)
    c.client(db.tns_connect()).server(db.tns_accept())
    c.client(db.auth_phase_one()).server(db.auth_phase_one_response())
    c.client(db.auth_phase_two()).server(db.auth_ok_response())
    return list(c.close().frames)


def rdp(port: int = 3389) -> list[Frame | bytes]:
    c = tcp(port)
    c.client(connection_request(b"fakeuser", PROTOCOL_RDP)).server(connection_confirm(PROTOCOL_RDP))
    return list(c.close().frames)


def cloud_key(port: int = 8000) -> list[Frame | bytes]:
    c = tcp(port)
    c.client(b"PUT /cfg HTTP/1.1\r\nHost: cfg.example\r\nContent-Length: 40\r\n\r\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
    c.server(b"HTTP/1.1 204 No Content\r\n\r\n")
    return list(c.close().frames)


def http2(port: int = 80) -> list[Frame | bytes]:
    from netcreds_ng.testing import h2_msgs as h2

    enc, senc = h2.Encoder(), h2.Encoder()
    basic = b"Basic " + __import__("base64").b64encode(b"alice:Fake-Pass-1")
    c = tcp(port)
    req = h2.request_headers(b"GET", b"/admin", extra=[(b"authorization", basic)])
    c.client(h2.PREFACE + h2.settings() + h2.headers_frame(1, enc.encode(req), end_stream=True))
    c.server(h2.settings() + h2.headers_frame(1, senc.encode([(b":status", b"200")]), end_stream=True))
    return list(c.close().frames)


CASES: dict[str, tuple[Callable[..., list[Frame | bytes]], set[str], int]] = {
    "radius": (radius, {"radius"}, 31812),
    "tacacs": (tacacs, {"tacacs"}, 4949),
    "mssql": (mssql, {"mssql"}, 14330),
    "oracle": (oracle, {"oracle"}, 15210),
    "rdp": (rdp, {"rdp"}, 33890),
    "cloud_key": (cloud_key, {"http", "secrets"}, 8000),
    "http2": (http2, {"http2"}, 18080),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_only_owning_plugins_fire(name):
    build, owners, _ = CASES[name]
    findings = analyze(build(), enable=["all"], enrichers=[])
    assert findings, f"{name}: owning plugin reported nothing"
    assert {f.plugin for f in findings} == owners


@pytest.mark.parametrize("name", sorted(CASES))
def test_only_owning_plugins_fire_on_nonstandard_port(name):
    build, owners, port = CASES[name]
    findings = analyze(build(port), enable=["all"], enrichers=[])
    assert {f.plugin for f in findings} == owners
