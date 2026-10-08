"""VNC/RFB plugin: security-type exposure and auth results (challenge/response never retained)."""

from __future__ import annotations

import struct

from netcreds_ng.model import Finding, Kind
from netcreds_ng.plugins.protocols.vnc import VNCPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation, udp_frame

CLIENT, SERVER = "192.0.2.10", "198.51.100.20"
CHALLENGE = b"0123456789abcdef"
RESPONSE = b"fedcba9876543210"
U32 = struct.Struct(">I")


def run(conv: TCPConversation) -> list[Finding]:
    return analyze(conv.frames, plugins=[VNCPlugin()], enrichers=[])


def new(port: int = 5900, sport: int = 50000) -> TCPConversation:
    return TCPConversation(CLIENT, sport, SERVER, port).handshake()


def assert_no_challenge(found: list[Finding]) -> None:
    blob = " ".join(str(f.to_dict()) for f in found)
    for secret in (CHALLENGE, RESPONSE):
        assert secret.decode() not in blob
        assert secret.hex() not in blob


def handshake_38(conv: TCPConversation, choice: int, offered: bytes, segment: int | None = None) -> None:
    conv.server(b"RFB 003.008\n", segment)
    conv.client(b"RFB 003.008\n", segment)
    conv.server(bytes([len(offered)]) + offered, segment)
    conv.client(bytes([choice]), segment)


def test_v38_vnc_auth_success() -> None:
    conv = new()
    handshake_38(conv, 2, b"\x02")
    conv.server(CHALLENGE).client(RESPONSE).server(U32.pack(0)).close()
    found = run(conv)
    assert [f.kind for f in found] == [Kind.AUTH_EVENT, Kind.AUTH_RESULT]
    ev, res = found
    assert ev.protocol == "VNC"
    assert ev.value == "VNC password authentication (DES challenge-response, unencrypted session)"
    assert ev.risk == "medium"
    assert ev.username is None and ev.secret is None
    assert ev.extra == {"version": "3.8", "security_type": "2", "security_type_name": "VNC Authentication",
                        "selected_by": "client"}  # fmt: skip
    assert (ev.src.ip, ev.dst.ip, ev.dst.port) == (CLIENT, SERVER, 5900)
    assert res.value == "VNC authentication succeeded"
    assert (res.src.ip, res.dst.ip) == (CLIENT, SERVER)
    assert_no_challenge(found)


def test_v38_vnc_auth_failure_with_reason() -> None:
    conv = new()
    handshake_38(conv, 2, b"\x01\x02")
    reason = b"Authentication failed"
    conv.server(CHALLENGE).client(RESPONSE).server(U32.pack(1) + U32.pack(len(reason)) + reason).close()
    found = run(conv)
    assert [f.kind for f in found] == [Kind.AUTH_EVENT, Kind.AUTH_RESULT]
    assert found[1].value == "VNC authentication failed"
    assert found[1].extra == {"security_type": "2", "reason": "Authentication failed"}
    assert_no_challenge(found)


def test_v38_failure_without_reason_reported_on_close() -> None:
    conv = new()
    handshake_38(conv, 2, b"\x02")
    conv.server(CHALLENGE).client(RESPONSE).server(U32.pack(1)).close()
    found = run(conv)
    assert [f.value for f in found if f.kind is Kind.AUTH_RESULT] == ["VNC authentication failed"]


def test_v33_forced_vnc_auth_and_tiny_segments() -> None:
    conv = new(sport=50001)
    conv.server(b"RFB 003.003\n", 1).client(b"RFB 003.003\n", 1)
    conv.server(U32.pack(2), 1)
    conv.server(CHALLENGE, 3).client(RESPONSE, 2).server(U32.pack(1), 1).close()
    found = run(conv)
    assert [f.kind for f in found] == [Kind.AUTH_EVENT, Kind.AUTH_RESULT]
    assert found[0].extra["version"] == "3.3"
    assert found[0].extra["selected_by"] == "server"
    assert found[1].value == "VNC authentication failed"
    assert_no_challenge(found)


def test_v33_none_auth() -> None:
    conv = new(sport=50002)
    conv.server(b"RFB 003.003\n").client(b"RFB 003.003\n").server(U32.pack(1)).close()
    found = run(conv)
    assert len(found) == 1
    f = found[0]
    assert f.kind is Kind.AUTH_EVENT
    assert f.value == "VNC session without authentication"
    assert f.risk == "high"
    assert f.tags == ["no-authentication"]


def test_v38_none_auth_with_result() -> None:
    conv = new(sport=50003)
    handshake_38(conv, 1, b"\x01", segment=2)
    conv.server(U32.pack(0)).close()
    found = run(conv)
    assert [f.kind for f in found] == [Kind.AUTH_EVENT, Kind.AUTH_RESULT]
    assert found[0].value == "VNC session without authentication"
    assert found[0].risk == "high"
    assert found[1].value == "VNC authentication succeeded"


def test_v37_none_auth_has_no_result_and_vnc_auth_works() -> None:
    conv = new(sport=50004)
    conv.server(b"RFB 003.007\n").client(b"RFB 003.007\n").server(b"\x01\x01").client(b"\x01").close()
    found = run(conv)
    assert [f.kind for f in found] == [Kind.AUTH_EVENT]
    assert found[0].extra["version"] == "3.7"
    conv = new(sport=50005)
    conv.server(b"RFB 003.007\n").client(b"RFB 003.007\n").server(b"\x01\x02").client(b"\x02")
    conv.server(CHALLENGE).client(RESPONSE).server(U32.pack(0)).close()
    found = run(conv)
    assert [f.kind for f in found] == [Kind.AUTH_EVENT, Kind.AUTH_RESULT]


def test_client_negotiates_down_server_38_client_33() -> None:
    conv = new(sport=50006)
    conv.server(b"RFB 003.008\n").client(b"RFB 003.003\n").server(U32.pack(1)).close()
    found = run(conv)
    assert found[0].extra["version"] == "3.3"


def test_other_security_types_low_risk() -> None:
    for sec_type, name in ((19, "VeNCrypt"), (18, "TLS"), (16, "Tight"), (30, "Apple Remote Desktop"), (77, "type 77")):
        conv = new(sport=50100 + sec_type)
        handshake_38(conv, sec_type, bytes([sec_type, 2]))
        conv.server(b"\x00\x01\x02\x03").close()
        found = run(conv)
        assert len(found) == 1, sec_type
        assert found[0].kind is Kind.AUTH_EVENT
        assert found[0].risk == "low"
        assert found[0].value == f"VNC security type {name}"
        assert found[0].extra["security_type"] == str(sec_type)


def test_non_standard_port() -> None:
    conv = new(port=12345, sport=50007)
    handshake_38(conv, 2, b"\x02")
    conv.server(CHALLENGE).client(RESPONSE).server(U32.pack(0)).close()
    found = run(conv)
    assert len(found) == 2
    assert found[0].dst.port == 12345
    assert "nonstandard-port" in found[0].tags


def test_non_rfb_server_detaches() -> None:
    conv = new(sport=50008)
    conv.server(b"SSH-2.0-OpenSSH_9.0\r\n").client(b"SSH-2.0-test\r\n").server(U32.pack(1)).close()
    assert run(conv) == []
    conv = new(sport=50009)
    conv.server(b"HTTP/1.1 200 OK\r\n\r\n").close()
    assert run(conv) == []


def test_udp_and_unrelated_traffic_nothing() -> None:
    frames = [udp_frame(CLIENT, 5000, SERVER, 5900, b"RFB 003.008\n")]
    assert analyze(frames, plugins=[VNCPlugin()], enrichers=[]) == []


def test_malformed_and_truncated_input() -> None:
    cases: list[list[tuple[str, bytes]]] = [
        [("s", b"RFB 003.0")],  # truncated version
        [("s", b"RFB 003.008\n"), ("c", b"RFB 003.0")],
        [("s", b"RFB 003.008\n"), ("c", b"garbage-data!")],
        [("s", b"RFB 003.008\n"), ("c", b"RFB 003.008\n"), ("s", b"\x00" + U32.pack(4) + b"nope")],
        [("s", b"RFB 003.008\n"), ("c", b"RFB 003.008\n"), ("s", b"\x02\x01\x02")],  # no client choice
        [("s", b"RFB 003.008\n"), ("c", b"RFB 003.008\n"), ("s", b"\x02\x01\x02"), ("c", b"\x09")],
        [("s", b"RFB 003.003\n"), ("c", b"RFB 003.003\n"), ("s", U32.pack(0))],
        [("s", b"RFB 003.003\n"), ("c", b"RFB 003.003\n"), ("s", b"\xff\xff\xff\xff")],
        [("s", b"RFB 003.008\n"), ("c", b"RFB 003.008\n"), ("s", b"\x01\x02"), ("c", b"\x02"), ("s", b"short")],
        [("s", b"RFB 003.003\n"), ("c", b"RFB 003.003\n"), ("s", U32.pack(2)), ("s", CHALLENGE),
         ("c", RESPONSE), ("s", U32.pack(9))],
    ]  # fmt: skip
    for i, case in enumerate(cases):
        conv = new(sport=51000 + i)
        for who, data in case:
            (conv.server if who == "s" else conv.client)(data)
        conv.close()
        found = run(conv)
        # Only a well-formed security-type announcement may yield an AUTH_EVENT; never a result or secret.
        assert all(f.kind is Kind.AUTH_EVENT for f in found), case
        assert_no_challenge(found)
    # Truncation after valid selection: event only, no result.
    conv = new(sport=52000)
    handshake_38(conv, 2, b"\x02")
    conv.server(CHALLENGE[:7]).close()
    assert [f.kind for f in run(conv)] == [Kind.AUTH_EVENT]
