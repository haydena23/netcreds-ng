"""MQTT plugin: CONNECT credentials (levels 3/4/5), CONNACK results, framing, non-matching input."""

from __future__ import annotations

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.mqtt import MQTTPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

CLIENT, SERVER = "192.0.2.10", "198.51.100.20"


def s(v: bytes) -> bytes:
    return len(v).to_bytes(2, "big") + v


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def connect(
    level: int = 4,
    cid: str = "client-fake",
    user: str | None = "mqtt-user",
    pw: str | None = "Mqtt-Fake-Pass",
    will: bool = False,
) -> bytes:
    flags = 0x02
    name = b"MQIsdp" if level == 3 else b"MQTT"
    body = s(name) + bytes([level])
    payload = s(cid.encode())
    if will:
        flags |= 0x04
        payload += (b"\x00" if level == 5 else b"") + s(b"will/topic") + s(b"bye")
    if user is not None:
        flags |= 0x80
        payload += s(user.encode())
    if pw is not None:
        flags |= 0x40
        payload += s(pw.encode())
    body += bytes([flags]) + b"\x00\x3c" + (b"\x00" if level == 5 else b"") + payload
    return b"\x10" + varint(len(body)) + body


def connack(code: int, level: int = 4) -> bytes:
    if level == 5:
        return b"\x20\x03\x00" + bytes([code]) + b"\x00"
    return b"\x20\x02\x00" + bytes([code])


def conv(port: int = 1883) -> TCPConversation:
    return TCPConversation(CLIENT, 50000, SERVER, port).handshake()


def run(c: TCPConversation):
    return analyze(c.frames, plugins=[MQTTPlugin()], enrichers=[])


@pytest.mark.parametrize("level", [3, 4, 5])
def test_connect_credential_all_levels(level):
    c = conv()
    c.client(connect(level)).server(connack(0, level)).close()
    cred, res = run(c)
    assert (cred.protocol, cred.kind, cred.username, cred.secret, cred.risk) == (
        "MQTT", Kind.CREDENTIAL, "mqtt-user", "Mqtt-Fake-Pass", "high",
    )  # fmt: skip
    assert cred.extra["client_id"] == "client-fake" and cred.extra["protocol_level"] == level
    assert (cred.src.ip, cred.src.port, cred.dst.ip, cred.dst.port) == (CLIENT, 50000, SERVER, 1883)
    assert (res.kind, res.username, res.value) == (Kind.AUTH_RESULT, "mqtt-user", "login succeeded")
    assert (res.src.ip, res.dst.ip) == (CLIENT, SERVER)


@pytest.mark.parametrize(("level", "code"), [(4, 4), (4, 5), (3, 5), (5, 0x86), (5, 0x87)])
def test_connack_failures(level, code):
    c = conv()
    c.client(connect(level)).server(connack(code, level))
    assert run(c)[-1].value == "login failed"


def test_connack_non_auth_error_is_not_a_login_verdict():
    c = conv()
    c.client(connect(4)).server(connack(3))
    assert [f.kind for f in run(c)] == [Kind.CREDENTIAL]


def test_will_message_is_skipped():
    for level in (4, 5):
        c = conv()
        c.client(connect(level, will=True))
        (f,) = run(c)
        assert (f.username, f.secret) == ("mqtt-user", "Mqtt-Fake-Pass")


def test_username_only():
    c = conv()
    c.client(connect(4, pw=None))
    (f,) = run(c)
    assert (f.kind, f.username, f.secret) == (Kind.USERNAME, "mqtt-user", None)


def test_anonymous_connect_reports_nothing():
    c = conv()
    c.client(connect(4, user=None, pw=None)).server(connack(0))
    assert run(c) == []


def test_segmentation_and_multi_byte_remaining_length():
    c = conv()
    c.client(connect(5, cid="c" * 150), segment=3).server(connack(0, 5), segment=1)
    cred, res = run(c)
    assert cred.secret == "Mqtt-Fake-Pass" and len(cred.extra["client_id"]) == 150
    assert res.value == "login succeeded"


def test_connect_followed_by_other_packets_in_same_segment():
    c = conv()
    c.client(connect(4) + b"\xc0\x00")  # + PINGREQ
    assert len(run(c)) == 1


def test_nonstandard_port():
    c = conv(port=11883)
    c.client(connect(4))
    (f,) = run(c)
    assert f.dst.port == 11883 and "nonstandard-port" in f.tags


def test_truncated_and_malformed_input_is_silent():
    c = conv()
    c.client(connect(4)[:-4])
    assert run(c) == []
    for bad in (
        b"\x10\x0c" + s(b"HTTP") + b"\x04\x02\x00\x3c\x00\x00",  # unknown protocol name
        b"\x10\x0c" + s(b"MQTT") + b"\x09\x02\x00\x3c\x00\x00",  # unsupported level
        b"\x10\xff\xff\xff\xff\x01",  # over-long remaining length
        b"\x10\x0e" + s(b"MQTT") + b"\x04\xc2\x00\x3c\x00\x02id\x00\x09ab",  # field overruns packet
    ):
        c = conv()
        c.client(bad)
        assert run(c) == []


def test_not_mqtt_streams_produce_nothing():
    c = conv()
    c.client(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").server(b"HTTP/1.1 200 OK\r\n\r\n")
    assert run(c) == []
    c = conv()
    c.server(connack(0))  # server-first: not an MQTT conversation shape
    assert run(c) == []
