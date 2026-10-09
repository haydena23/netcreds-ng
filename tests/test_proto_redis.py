"""Redis plugin: AUTH (RESP and inline), HELLO AUTH, results, framing and non-matching input."""

from __future__ import annotations

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.redis import RedisPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

CLIENT, SERVER = "192.0.2.10", "198.51.100.20"
PW = "Redis-Fake-Pass"


def resp(*args: str) -> bytes:
    out = b"*%d\r\n" % len(args)
    for a in args:
        raw = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(raw), raw)
    return out


def conv(port: int = 6379) -> TCPConversation:
    return TCPConversation(CLIENT, 50000, SERVER, port).handshake()


def run(c: TCPConversation):
    return analyze(c.frames, plugins=[RedisPlugin()], enrichers=[])


def test_resp_auth_password_only_and_ok():
    c = conv()
    c.client(resp("AUTH", PW)).server(b"+OK\r\n").close()
    pw, res = run(c)
    assert (pw.protocol, pw.kind, pw.username, pw.secret, pw.risk) == ("Redis", Kind.PASSWORD, None, PW, "high")
    assert (pw.src.ip, pw.src.port, pw.dst.ip, pw.dst.port) == (CLIENT, 50000, SERVER, 6379)
    assert (res.kind, res.value) == (Kind.AUTH_RESULT, "login succeeded")
    assert (res.src.ip, res.dst.ip) == (CLIENT, SERVER)


def test_resp_auth_with_username_acl():
    c = conv()
    c.client(resp("auth", "acl-user", PW)).server(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
    cred, res = run(c)
    assert (cred.kind, cred.username, cred.secret, cred.risk) == (Kind.CREDENTIAL, "acl-user", PW, "high")
    assert (res.kind, res.username, res.value) == (Kind.AUTH_RESULT, "acl-user", "login failed")


def test_legacy_invalid_password_error():
    c = conv()
    c.client(resp("AUTH", PW)).server(b"-ERR invalid password\r\n")
    assert run(c)[-1].value == "login failed"


def test_inline_auth():
    c = conv()
    c.client(b"AUTH " + PW.encode() + b"\r\n").server(b"+OK\r\n")
    pw, res = run(c)
    assert (pw.kind, pw.secret) == (Kind.PASSWORD, PW)
    assert res.value == "login succeeded"


def test_hello_auth():
    c = conv()
    c.client(resp("HELLO", "3", "AUTH", "hello-user", PW, "SETNAME", "x")).server(b"%2\r\n$6\r\nserver\r\n")
    cred, res = run(c)
    assert (cred.kind, cred.username, cred.secret) == (Kind.CREDENTIAL, "hello-user", PW)
    assert cred.extra["command"] == "HELLO"
    assert res.value == "login succeeded"


def test_hello_without_auth_reports_nothing():
    c = conv()
    c.client(resp("HELLO", "3")).server(b"%1\r\n")
    assert run(c) == []


def test_segmented_one_byte_at_a_time():
    c = conv()
    c.client(resp("AUTH", "seg-user", PW), segment=1).server(b"+OK\r\n", segment=1)
    cred, res = run(c)
    assert (cred.username, cred.secret) == ("seg-user", PW)
    assert res.value == "login succeeded"


def test_pipelined_commands_in_one_segment():
    c = conv()
    c.client(resp("PING") + resp("AUTH", PW) + resp("SELECT", "1"))
    c.server(b"+PONG\r\n+OK\r\n+OK\r\n")
    pw, res = run(c)
    assert pw.secret == PW
    assert res.value == "login succeeded"


def test_nonstandard_port():
    c = conv(port=16379)
    c.client(resp("AUTH", PW))
    (f,) = run(c)
    assert f.dst.port == 16379 and "nonstandard-port" in f.tags


def test_truncated_and_malformed_input_is_silent():
    for bad in (
        resp("AUTH", PW)[:-6],
        b"*2\r\n$4\r\nAUTH\r\n$99\r\nshort",
        b"*x\r\n$4\r\nAUTH\r\n",
        b"*2\r\n+AUTH\r\n+pw\r\n",
        b"*1000000\r\n",
        b"AUTH\r\n",
    ):
        c = conv()
        c.client(bad)
        assert run(c) == [], bad


def test_not_redis_streams_produce_nothing():
    c = conv()
    c.client(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").server(b"HTTP/1.1 200 OK\r\n\r\n")
    assert run(c) == []
    c = conv()
    c.client(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03")
    assert run(c) == []


def test_gives_up_after_16k_without_a_command():
    c = conv()
    c.client(b"lorem ipsum dolor\r\n" * 1000)  # > 16 KiB of non-Redis text
    c.client(resp("AUTH", PW))
    assert run(c) == []


def test_auth_after_other_commands_is_still_found():
    c = conv()
    c.client(resp("PING")).server(b"+PONG\r\n").client(resp("AUTH", PW))
    (f,) = run(c)
    assert f.secret == PW


def test_resync_after_gap_finds_next_command():
    # E-5: a hole in the client stream; the plugin skips to the next RESP array.
    c = conv()
    c.client(resp("AUTH", "Fake-Pass-1"))
    c.server(b"+OK\r\n")
    c.advance(True, 25)
    c.client(b"lost-bulk-tail\r\n" + resp("AUTH", "alice", "Fake-Pass-2"))
    found = run(c)
    secrets = [f.secret for f in found if f.kind in (Kind.CREDENTIAL, Kind.PASSWORD)]
    assert secrets == ["Fake-Pass-1", "Fake-Pass-2"]
    # The reply order is unreliable after a hole, so the second AUTH gets no guessed verdict.
    assert [f.value for f in found if f.kind is Kind.AUTH_RESULT] == ["login succeeded"]
