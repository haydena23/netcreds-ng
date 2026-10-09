"""TACACS+ plugin tests (synthetic traffic, documentation IPs, fake values)."""

from __future__ import annotations

import random

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.tacacs import TacacsPlugin
from netcreds_ng.testing.aaa_msgs import (
    TAC_ACCT,
    TAC_AUTHEN,
    TAC_AUTHOR,
    tacacs_acct_reply,
    tacacs_acct_request,
    tacacs_authen_continue,
    tacacs_authen_reply,
    tacacs_authen_start,
    tacacs_author_request,
    tacacs_author_response,
    tacacs_packet,
)
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

PASS, FAIL, GETUSER, GETPASS = 1, 2, 4, 5


def conv(port: int = 49) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50000, "198.51.100.20", port).handshake()


def run(c: TCPConversation):
    return analyze(c.close().frames, plugins=[TacacsPlugin()], enrichers=[])


def ascii_login(c: TCPConversation, segment: int | None = None, result: int = PASS) -> TCPConversation:
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start()), segment=segment)
    c.server(tacacs_packet(TAC_AUTHEN, 2, tacacs_authen_reply(GETUSER, b"Username: ")))
    c.client(tacacs_packet(TAC_AUTHEN, 3, tacacs_authen_continue(b"alice")), segment=segment)
    c.server(tacacs_packet(TAC_AUTHEN, 4, tacacs_authen_reply(GETPASS, b"Password: ", flags=1)))
    c.client(tacacs_packet(TAC_AUTHEN, 5, tacacs_authen_continue(b"Fake-Pass-1")), segment=segment)
    c.server(tacacs_packet(TAC_AUTHEN, 6, tacacs_authen_reply(result)))
    return c


@pytest.mark.parametrize("segment", [None, 1, 5])
def test_ascii_login_credential_and_result(segment):
    cred, result = run(ascii_login(conv(), segment=segment))
    assert cred.kind is Kind.CREDENTIAL
    assert (cred.protocol, cred.plugin, cred.username, cred.secret) == ("TACACS+", "tacacs", "alice", "Fake-Pass-1")
    assert cred.risk == "high" and cred.tags == ["cleartext-password"]
    assert cred.extra == {
        "session_id": "0badf00d", "action": "login", "authen_type": "ASCII", "service": "login",
        "priv_lvl": 1, "port": "tty0", "rem_addr": "192.0.2.99",
    }  # fmt: skip
    assert (cred.src.ip, cred.dst.ip, cred.dst.port) == ("192.0.2.10", "198.51.100.20", 49)
    assert result.kind is Kind.AUTH_RESULT and result.value == "login succeeded"
    assert result.username == "alice" and result.src.ip == "192.0.2.10"


def test_ascii_login_failure():
    _, result = run(ascii_login(conv(), result=FAIL))
    assert result.value == "login failed"


def test_ascii_with_username_in_start():
    c = conv()
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(user=b"alice", service=2)))
    c.server(tacacs_packet(TAC_AUTHEN, 2, tacacs_authen_reply(GETPASS, b"Password: ", flags=1)))
    c.client(tacacs_packet(TAC_AUTHEN, 3, tacacs_authen_continue(b"Fake-Pass-1")))
    (cred,) = run(c)
    assert (cred.username, cred.secret, cred.extra["service"]) == ("alice", "Fake-Pass-1", "enable")


def test_password_without_user_is_password_kind():
    c = conv()
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(service=2)))
    c.server(tacacs_packet(TAC_AUTHEN, 2, tacacs_authen_reply(GETPASS, flags=1)))
    c.client(tacacs_packet(TAC_AUTHEN, 3, tacacs_authen_continue(b"Fake-Pass-1")))
    (pw,) = run(c)
    assert pw.kind is Kind.PASSWORD and pw.secret == "Fake-Pass-1" and pw.username is None


def test_pap_start_data_is_cleartext_password():
    c = conv()
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice", b"Fake-Pass-1", authen_type=2),
                           version=0xC1))  # fmt: skip
    c.server(tacacs_packet(TAC_AUTHEN, 2, tacacs_authen_reply(PASS), version=0xC1))
    cred, result = run(c)
    assert (cred.kind, cred.username, cred.secret) == (Kind.CREDENTIAL, "alice", "Fake-Pass-1")
    assert cred.extra["authen_type"] == "PAP"
    assert result.value == "login succeeded"


@pytest.mark.parametrize(("atype", "name"), [(3, "CHAP"), (5, "MSCHAP"), (6, "MSCHAPv2")])
def test_challenge_response_is_metadata_only(atype, name):
    c = conv()
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice", b"\x01" + b"\xee" * 32, authen_type=atype),
                           version=0xC1))  # fmt: skip
    (event,) = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.value == f"TACACS+ {name} login"
    assert event.secret is None and event.risk == "medium"
    assert "\\xee" not in repr(event.to_dict()) and "\xee" not in repr(event.to_dict())


def test_encrypted_body_reported_once_per_flow():
    c = conv()
    c.client(tacacs_packet(TAC_AUTHEN, 1, b"\xee" * 40, flags=0, session_id=0x01020304))
    c.server(tacacs_packet(TAC_AUTHEN, 2, b"\xee" * 20, flags=0, session_id=0x01020304))
    c.client(tacacs_packet(TAC_AUTHEN, 3, b"\xee" * 30, flags=0, session_id=0x01020304))
    c.client(tacacs_packet(TAC_AUTHOR, 1, b"\xee" * 30, flags=0, session_id=0x05060708))
    (event,) = run(c)
    assert event.kind is Kind.AUTH_EVENT and event.value == "TACACS+ session (encrypted body)"
    assert event.risk == "info" and event.secret is None
    assert event.extra == {"session_id": "01020304", "packet_type": "authentication", "minor_version": 0}
    assert "\\xee" not in repr(event.to_dict())


def test_authorization_and_accounting_commands():
    args = [b"service=shell", b"cmd=show", b"cmd-arg=running-config", b"cmd-arg=<cr>"]
    c = conv()
    c.client(tacacs_packet(TAC_AUTHOR, 1, tacacs_author_request(b"alice", args), session_id=11))
    c.server(tacacs_packet(TAC_AUTHOR, 2, tacacs_author_response(1), session_id=11))
    c.client(tacacs_packet(TAC_ACCT, 1, tacacs_acct_request(b"alice", [b"task_id=1", *args], flags=0x04),
                           session_id=12))  # fmt: skip
    c.server(tacacs_packet(TAC_ACCT, 2, tacacs_acct_reply(1), session_id=12))
    author, acct = run(c)
    assert author.kind is Kind.INFO and author.risk == "low" and author.username == "alice"
    assert author.value == "TACACS+ authorization: show running-config"
    assert author.extra["command"] == "show running-config" and author.extra["priv_lvl"] == 15
    assert author.extra["args"] == [a.decode() for a in args]
    assert acct.value == "TACACS+ accounting stop: show running-config"
    assert "sensitive-arguments" not in author.tags


def test_sensitive_command_arguments_tagged():
    args = [b"service=shell", b"cmd=username", b"cmd-arg=bob", b"cmd-arg=password", b"cmd-arg=Fake-Pass-1"]
    c = conv()
    c.client(tacacs_packet(TAC_AUTHOR, 1, tacacs_author_request(b"alice", args)))
    (info,) = run(c)
    assert "sensitive-arguments" in info.tags


def test_authorization_without_command_summarises_service():
    c = conv()
    c.client(tacacs_packet(TAC_AUTHOR, 1, tacacs_author_request(b"alice", [b"service=ppp", b"protocol=ip"])))
    (info,) = run(c)
    assert info.value == "TACACS+ authorization: service=ppp"


def test_nonstandard_port_tag_and_single_connect_sessions():
    c = conv(port=4949)
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice", b"Fake-Pass-1", authen_type=2),
                           flags=0x05, session_id=1))  # fmt: skip
    c.server(tacacs_packet(TAC_AUTHEN, 2, tacacs_authen_reply(FAIL), flags=0x05, session_id=1))
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice", b"Fake-Pass-2", authen_type=2),
                           flags=0x05, session_id=2))  # fmt: skip
    findings = run(c)
    assert [f.kind for f in findings] == [Kind.CREDENTIAL, Kind.AUTH_RESULT, Kind.CREDENTIAL]
    assert all("nonstandard-port" in f.tags for f in findings)


@pytest.mark.parametrize(
    "first",
    [
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        b"\x16\x03\x01\x00\x05hello",  # TLS
        tacacs_packet(TAC_AUTHEN, 2, tacacs_authen_reply(PASS)),  # server seq from the client
        tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice"), flags=0x80),  # unknown flag
        tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice"), version=0xB0),
        tacacs_packet(9, 1, tacacs_authen_start(b"alice")),
        b"\xc0\x01\x01\x01\x00\x00\x00\x01\xff\xff\xff\xff",  # absurd length
        # START whose field lengths do not match the body
        tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice", b"Fake-Pass-1", authen_type=2) + b"zz"),
        tacacs_packet(TAC_AUTHEN, 1, b"\x01\x01"),  # truncated START
    ],
)
def test_garbage_or_foreign_streams_produce_nothing(first):
    c = conv()
    c.client(first)
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice", b"Fake-Pass-1", authen_type=2),
                           session_id=99))  # fmt: skip
    assert run(c) == []


def test_truncated_packet_at_close():
    c = conv()
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice", b"Fake-Pass-1", authen_type=2))[:-4])
    assert run(c) == []


def test_continue_without_prompt_is_ignored():
    c = conv()
    c.client(tacacs_packet(TAC_AUTHEN, 1, tacacs_authen_start(b"alice")))
    c.client(tacacs_packet(TAC_AUTHEN, 3, tacacs_authen_continue(b"Fake-Pass-1")))
    assert run(c) == []


def test_random_streams_never_raise():
    rng = random.Random(49)
    for i in range(60):
        c = TCPConversation("192.0.2.10", 30000 + i, "198.51.100.20", 49).handshake()
        head = tacacs_packet(rng.choice([1, 2, 3]), 1, rng.randbytes(rng.randrange(0, 60)))
        c.client(head if i % 2 else rng.randbytes(rng.randrange(1, 80)), segment=rng.choice([None, 3]))
        c.server(rng.randbytes(rng.randrange(1, 40)))
        run(c)
