"""E-7: Telnet heuristic evidence and strict mode."""

from __future__ import annotations

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.telnet import TelnetPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

C, S = "192.0.2.10", "198.51.100.20"
IAC_DO_ECHO = b"\xff\xfd\x01"


def login(port: int, negotiate: bool = False) -> TCPConversation:
    c = TCPConversation(C, 50000, S, port).handshake()
    if negotiate:
        c.server(IAC_DO_ECHO)
    c.server(b"login: ").client(b"alice\r\n").server(b"Password: ").client(b"Fake-Pass-1\r\n")
    return c.close()


def creds(c: TCPConversation, **opts: object):
    return [f for f in analyze(c.frames, plugins=[TelnetPlugin(dict(opts))], enrichers=[]) if f.kind is Kind.CREDENTIAL]


def test_telnet_port_is_trusted():
    (f,) = creds(login(23))
    assert (f.username, f.secret, f.confidence) == ("alice", "Fake-Pass-1", 1.0)
    assert "heuristic" not in f.tags


def test_other_port_without_negotiation_is_tagged_heuristic():
    (f,) = creds(login(4000))
    assert f.secret == "Fake-Pass-1" and "heuristic" in f.tags and f.confidence < 1.0


def test_option_negotiation_is_evidence_on_any_port():
    (f,) = creds(login(4000, negotiate=True))
    assert "heuristic" not in f.tags


def test_strict_mode_ignores_bare_prompts_on_other_ports():
    assert creds(login(4000), strict=True) == []
    assert len(creds(login(4000, negotiate=True), strict=True)) == 1
    assert len(creds(login(23), strict=True)) == 1


def test_cli_strict_heuristics_flag(tmp_path, capsys):
    from netcreds_ng.cli import main
    from netcreds_ng.testing.packets import write_pcap

    pcap = tmp_path / "t.pcap"
    write_pcap(str(pcap), login(4000).frames)
    out = tmp_path / "o.jsonl"
    assert main(["-p", str(pcap), "-q", "--jsonl", str(out), "--strict-heuristics"]) == 0
    assert "Fake-Pass-1" not in out.read_text(encoding="utf-8") if out.exists() else True
    assert main(["-p", str(pcap), "-q", "--jsonl", str(out)]) == 0
    assert "Fake-Pass-1" in out.read_text(encoding="utf-8")


# --- M32: fewer false positives ------------------------------------------------------


def test_binary_reply_to_a_password_prompt_on_another_port_is_not_a_password():
    c = TCPConversation(C, 50001, S, 4000).handshake()
    c.server(b"Enter Password: ").client(b"\x16\x01\x02binary\x03payload\r\n").close()
    assert [f for f in analyze(c.frames, plugins=[TelnetPlugin()], enrichers=[]) if f.plugin == "telnet"] == []


def test_typed_password_with_spaces_and_utf8_on_another_port_is_kept():
    c = TCPConversation(C, 50002, S, 4000).handshake()
    c.server(b"login: ").client(b"alice\r\n").server(b"Password: ").client("Fake päss\tword\r\n".encode())
    (f,) = creds(c.close())
    assert (f.username, f.secret) == ("alice", "Fake päss\tword") and "heuristic" in f.tags


def test_telnet_port_keeps_control_characters_in_typed_values():
    # On a Telnet port the evidence is strong: the value is reported as typed.
    c = TCPConversation(C, 50003, S, 23).handshake()
    c.server(b"Password: ").client(b"Fake\x1b[A-Pass\r\n").close()
    (f,) = [x for x in analyze(c.frames, plugins=[TelnetPlugin()], enrichers=[]) if x.plugin == "telnet"]
    assert f.secret == "Fake\x1b[A-Pass"


def _keyvalue(payload: bytes):
    from netcreds_ng.plugins.protocols.keyvalue import KeyValuePlugin

    c = TCPConversation(C, 50010, S, 7000).handshake()
    c.client(payload).close()
    return [(f.username, f.secret) for f in analyze(c.frames, plugins=[KeyValuePlugin()], enrichers=[])]


def test_keyvalue_ignores_template_and_masked_values():
    lines = [b"user=alice password=****", b"login user=alice pass=%s", b"db user=app password=${DB_PASSWORD}",
             b"user=alice pw={{ pw }}", b"user=alice password=<password>", b"password=null", b"password=xxxxxx",
             b"password=[REDACTED]", b"user=alice password=%(password)s", b"pass=''"]  # fmt: skip
    assert _keyvalue(b"\n".join(lines) + b"\n") == []


def test_keyvalue_still_reports_real_values_next_to_placeholders():
    found = _keyvalue(b"user=alice password=**** pass=Kv-Fake-Pass\nuser=bob pwd=$ecret-Fake\n")
    assert found == [("alice", "Kv-Fake-Pass"), ("bob", "$ecret-Fake")]



def test_dropped_binary_password_forgets_the_username():
    # Review M32 LOW-1: the next password must not be paired with the earlier user name.
    c = TCPConversation(C, 50004, S, 4000).handshake()
    c.server(b"login: ").client(b"alice\r\n").server(b"Password: ").client(b"\x16\x01bin\x02\r\n")
    c.server(b"Password: ").client(b"Fake-Pass-2\r\n").close()
    found = [f for f in analyze(c.frames, plugins=[TelnetPlugin()], enrichers=[]) if f.secret]
    assert [(f.kind, f.username, f.secret) for f in found] == [(Kind.PASSWORD, None, "Fake-Pass-2")]


def test_keyvalue_keeps_real_values_that_resemble_placeholders():
    # Review M32 MED-3: "$Secret1", "$1abc" and "xx" are real values; ALL-CAPS $NAME is a variable.
    found = _keyvalue(b"user=alice password=$Secret1\nuser=bob pass=$1abc\nuser=carol pwd=xx\n"
                      b"user=dave password=$DB_PASS\n")
    assert found == [("alice", "$Secret1"), ("bob", "$1abc"), ("carol", "xx")]
