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
