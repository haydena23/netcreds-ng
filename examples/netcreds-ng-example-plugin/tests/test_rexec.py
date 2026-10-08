from netcreds_example import RexecPlugin

from netcreds_ng.model import Kind
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation


def test_rexec_login_and_result():
    c = TCPConversation("192.0.2.10", 1023, "198.51.100.20", 512).handshake()
    c.client(b"0\x00rexecuser\x00Rexec-Fake-Pass\x00uptime\x00", segment=4)
    c.server(b"\x00 10:00 up 1 day\n").close()
    found = analyze(c.frames, plugins=[RexecPlugin()], enrichers=[])
    cred = next(f for f in found if f.kind is Kind.CREDENTIAL)
    assert (cred.username, cred.secret, cred.extra["command"]) == ("rexecuser", "Rexec-Fake-Pass", "uptime")
    assert [f.value for f in found if f.kind is Kind.AUTH_RESULT] == ["login succeeded"]


def test_other_ports_ignored():
    c = TCPConversation("192.0.2.10", 1023, "198.51.100.20", 513).handshake()
    c.client(b"0\x00u\x00p\x00c\x00").close()
    assert analyze(c.frames, plugins=[RexecPlugin()], enrichers=[]) == []
