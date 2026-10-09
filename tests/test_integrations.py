"""M10: CEF, syslog and chat-webhook integrations. No traffic leaves the process: sockets and
HTTP are replaced with recorders."""

from __future__ import annotations

import json
import socket

import pytest

from netcreds_ng.model import Endpoint, Finding, Kind, RunStats
from netcreds_ng.output.formats import cef_line, chat_payload, syslog_message
from netcreds_ng.plugins.api import SinkContext
from netcreds_ng.plugins.sinks import webhook as webhook_mod
from netcreds_ng.plugins.sinks.siem import CefSink, SyslogSink
from netcreds_ng.plugins.sinks.webhook import WebhookSink


def cred(risk: str = "high", secret: str = "Fake-Pass-1") -> Finding:
    return Finding(
        protocol="FTP", kind=Kind.CREDENTIAL, src=Endpoint("192.0.2.10", 40000), dst=Endpoint("198.51.100.20", 21),
        timestamp=1_700_000_000.5, frame=7, username="alice", secret=secret, risk=risk, plugin="ftp",
        tags=["cleartext", "weak|tag=x"],
    )  # fmt: skip


def test_cef_line_fields_and_escaping():
    line = cef_line(cred(secret="pa=ss\\word\nx"))
    parts = line.split("|", 7)
    assert parts[:7] == ["CEF:0", "netcreds-ng", "netcreds-ng", parts[3], "credential", "FTP credential", "9"]
    ext = parts[7]
    assert "src=192.0.2.10 spt=40000 dst=198.51.100.20 dpt=21" in ext
    assert "suser=alice" in ext and "rt=1700000000500" in ext and "cn1=7" in ext
    assert r"msg=alice:pa\=ss\\word\nx" in ext  # = \ and newline escaped in extension values
    assert r"cs1=cleartext,weak|tag\=x" in ext


def test_cef_file_sink_masks_with_option(tmp_path):
    path = tmp_path / "out.cef"
    sink = CefSink(str(path), {"mask": True})
    sink.open(SinkContext(RunStats()))
    sink.write(cred())
    sink.close(RunStats())
    text = path.read_text(encoding="utf-8")
    assert text.startswith("CEF:0|") and "Fake-Pass-1" not in text and "F*********1 (11)" in text


def test_syslog_message_priority_and_timestamp():
    msg = syslog_message(cred(), "BODY", hostname="sensor 1")
    assert msg == "<130>1 2023-11-14T22:13:20.500+00:00 sensor_1 netcreds-ng - credential - BODY"


class _FakeSocket:
    sent: list[tuple[bytes, object]] = []

    def __init__(self, *a: object, **k: object) -> None:
        pass

    def sendto(self, data: bytes, addr: object) -> None:
        self.sent.append((data, addr))

    def sendall(self, data: bytes) -> None:
        self.sent.append((data, None))

    def close(self) -> None:
        pass


def test_syslog_udp_masks_and_filters_by_risk(monkeypatch):
    _FakeSocket.sent = []
    monkeypatch.setattr(socket, "socket", _FakeSocket)
    sink = SyslogSink("udp://198.51.100.99:5514", {"hostname": "sensor"})
    sink.open(SinkContext(RunStats()))
    sink.write(cred())
    sink.write(cred(risk="info"))  # below default min_risk "low"
    sink.close(RunStats())
    assert len(_FakeSocket.sent) == 1
    data, addr = _FakeSocket.sent[0]
    assert addr == ("198.51.100.99", 5514)
    assert data.startswith(b"<130>1 ") and b"CEF:0|" in data
    assert b"Fake-Pass-1" not in data


def test_syslog_tcp_octet_counting_json(monkeypatch):
    _FakeSocket.sent = []
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: _FakeSocket())
    sink = SyslogSink("tcp://198.51.100.99", {"format": "json", "include_secrets": True})
    sink.open(SinkContext(RunStats()))
    sink.write(cred())
    data, _ = _FakeSocket.sent[0]
    count, _, msg = data.partition(b" ")
    assert int(count) == len(msg)
    body = msg.split(b" - ", 2)[-1]
    assert json.loads(body)["secret"] == "Fake-Pass-1"


@pytest.mark.parametrize("bad", ["http://x", "udp://", "514"])
def test_syslog_rejects_bad_targets(bad):
    with pytest.raises(ValueError):
        SyslogSink(bad).open(SinkContext(RunStats()))


@pytest.mark.parametrize(
    ("style", "key"), [("slack", "text"), ("discord", "content"), ("teams", "text"), ("generic", "findings")]
)
def test_webhook_chat_formats(monkeypatch, style, key):
    posted: list[dict] = []

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=None):
        posted.append(json.loads(req.data))
        return _Resp()

    monkeypatch.setattr(webhook_mod.urllib.request, "urlopen", fake_urlopen)
    sink = WebhookSink("https://hooks.example.test/x", {"format": style})
    sink.open(SinkContext(RunStats()))
    sink.write(cred())
    sink.close(RunStats())
    (payload,) = posted
    assert key in payload
    dumped = json.dumps(payload)
    assert "Fake-Pass-1" not in dumped
    if style != "generic":
        assert "netcreds-ng: 1 new finding" in dumped and "alice" in dumped


def test_unknown_webhook_format_rejected():
    with pytest.raises(ValueError):
        chat_payload("irc", [], [])
    with pytest.raises(ValueError):
        WebhookSink("https://hooks.example.test/x", {"format": "irc"}).open(SinkContext(RunStats()))
