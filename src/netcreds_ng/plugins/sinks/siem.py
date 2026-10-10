"""SIEM sinks: CEF lines to a file, and syslog (RFC 5424, CEF or JSON body) over UDP/TCP.

The syslog sink transmits over the network, so it only runs when explicitly requested
(``--syslog udp://host:514``). Findings are sent as seen, secrets included; findings below
``min_risk`` (default ``low``) are not sent.
"""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlsplit

from netcreds_ng.model import Finding, RunStats
from netcreds_ng.output.formats import RISK_ORDER, cef_line, json_event, syslog_message
from netcreds_ng.plugins.api import SinkContext, SinkPlugin
from netcreds_ng.plugins.sinks.files import _FileSink


class CefSink(_FileSink):
    name = "cef"
    description = "ArcSight CEF events, one per line"

    def write(self, finding: Finding) -> None:
        assert self.fh is not None
        self.fh.write(cef_line(finding) + "\n")
        self.fh.flush()


class SyslogSink(SinkPlugin):
    """Options: ``format`` cef|json (default cef), ``min_risk`` (default low), ``hostname``,
    ``timeout`` seconds (default 5)."""

    name = "syslog"
    description = "Send findings to a syslog collector (udp:// or tcp://; opt-in)"

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.sock: socket.socket | None = None
        self.transport = "udp"
        self.address: tuple[str, int] = ("", 0)
        self.sent = 0

    def open(self, ctx: SinkContext) -> None:
        parts = urlsplit(self.target or "")
        if parts.scheme not in ("udp", "tcp") or not parts.hostname:
            raise ValueError("syslog output needs udp://host[:port] or tcp://host[:port]")
        if str(self.options.get("format", "cef")) not in ("cef", "json"):
            raise ValueError("syslog format must be cef or json")
        self.transport = parts.scheme
        self.address = (parts.hostname, parts.port or 514)
        if self.transport == "udp":
            self.sock = socket.socket(socket.AF_INET6 if ":" in parts.hostname else socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.sock = socket.create_connection(self.address, timeout=float(self.options.get("timeout", 5)))

    def write(self, finding: Finding) -> None:
        if RISK_ORDER.get(finding.risk, 0) < RISK_ORDER.get(str(self.options.get("min_risk", "low")), 1):
            return
        f = finding
        body = json_event(f) if self.options.get("format") == "json" else cef_line(f)
        msg = syslog_message(f, body, self.options.get("hostname")).encode("utf-8")
        assert self.sock is not None
        if self.transport == "udp":
            self.sock.sendto(msg[:65000], self.address)
        else:
            self.sock.sendall(f"{len(msg)} ".encode() + msg)  # RFC 6587 octet counting
        self.sent += 1

    def close(self, stats: RunStats) -> None:
        if self.sock is not None:
            self.sock.close()
