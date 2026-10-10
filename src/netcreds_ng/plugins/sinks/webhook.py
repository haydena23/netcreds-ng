"""Webhook notifications (opt-in). Posts findings as JSON, as seen (secrets included)."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from netcreds_ng.model import Finding, RunStats
from netcreds_ng.output.formats import chat_line, chat_payload
from netcreds_ng.plugins.api import SinkContext, SinkPlugin
from netcreds_ng.plugins.sinks.files import iso

log = logging.getLogger(__name__)

_RISK = {"info": 0, "low": 1, "medium": 2, "high": 3}


class WebhookSink(SinkPlugin):
    """Sends batches of findings to an HTTP(S) endpoint.

    Options: ``min_risk`` (default ``medium``), ``batch`` (default 20),
    ``timeout`` seconds (default 5), ``format`` generic|slack|teams|discord (default generic: the JSON
    findings; the others post a chat message to an incoming-webhook URL).
    """

    name = "webhook"
    description = "POST findings as JSON to an HTTP(S) endpoint (opt-in)"

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.buffer: list[dict[str, Any]] = []
        self.lines: list[str] = []
        self.failures = 0

    def open(self, ctx: SinkContext) -> None:
        if not self.target or not self.target.startswith(("http://", "https://")):
            raise ValueError("webhook output needs an http(s):// URL")
        chat_payload(str(self.options.get("format", "generic")), [], [])  # validates the format name

    def write(self, finding: Finding) -> None:
        if _RISK.get(finding.risk, 0) < _RISK.get(str(self.options.get("min_risk", "medium")), 2):
            return
        f = finding
        data = f.to_dict()
        data["timestamp"] = iso(finding.timestamp)
        self.buffer.append(data)
        self.lines.append(chat_line(f))
        if len(self.buffer) >= int(self.options.get("batch", 20)):
            self._flush()

    def close(self, stats: RunStats) -> None:
        self._flush()

    def _flush(self) -> None:
        if not self.buffer:
            return
        assert self.target is not None
        payload = chat_payload(str(self.options.get("format", "generic")), self.buffer, self.lines)
        body = json.dumps(payload).encode()
        self.buffer, self.lines = [], []
        req = urllib.request.Request(self.target, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=float(self.options.get("timeout", 5))) as resp:
                resp.read()
        except OSError as exc:
            self.failures += 1
            raise RuntimeError(f"webhook delivery failed: {exc}") from exc
