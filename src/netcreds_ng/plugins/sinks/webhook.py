"""Webhook notifications (opt-in). Posts findings as JSON; secrets are masked unless explicitly requested."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from netcreds_ng.model import Finding, RunStats
from netcreds_ng.output.masking import masked
from netcreds_ng.plugins.api import SinkContext, SinkPlugin
from netcreds_ng.plugins.sinks.files import iso

log = logging.getLogger(__name__)

_RISK = {"info": 0, "low": 1, "medium": 2, "high": 3}


class WebhookSink(SinkPlugin):
    """Sends batches of findings to an HTTP(S) endpoint.

    Options: ``min_risk`` (default ``medium``), ``include_secrets`` (default False), ``batch`` (default 20),
    ``timeout`` seconds (default 5).
    """

    name = "webhook"
    description = "POST findings as JSON to an HTTP(S) endpoint (opt-in; secrets masked by default)"

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.buffer: list[dict[str, Any]] = []
        self.failures = 0

    def open(self, ctx: SinkContext) -> None:
        if not self.target or not self.target.startswith(("http://", "https://")):
            raise ValueError("webhook output needs an http(s):// URL")

    def write(self, finding: Finding) -> None:
        if _RISK.get(finding.risk, 0) < _RISK.get(str(self.options.get("min_risk", "medium")), 2):
            return
        f = finding if self.options.get("include_secrets") else masked(finding)
        data = f.to_dict()
        data["timestamp"] = iso(finding.timestamp)
        self.buffer.append(data)
        if len(self.buffer) >= int(self.options.get("batch", 20)):
            self._flush()

    def close(self, stats: RunStats) -> None:
        self._flush()

    def _flush(self) -> None:
        if not self.buffer:
            return
        assert self.target is not None
        body = json.dumps({"source": "netcreds-ng", "findings": self.buffer}).encode()
        self.buffer = []
        req = urllib.request.Request(self.target, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=float(self.options.get("timeout", 5))) as resp:
                resp.read()
        except OSError as exc:
            self.failures += 1
            raise RuntimeError(f"webhook delivery failed: {exc}") from exc
