"""File sinks: JSON Lines, CSV and plain log."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from typing import IO, Any

from netcreds_ng.model import Finding, RunStats
from netcreds_ng.plugins.api import SinkContext, SinkPlugin


def iso(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=UTC).isoformat(timespec="microseconds")


class _FileSink(SinkPlugin):
    """Appends to ``target`` (or writes to stdout when target is ``-``)."""

    newline: str | None = None

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.fh: IO[str] | None = None
        self.is_new = True

    def open(self, ctx: SinkContext) -> None:
        if not self.target:
            raise ValueError(f"{self.name} output needs a file path")
        if self.target == "-":
            import sys

            self.fh = sys.stdout
            return
        import os

        self.is_new = not os.path.exists(self.target) or os.path.getsize(self.target) == 0
        self.fh = open(self.target, "a", encoding="utf-8", newline=self.newline)

    def close(self, stats: RunStats) -> None:
        if self.fh is not None and self.target != "-":
            self.fh.close()


class JsonlSink(_FileSink):
    name = "jsonl"
    description = "One JSON object per finding (SIEM friendly)"

    def write(self, finding: Finding) -> None:
        assert self.fh is not None
        data = finding.to_dict()
        data["timestamp"] = iso(finding.timestamp)
        self.fh.write(json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n")
        self.fh.flush()


CSV_FIELDS = ["timestamp", "protocol", "kind", "risk", "src", "dst", "username", "domain", "secret", "value",
              "tags", "frame", "plugin"]  # fmt: skip


class CsvSink(_FileSink):
    name = "csv"
    description = "Comma separated values"
    newline = ""

    def open(self, ctx: SinkContext) -> None:
        super().open(ctx)
        assert self.fh is not None
        self.writer = csv.writer(self.fh)
        if self.is_new:
            self.writer.writerow(CSV_FIELDS)

    def write(self, finding: Finding) -> None:
        f = finding
        self.writer.writerow([
            iso(f.timestamp), f.protocol, f.kind.value, f.risk, str(f.src), str(f.dst), f.username or "",
            f.domain or "", f.secret or "", f.value or "", ";".join(f.tags), f.frame, f.plugin,
        ])  # fmt: skip
        assert self.fh is not None
        self.fh.flush()


class LogSink(_FileSink):
    name = "log"
    description = "Human readable log lines"

    def write(self, finding: Finding) -> None:
        f = finding
        tags = f" [{', '.join(f.tags)}]" if f.tags else ""
        assert self.fh is not None
        self.fh.write(
            f"{iso(f.timestamp)} [{f.risk.upper()}] [{f.protocol}] {f.kind.value} {f.src} -> {f.dst}: {f.display}{tags}\n"
        )
        self.fh.flush()
