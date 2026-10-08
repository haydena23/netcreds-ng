"""SQLite session database: every finding, queryable after the run."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from netcreds_ng.model import Finding, RunStats
from netcreds_ng.output.masking import masked
from netcreds_ng.plugins.api import SinkContext, SinkPlugin

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL, frames INTEGER, findings INTEGER, duplicates INTEGER, errors INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id),
    ts REAL, frame INTEGER, protocol TEXT, kind TEXT, risk TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
    username TEXT, domain TEXT, secret TEXT, value TEXT,
    tags TEXT, plugin TEXT, extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_proto ON findings(protocol, kind);
CREATE INDEX IF NOT EXISTS idx_findings_hosts ON findings(src_ip, dst_ip);
"""


class SqliteSink(SinkPlugin):
    name = "sqlite"
    description = "SQLite session database (findings + run statistics)"

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.db: sqlite3.Connection | None = None
        self.run_id = 0

    def open(self, ctx: SinkContext) -> None:
        if not self.target:
            raise ValueError("sqlite output needs a database path")
        self.db = sqlite3.connect(self.target)
        self.db.executescript(SCHEMA)
        cur = self.db.execute("INSERT INTO runs(started) VALUES (strftime('%s','now'))")
        self.run_id = int(cur.lastrowid or 0)

    def write(self, finding: Finding) -> None:
        assert self.db is not None
        f = masked(finding) if self.options.get("mask") else finding
        self.db.execute(
            "INSERT INTO findings(run_id, ts, frame, protocol, kind, risk, src_ip, src_port, dst_ip, dst_port,"
            " username, domain, secret, value, tags, plugin, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                self.run_id, f.timestamp, f.frame, f.protocol, f.kind.value, f.risk, f.src.ip, f.src.port,
                f.dst.ip, f.dst.port, f.username, f.domain, f.secret, f.value, ",".join(f.tags), f.plugin,
                json.dumps(f.extra, default=str, sort_keys=True),
            ),
        )  # fmt: skip

    def close(self, stats: RunStats) -> None:
        if self.db is None:
            return
        self.db.execute(
            "UPDATE runs SET frames=?, findings=?, duplicates=?, errors=? WHERE id=?",
            (stats.frames, stats.findings, stats.duplicates, stats.total_plugin_errors, self.run_id),
        )
        self.db.commit()
        self.db.close()
