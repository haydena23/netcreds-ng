"""SQLite session database: every finding, queryable after the run, and followable during it.

The database uses WAL journaling and is committed at least every ``commit_interval``
seconds (default 1) while findings arrive, together with a snapshot of the run's counters in
``runs.stats``. Another process can therefore read it while the run is going.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from netcreds_ng.model import Finding, RunStats
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

# Columns added to ``runs`` after the first release; older databases are upgraded in place.
RUN_COLUMNS = {"source": "TEXT", "updated": "REAL", "finished": "REAL", "stats": "TEXT"}


def upgrade(db: sqlite3.Connection) -> None:
    have = {row[1] for row in db.execute("PRAGMA table_info(runs)")}
    for name, decl in RUN_COLUMNS.items():
        if name not in have:
            db.execute(f"ALTER TABLE runs ADD COLUMN {name} {decl}")


class SqliteSink(SinkPlugin):
    name = "sqlite"
    description = "SQLite session database (findings + run statistics)"

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.db: sqlite3.Connection | None = None
        self.run_id = 0
        self.stats: RunStats | None = None
        self.interval = float(self.options.get("commit_interval", 1.0))
        self._last_commit = 0.0

    def open(self, ctx: SinkContext) -> None:
        if not self.target:
            raise ValueError("sqlite output needs a database path")
        self.stats = ctx.stats
        self.db = sqlite3.connect(self.target, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")  # readers never block the run
        self.db.executescript(SCHEMA)
        upgrade(self.db)
        source = str(self.options.get("source_label") or "")
        cur = self.db.execute("INSERT INTO runs(started, source, updated) VALUES (strftime('%s','now'), ?, ?)",
                              (source, time.time()))  # fmt: skip
        self.run_id = int(cur.lastrowid or 0)
        self.db.commit()
        self._last_commit = time.monotonic()

    def write(self, finding: Finding) -> None:
        assert self.db is not None
        f = finding
        self.db.execute(
            "INSERT INTO findings(run_id, ts, frame, protocol, kind, risk, src_ip, src_port, dst_ip, dst_port,"
            " username, domain, secret, value, tags, plugin, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                self.run_id, f.timestamp, f.frame, f.protocol, f.kind.value, f.risk, f.src.ip, f.src.port,
                f.dst.ip, f.dst.port, f.username, f.domain, f.secret, f.value, ",".join(f.tags), f.plugin,
                json.dumps(f.extra, default=str, sort_keys=True),
            ),
        )  # fmt: skip
        if time.monotonic() - self._last_commit >= self.interval:
            self._checkpoint(self.stats)

    def _checkpoint(self, stats: RunStats | None, finished: bool = False) -> None:
        assert self.db is not None
        if stats is not None:
            self.db.execute(
                "UPDATE runs SET frames=?, findings=?, duplicates=?, errors=?, updated=?, stats=?,"
                " finished=COALESCE(finished, ?) WHERE id=?",
                (stats.frames, stats.findings, stats.duplicates, stats.total_plugin_errors, time.time(),
                 json.dumps(stats.snapshot(), sort_keys=True), time.time() if finished else None, self.run_id),
            )  # fmt: skip
        self.db.commit()
        self._last_commit = time.monotonic()

    def close(self, stats: RunStats) -> None:
        if self.db is None:
            return
        self._checkpoint(stats, finished=True)
        self.db.close()
        self.db = None
