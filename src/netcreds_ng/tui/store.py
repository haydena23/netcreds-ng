"""Read-only access to a ``--sqlite`` findings database, for ``--attach``.

The reader opens the database read-only and fetches findings by row id, so it can be
polled while another netcreds-ng process is still writing (the sink uses WAL journaling and
commits about once a second).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netcreds_ng.model import Endpoint, Finding, Kind, RunStats

ACTIVE_SECONDS = 15.0  # a run without an end that was updated this recently counts as in progress


class StoreError(ValueError):
    pass


@dataclass
class RunInfo:
    id: int
    source: str
    started: float | None
    updated: float | None
    finished: float | None

    @property
    def in_progress(self) -> bool:
        return self.finished is None and self.updated is not None and time.time() - self.updated < ACTIVE_SECONDS


class FindingStore:
    def __init__(self, path: str) -> None:
        self.path = path
        if not Path(path).is_file():
            raise StoreError(f"database not found: {path}")
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        try:
            self.db = sqlite3.connect(uri, uri=True, check_same_thread=False)
            tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.DatabaseError as exc:
            raise StoreError(f"{path}: not a netcreds-ng database ({exc})") from exc
        if not {"runs", "findings"} <= tables:
            raise StoreError(f"{path}: not a netcreds-ng database (no runs/findings tables)")
        self.run_columns = {r[1] for r in self.db.execute("PRAGMA table_info(runs)")}
        self.last_id = 0
        self.skipped = 0  # rows with a kind this version does not know (shown in the status bar)
        self._lock = threading.Lock()  # the dashboard polls from a worker thread and reads stats from the UI

    def poll(self, limit: int = 5000) -> list[Finding]:
        """Findings added since the previous call (at most ``limit`` per call), oldest first."""
        with self._lock:
            return self._poll(limit)

    def _poll(self, limit: int) -> list[Finding]:
        rows = self.db.execute(
            "SELECT id, ts, frame, protocol, kind, risk, src_ip, src_port, dst_ip, dst_port, username, domain,"
            " secret, value, tags, plugin, extra FROM findings WHERE id > ? ORDER BY id LIMIT ?",
            (self.last_id, limit),
        ).fetchall()
        out: list[Finding] = []
        for row in rows:
            self.last_id = row[0]
            finding = _finding(row)
            if finding is None:
                self.skipped += 1
            else:
                out.append(finding)
        return out

    def runs(self) -> list[RunInfo]:
        with self._lock:
            return self._runs()

    def _runs(self) -> list[RunInfo]:
        cols = ["id", "started"] + [c if c in self.run_columns else "NULL" for c in ("source", "updated", "finished")]
        rows = self.db.execute(f"SELECT {', '.join(cols)} FROM runs ORDER BY id").fetchall()
        return [RunInfo(int(r[0]), str(r[2] or ""), _num(r[1]), _num(r[3]), _num(r[4])) for r in rows]

    def stats(self) -> RunStats:
        """Counters of every run in the database, added up. Older databases only know frame,
        finding and duplicate counts."""
        with self._lock:
            return self._stats()

    def _stats(self) -> RunStats:
        total = RunStats()
        has_stats = "stats" in self.run_columns
        query = "SELECT frames, findings, duplicates" + (", stats" if has_stats else "") + " FROM runs ORDER BY id"
        for row in self.db.execute(query):
            snap: dict[str, Any] = {}
            if has_stats and row[3]:
                try:
                    snap = json.loads(row[3])
                except ValueError:
                    snap = {}
            run = RunStats.from_snapshot(snap) if snap else RunStats(frames=int(row[0] or 0))
            total.merge(run)
            total.findings += int(snap.get("findings", row[1] or 0))
            total.duplicates += int(snap.get("duplicates", row[2] or 0))
            total.by_protocol.update(run.by_protocol)
            total.by_kind.update(run.by_kind)
        return total

    def close(self) -> None:
        with self._lock:
            self.db.close()


def _num(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _finding(row: tuple[Any, ...]) -> Finding | None:
    (_id, ts, frame, protocol, kind, risk, src_ip, src_port, dst_ip, dst_port, username, domain, secret, value,
     tags, plugin, extra) = row  # fmt: skip
    try:
        k = Kind(kind)
    except ValueError:
        return None  # a kind from a newer version: skip rather than guess
    try:
        extra_obj = json.loads(extra) if extra else {}
    except ValueError:
        extra_obj = {}
    return Finding(
        protocol=protocol or "", kind=k, src=Endpoint(src_ip or "", int(src_port or 0)),
        dst=Endpoint(dst_ip or "", int(dst_port or 0)), timestamp=float(ts or 0.0), frame=int(frame or 0),
        username=username, secret=secret, domain=domain, value=value, risk=risk or "info", plugin=plugin or "",
        tags=[t for t in (tags or "").split(",") if t], extra=extra_obj if isinstance(extra_obj, dict) else {},
    )  # fmt: skip
