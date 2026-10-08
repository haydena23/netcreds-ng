"""Findings pipeline: enrichers -> dedup -> sinks/listeners."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from collections.abc import Callable, Iterable
from typing import Any

from netcreds_ng.model import Finding, RunStats
from netcreds_ng.plugins.api import EnricherPlugin, SinkContext, SinkPlugin

log = logging.getLogger(__name__)

DEDUP_MODES = ("off", "run", "persistent")


class Deduplicator:
    """Suppress repeated findings. ``persistent`` keeps hashed keys in SQLite across runs."""

    def __init__(self, mode: str = "run", db_path: str | None = None) -> None:
        if mode not in DEDUP_MODES:
            raise ValueError(f"unknown dedup mode {mode!r}")
        self.mode = mode
        self._seen: set[str] = set()
        self._db: sqlite3.Connection | None = None
        if mode == "persistent":
            self._db = sqlite3.connect(db_path or "netcreds-ng-state.sqlite3")
            self._db.execute("CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY)")

    @staticmethod
    def _key(finding: Finding) -> str:
        return hashlib.sha256(repr(finding.dedup_key()).encode("utf-8", "surrogateescape")).hexdigest()

    def is_new(self, finding: Finding) -> bool:
        if self.mode == "off":
            return True
        key = self._key(finding)
        if key in self._seen:
            return False
        self._seen.add(key)
        if self._db is not None:
            cur = self._db.execute("INSERT OR IGNORE INTO seen(key) VALUES (?)", (key,))
            self._db.commit()
            return cur.rowcount == 1
        return True

    def close(self) -> None:
        if self._db is not None:
            self._db.close()


class Pipeline:
    def __init__(
        self,
        stats: RunStats,
        enrichers: Iterable[EnricherPlugin] = (),
        sinks: Iterable[SinkPlugin] = (),
        dedup: Deduplicator | None = None,
        listeners: Iterable[Callable[[Finding], None]] = (),
        options: dict[str, Any] | None = None,
    ) -> None:
        self.stats = stats
        self.enrichers = list(enrichers)
        self.sinks = list(sinks)
        self.dedup = dedup or Deduplicator("run")
        self.listeners = list(listeners)
        self.options = options or {}
        self.errors: list[str] = []
        self._opened = False

    def open(self) -> None:
        if self._opened:
            return
        self._opened = True
        ctx = SinkContext(self.stats, self.options)
        for sink in self.sinks:
            sink.open(ctx)

    def publish(self, finding: Finding) -> None:
        self.open()
        queue = [finding]
        while queue:
            item = queue.pop(0)
            # Dedup first so enrichers (analytics, host profiles) see each finding once.
            if not self.dedup.is_new(item):
                self.stats.duplicates += 1
                continue
            for enricher in self.enrichers:
                try:
                    queue.extend(enricher.enrich(item))
                except Exception as exc:  # noqa: BLE001 - isolate third-party code
                    self._error(f"enricher:{enricher.name}", exc)
            self.stats.findings += 1
            self.stats.by_protocol[item.protocol] += 1
            self.stats.by_kind[item.kind.value] += 1
            for sink in self.sinks:
                try:
                    sink.write(item)
                except Exception as exc:  # noqa: BLE001
                    self._error(f"sink:{sink.name}", exc)
            for listener in self.listeners:
                listener(item)

    def close(self) -> None:
        self.open()
        for sink in self.sinks:
            try:
                sink.close(self.stats)
            except Exception as exc:  # noqa: BLE001
                self._error(f"sink:{sink.name}", exc)
        self.dedup.close()

    def _error(self, where: str, exc: BaseException) -> None:
        self.stats.plugin_errors[where] += 1
        msg = f"{where}: {type(exc).__name__}: {exc}"
        if len(self.errors) < 100:
            self.errors.append(msg)
        log.warning(msg)
