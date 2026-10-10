"""Wires sources, engine, plugins, enrichers and sinks into a runnable analysis session."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.engine.engine import Engine, relaxed_gc
from netcreds_ng.engine.pcapio import CaptureFormatError, RawFrame
from netcreds_ng.engine.pipeline import Deduplicator, Pipeline
from netcreds_ng.engine.sources import file_frames
from netcreds_ng.model import Finding, RunStats
from netcreds_ng.plugins.api import SinkPlugin
from netcreds_ng.plugins.enrichers.analytics import AnalyticsEnricher
from netcreds_ng.plugins.enrichers.detection import DetectionEnricher
from netcreds_ng.plugins.registry import Registry

log = logging.getLogger(__name__)


@dataclass
class SessionConfig:
    enable: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)  # --plugins: run only these plugins/sets (empty: default)
    sets: dict[str, list[str]] = field(default_factory=dict)  # user-defined plugin sets ([sets] in the config)
    plugin_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    outputs: list[tuple[str, str]] = field(default_factory=list)  # (format, target)
    dedup: str = "run"
    dedup_db: str | None = None
    exclude_hosts: set[str] = field(default_factory=set)
    source_label: str = ""
    tls_keylog: str | None = None  # NSS key-log file: decrypt TLS sessions it has secrets for
    jobs: int = 1  # worker processes (netcreds_ng.parallel); 1: analyse in this process
    plugin_dirs: list[str] = field(default_factory=list)  # so workers load the same plugins


def _protocols(registry: Registry, config: SessionConfig) -> list[Any]:
    return registry.select_protocols(config.enable, config.disable, config.plugin_options, only=config.plugins,
                                     user_sets=config.sets)  # fmt: skip


def combine_summary(analytics: AnalyticsEnricher | None, detection: DetectionEnricher | None) -> dict[str, Any]:
    """The analytics summary of a run: host profiles and counters, plus alerts, services and scores."""
    out: dict[str, Any] = analytics.summary() if analytics else {}
    if detection is not None:
        det = detection.summary()
        out.update({k: v for k, v in det.items() if k != "host_scores"})
        scores = det["host_scores"]
        for host in out.get("hosts", []):
            host["score"] = scores.get(host["ip"], 0)
        out["host_scores"] = scores
    return out


class Session:
    def __init__(self, registry: Registry, config: SessionConfig, listeners: Iterable[Callable[[Finding], None]] = ()):
        self.config = config
        self.stats = RunStats()
        self.protocols = _protocols(registry, config)
        self.enrichers = registry.select_enrichers(config.enable, config.disable, config.plugin_options, config.sets)
        self.analytics = next((e for e in self.enrichers if isinstance(e, AnalyticsEnricher)), None)
        self.detection = next((e for e in self.enrichers if isinstance(e, DetectionEnricher)), None)
        self.sinks: list[SinkPlugin] = []
        for fmt, target in config.outputs:
            cls = registry.sink_class(fmt)
            opts = dict(config.plugin_options.get(fmt, {}))
            opts.setdefault("summary", self.summary)
            opts.setdefault("source_label", config.source_label)
            self.sinks.append(cls(target, opts))
        self.pipeline = Pipeline(
            self.stats,
            enrichers=self.enrichers,
            sinks=self.sinks,
            dedup=Deduplicator(config.dedup, config.dedup_db),
            listeners=list(listeners),
        )
        tls = None
        if config.tls_keylog:
            from netcreds_ng.engine.tls import KeyLog, TLSDecryptor

            if not os.path.isfile(config.tls_keylog):
                raise ValueError(f"TLS key log not found: {config.tls_keylog}")
            tls = TLSDecryptor(KeyLog(config.tls_keylog))  # RuntimeError if cryptography is missing
        self.engine = Engine(self.protocols, self.pipeline, self.stats, exclude_hosts=config.exclude_hosts, tls=tls)
        for sink in self.sinks:
            if getattr(sink, "wants_packets", False):
                self.engine.packet_observers.append(self._observer(sink))
        self.findings_seen = 0

    def _observer(self, sink: SinkPlugin) -> Callable[[Any], None]:
        def observe(pkt: Any) -> None:
            try:
                sink.on_packet(pkt)  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001 - isolate sink code like any other plugin
                self.pipeline._error(f"sink:{sink.name}", exc)

        return observe

    def summary(self) -> dict[str, Any]:
        return combine_summary(self.analytics, self.detection)

    def open(self) -> None:
        self.pipeline.open()

    def feed(self, frames: Iterable[RawFrame], stop: Callable[[], bool] | None = None) -> None:
        process = self.engine.process_frame
        with relaxed_gc():
            for frame in frames:
                process(frame)
                if stop is not None and stop():
                    break

    def notify_source(self, path: str) -> None:
        """Tell sinks that want to know (``on_source``) that the next findings come from ``path``."""
        for sink in self.sinks:
            notify = getattr(sink, "on_source", None)
            if callable(notify):
                notify(path)

    def run_file(self, path: str, stop: Callable[[], bool] | None = None) -> None:
        self.notify_source(path)
        try:
            self.feed(file_frames(path), stop)
        except CaptureFormatError as exc:
            self.stats.source_errors.append(f"{path}: {exc}")
        except OSError as exc:
            self.stats.source_errors.append(f"{path}: {exc.strerror or exc}")

    def run_files(self, paths: list[str], stop: Callable[[], bool] | None = None) -> None:
        """Analyse capture files in order, as one stream: a flow may continue into the next file
        (rotated captures, e.g. ``tcpdump -C``).

        With ``jobs > 1`` the frames are split across worker processes (:mod:`netcreds_ng.parallel`)
        and the output is the same as with one. See :meth:`parallel_workers` for when that happens.
        """
        workers = self.parallel_workers(paths) if stop is None else 1
        if workers > 1:
            from netcreds_ng.parallel import run_parallel

            run_parallel(self, paths, workers)
            return
        for path in paths:
            self.run_file(path, stop)

    def parallel_workers(self, paths: list[str]) -> int:
        """Worker processes for ``paths``: ``jobs``, at most one per CPU; 1 (no workers) for inputs too
        small to gain from them and when a per-packet sink (``--evidence``) must see every packet in order."""
        from netcreds_ng import parallel

        workers = min(self.config.jobs, os.cpu_count() or 1)
        if workers <= 1 or self.engine.packet_observers:
            return 1
        size = 0
        for path in paths:
            try:
                size += os.path.getsize(path)
            except OSError:
                pass  # reported when the file is read
        return workers if size >= parallel.PARALLEL_MIN_BYTES else 1

    def close(self) -> None:
        self.engine.finish()
        self.pipeline.close()

    @property
    def errors(self) -> list[str]:
        return self.pipeline.errors
