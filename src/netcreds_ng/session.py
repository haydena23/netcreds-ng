"""Wires sources, engine, plugins, enrichers and sinks into a runnable analysis session."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.engine.engine import Engine
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
    plugin_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    outputs: list[tuple[str, str]] = field(default_factory=list)  # (format, target)
    mask_outputs: bool = False
    dedup: str = "run"
    dedup_db: str | None = None
    exclude_hosts: set[str] = field(default_factory=set)
    source_label: str = ""
    tls_keylog: str | None = None  # NSS key-log file: decrypt TLS sessions it has secrets for
    jobs: int = 1  # worker processes for multiple capture files
    plugin_dirs: list[str] = field(default_factory=list)  # so workers load the same plugins


def _worker(path: str, config: SessionConfig) -> tuple[list[Finding], RunStats, list[str]]:
    """Analyse one capture in a worker process: decoding and protocol plugins only.

    Dedup, enrichers and sinks run in the parent, which publishes the findings in file order.
    """
    from netcreds_ng.plugins.registry import load_registry

    registry = load_registry(plugin_dirs=config.plugin_dirs)
    stats = RunStats()
    found: list[Finding] = []
    pipeline = Pipeline(stats, dedup=Deduplicator("off"), listeners=[found.append])
    tls = None
    if config.tls_keylog:
        from netcreds_ng.engine.tls import KeyLog, TLSDecryptor

        tls = TLSDecryptor(KeyLog(config.tls_keylog))
    engine = Engine(registry.select_protocols(config.enable, config.disable, config.plugin_options), pipeline, stats,
                    exclude_hosts=config.exclude_hosts, tls=tls)  # fmt: skip
    try:
        engine.process(file_frames(path))
    except CaptureFormatError as exc:
        stats.source_errors.append(f"{path}: {exc}")
    except OSError as exc:
        stats.source_errors.append(f"{path}: {exc.strerror or exc}")
    engine.finish()
    return found, stats, pipeline.errors


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
        self.protocols = registry.select_protocols(config.enable, config.disable, config.plugin_options)
        self.enrichers = registry.select_enrichers(config.enable, config.disable, config.plugin_options)
        self.analytics = next((e for e in self.enrichers if isinstance(e, AnalyticsEnricher)), None)
        self.detection = next((e for e in self.enrichers if isinstance(e, DetectionEnricher)), None)
        self.sinks: list[SinkPlugin] = []
        for fmt, target in config.outputs:
            cls = registry.sink_class(fmt)
            opts = dict(config.plugin_options.get(fmt, {}))
            opts.setdefault("mask", config.mask_outputs)
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
        for frame in frames:
            self.engine.process_frame(frame)
            if stop is not None and stop():
                break

    def run_file(self, path: str, stop: Callable[[], bool] | None = None) -> None:
        for sink in self.sinks:
            notify = getattr(sink, "on_source", None)
            if callable(notify):
                notify(path)
        try:
            self.feed(file_frames(path), stop)
        except CaptureFormatError as exc:
            self.stats.source_errors.append(f"{path}: {exc}")
        except OSError as exc:
            self.stats.source_errors.append(f"{path}: {exc.strerror or exc}")

    def run_files(self, paths: list[str], stop: Callable[[], bool] | None = None) -> None:
        """Analyse capture files in order; with ``jobs > 1`` several files are analysed in parallel.

        Sequential mode lets a flow continue into the next file (rotated captures, e.g.
        ``tcpdump -C``). Parallel mode analyses each file on its own, so a flow split across
        files is seen as two partial flows; it is skipped when per-packet sinks (``--evidence``)
        are active. Findings are published in file order either way.
        """
        jobs = min(self.config.jobs, len(paths))
        if jobs <= 1 or stop is not None or self.engine.packet_observers:
            for path in paths:
                self.run_file(path, stop)
            return
        from concurrent.futures import ProcessPoolExecutor

        with ProcessPoolExecutor(max_workers=jobs) as pool:
            futures = [pool.submit(_worker, path, self.config) for path in paths]
            for future in futures:
                found, stats, errors = future.result()
                self.stats.merge(stats)
                for err in errors:
                    if len(self.pipeline.errors) < 100:
                        self.pipeline.errors.append(err)
                for finding in found:
                    self.pipeline.publish(finding)

    def close(self) -> None:
        self.engine.finish()
        self.pipeline.close()

    @property
    def errors(self) -> list[str]:
        return self.pipeline.errors
