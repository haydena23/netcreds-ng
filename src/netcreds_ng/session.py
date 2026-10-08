"""Wires sources, engine, plugins, enrichers and sinks into a runnable analysis session."""

from __future__ import annotations

import logging
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


class Session:
    def __init__(self, registry: Registry, config: SessionConfig, listeners: Iterable[Callable[[Finding], None]] = ()):
        self.config = config
        self.stats = RunStats()
        self.protocols = registry.select_protocols(config.enable, config.disable, config.plugin_options)
        self.enrichers = registry.select_enrichers(config.enable, config.disable, config.plugin_options)
        self.analytics = next((e for e in self.enrichers if isinstance(e, AnalyticsEnricher)), None)
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
        self.engine = Engine(self.protocols, self.pipeline, self.stats, exclude_hosts=config.exclude_hosts)
        self.findings_seen = 0

    def summary(self) -> dict[str, Any]:
        return self.analytics.summary() if self.analytics else {}

    def open(self) -> None:
        self.pipeline.open()

    def feed(self, frames: Iterable[RawFrame], stop: Callable[[], bool] | None = None) -> None:
        for frame in frames:
            self.engine.process_frame(frame)
            if stop is not None and stop():
                break

    def run_file(self, path: str, stop: Callable[[], bool] | None = None) -> None:
        try:
            self.feed(file_frames(path), stop)
        except CaptureFormatError as exc:
            self.stats.source_errors.append(f"{path}: {exc}")
        except OSError as exc:
            self.stats.source_errors.append(f"{path}: {exc.strerror or exc}")

    def close(self) -> None:
        self.engine.finish()
        self.pipeline.close()

    @property
    def errors(self) -> list[str]:
        return self.pipeline.errors
