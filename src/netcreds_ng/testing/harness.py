"""One-call analysis harness for tests and plugin development.

    from netcreds_ng.testing.harness import analyze
    from netcreds_ng.testing.packets import TCPConversation

    c = TCPConversation("192.0.2.1", 50000, "198.51.100.2", 21).handshake()
    c.client(b"USER a\\r\\nPASS b\\r\\n").close()
    findings = analyze(c.frames)                      # all built-in plugins
    findings = analyze(c.frames, plugins=[MyPlugin()])  # only yours
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from netcreds_ng.engine.engine import Engine
from netcreds_ng.engine.pcapio import RawFrame, open_capture
from netcreds_ng.engine.pipeline import Deduplicator, Pipeline
from netcreds_ng.model import Finding, RunStats
from netcreds_ng.plugins.api import EnricherPlugin, ProtocolPlugin
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.testing.packets import Frame


def to_raw_frames(frames: Iterable[Frame | bytes | RawFrame], linktype: int = 1) -> list[RawFrame]:
    out: list[RawFrame] = []
    for i, f in enumerate(frames, 1):
        if isinstance(f, RawFrame):
            out.append(f)
        elif isinstance(f, Frame):
            out.append(RawFrame(i, f.timestamp, linktype, f.data, len(f.data)))
        else:
            out.append(RawFrame(i, 1_700_000_000.0 + i / 100, linktype, f, len(f)))
    return out


def analyze(
    source: str | Sequence[Frame | bytes | RawFrame],
    plugins: Sequence[ProtocolPlugin] | None = None,
    enrichers: Sequence[EnricherPlugin] | None = None,
    enable: list[str] | None = None,
    disable: list[str] | None = None,
    options: dict[str, dict[str, Any]] | None = None,
    dedup: str = "run",
    linktype: int = 1,
    stats: RunStats | None = None,
) -> list[Finding]:
    """Run frames (or a capture file path) through the engine and return the findings."""
    stats = stats if stats is not None else RunStats()
    if plugins is None or enrichers is None:
        reg = load_registry(use_entry_points=False)
        if plugins is None:
            plugins = reg.select_protocols(enable, disable, options)
        if enrichers is None:
            enrichers = reg.select_enrichers(enable, disable, options)
    found: list[Finding] = []
    pipe = Pipeline(stats, enrichers=enrichers, dedup=Deduplicator(dedup), listeners=[found.append])
    engine = Engine(plugins, pipe, stats)
    frames = open_capture(source) if isinstance(source, str) else to_raw_frames(source, linktype)
    engine.process(frames)
    engine.finish()
    pipe.close()
    if stats.plugin_errors:
        raise AssertionError(f"plugin errors during analysis: {dict(stats.plugin_errors)} {pipe.errors[:3]}")
    return found
