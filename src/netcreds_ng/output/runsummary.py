"""Machine-readable run summary (``--summary-json``): counters, capture health and analytics.

It holds no secrets: findings are not included (use ``--jsonl`` for those), and the analytics
part names accounts and hosts only.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from netcreds_ng import __version__
from netcreds_ng.health import assess
from netcreds_ng.model import RunStats
from netcreds_ng.plugins.sinks.files import iso


def stats_dict(stats: RunStats) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in vars(stats).items():
        if isinstance(value, Counter):
            out[name] = dict(sorted(value.items()))
        elif isinstance(value, list):
            out[name] = list(value)
        else:
            out[name] = value
    out["first_ts"] = iso(stats.first_ts) if stats.first_ts else None
    out["last_ts"] = iso(stats.last_ts) if stats.last_ts else None
    return out


def build(stats: RunStats, analytics: dict[str, Any], source: str, errors: list[str]) -> dict[str, Any]:
    return {
        "tool": "netcreds-ng",
        "version": __version__,
        "source": source,
        "stats": stats_dict(stats),
        "capture_health": assess(stats),
        "analytics": analytics,
        "errors": list(errors),
    }


def write(path: str, stats: RunStats, analytics: dict[str, Any], source: str, errors: list[str]) -> None:
    data = build(stats, analytics, source, errors)
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n"
    if path == "-":
        import sys

        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
