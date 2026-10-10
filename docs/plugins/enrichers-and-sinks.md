# Enrichers and sinks

## Enrichers

An enricher sees every finding after de-duplication and before any output. It can change the finding in place (tags, risk, `extra`) and yield new findings.

```python title="corp.py"
from __future__ import annotations

from collections.abc import Iterator

from netcreds_ng.model import Finding
from netcreds_ng.plugins.api import EnricherPlugin


class CorporateAccounts(EnricherPlugin):
    name = "corp-accounts"
    description = "Tag findings for accounts in the corporate domain"
    priority = 30  # after analytics (10) and detection (20)

    def enrich(self, finding: Finding) -> Iterator[Finding]:
        domain = str(self.options.get("domain", "corp.example")).lower()
        user = (finding.username or "").lower()
        if user.endswith("@" + domain) or (finding.domain or "").lower() == domain.split(".")[0]:
            finding.tags.append("corporate-account")
            if finding.kind.is_secret:
                finding.risk = "high"
        return iter(())
```

```console
$ netcreds-ng -p smtp_auth_login.pcap --plugin-dir ./my-plugins --option corp-accounts.domain=example.com --jsonl - -q
{"display": "smtpuser@example.com:Smtp-Fake-Pass", ..., "tags": ["cleartext", "corporate-account"], ...}
```

Points to know:

- `enrich()` must return an iterator. Return `iter(())` when you add nothing; `yield` findings to add them. New findings go through dedup and **every** enricher again, including yours, so guard against loops (the `detection` enricher ignores `ALERT` findings for this reason).
- Enrichers run in `(priority, name)` order. The built-in `analytics` (10) sets `cleartext`, `weak-password`, `password-reuse` and escalates risk; `detection` (20) raises alerts. Use a priority above 20 to see their results.
- An enricher is constructed once per run, so it can keep state across findings (counters, windows) and expose a summary.
- Options come from `--option <name>.key=value` or `[plugins.<name>]`, in `self.options`.
- Exceptions are caught, counted as `enricher:<name>` errors, and the finding continues to the other enrichers and the outputs.
- `opt_in = True` disables the enricher unless it is enabled explicitly.
- Use `Kind.ALERT` for behavioural detections, and set `extra["detection"]`; the console summary lists alerts from the `detection` enricher's summary, but every output receives your alert findings.

## Sinks

A sink writes findings somewhere. It is selected by name with `-o <name>:<target>`.

```python title="counts.py"
from __future__ import annotations

import json
from collections import Counter

from netcreds_ng.model import Finding, RunStats
from netcreds_ng.plugins.api import SinkContext, SinkPlugin


class ProtocolCounts(SinkPlugin):
    name = "counts"
    description = "Write finding counts per protocol and kind as JSON"

    def open(self, ctx: SinkContext) -> None:
        if not self.target:
            raise ValueError("counts output needs a file path")
        self.counts: Counter[str] = Counter()

    def write(self, finding: Finding) -> None:
        self.counts[f"{finding.protocol}/{finding.kind.value}"] += 1

    def close(self, stats: RunStats) -> None:
        with open(self.target, "w", encoding="utf-8") as fh:
            json.dump({"frames": stats.frames, "counts": dict(sorted(self.counts.items()))}, fh, indent=2)
```

```console
$ netcreds-ng -p smtp_auth_login.pcap --plugin-dir ./my-plugins -o counts:counts.json
$ cat counts.json
{
  "frames": 15,
  "counts": {
    "SMTP/auth_result": 1,
    "SMTP/credential": 1
  }
}
```

### Lifecycle

| Method | When |
| --- | --- |
| `__init__(target, options)` | when the session is built; `self.target` and `self.options` are set |
| `open(ctx)` | before the first finding; `ctx.stats` is the live `RunStats`. Raise `ValueError` or `OSError` for bad targets: the CLI reports it and exits with code 1 |
| `write(finding)` | for every finding, after enrichment |
| `close(stats)` | once at the end of the run, with the final statistics |

### Options a sink receives

`self.options` contains the options for its name (`--option counts.key=value`, `[output.counts]` or `[plugins.counts]`), plus:

| Key | Value |
| --- | --- |
| `summary` | a callable returning `Session.summary()`: analytics, alerts, services, host scores |
| `source_label` | the capture paths or interface name |

### Guidelines

- **Network sinks are opt-in by nature.** A sink only runs when the user names it, but keep it that way: never enable one from a default configuration.
- **Do not modify the finding.** Every sink receives the same object; use `dataclasses.replace()` to make a changed copy.
- **Be robust.** An exception in `write()` is counted as a `sink:<name>` error and the run continues, but the finding is lost for your sink.

### Per-packet sinks

A sink that needs the packets themselves (like the built-in `evidence` output) sets `wants_packets = True` and implements `on_packet(pkt)`:

```python
from netcreds_ng.engine.decode import Packet

class FrameCounter(SinkPlugin):
    name = "framecount"
    wants_packets = True

    def open(self, ctx): self.n = 0
    def on_packet(self, pkt: Packet) -> None: self.n += 1     # every decoded TCP/UDP packet
    def write(self, finding): pass
    def close(self, stats): print(self.n, "packets")
```

`on_packet` is called for every decoded TCP or UDP packet before the protocol plugins see it. `pkt.frame` is the `RawFrame` (bytes, link type, timestamp, frame number); `pkt.src`, `pkt.sport`, `pkt.dst`, `pkt.dport`, `pkt.payload` are decoded fields. Such a sink makes the run sequential: `-j` is ignored.
