# Outputs and integrations

Every output receives the same findings, after de-duplication and enrichment (analytics, detection). Outputs can be combined freely. Network outputs (webhook, syslog) never run unless you request them.

| Option | Format | Writing | Secrets |
| --- | --- | --- | --- |
| `--jsonl PATH` | one JSON object per finding | appends, flushed per finding | full unless `--mask` |
| `--csv PATH` | CSV with a header row | appends; header only for a new or empty file | full unless `--mask` |
| `--log PATH` | human-readable lines | appends | full unless `--mask` |
| `--sqlite PATH` | SQLite `runs` and `findings` tables | adds one run | full unless `--mask` |
| `--cef PATH` | ArcSight CEF lines | appends | full unless `--mask` |
| `--html PATH` | self-contained audit report | rewritten at the end of the run | masked unless `html.include_secrets=true` |
| `--evidence PATH` | pcapng of the packets behind each finding | rewritten at the end of the run | never masked (raw packets) |
| `--webhook URL` | JSON or chat message over HTTP(S) | batched | masked unless `webhook.include_secrets=true` |
| `--syslog URL` | RFC 5424 syslog, CEF or JSON body | per finding | masked unless `syslog.include_secrets=true` |
| `--summary-json PATH` | run summary: counters, capture health, analytics | written at the end of the run | none included |

`-` as PATH writes to standard output for `jsonl`, `csv`, `log` and `cef`. Any output, including third-party ones, can also be selected with `-o FORMAT:PATH`. Output options are set with `--option <output>.<key>=<value>` or in an `[output.<name>]` table; see [plugin options](plugin-options.md#outputs).

An output that fails while writing (a full disk, an unreachable webhook) is counted as a `sink:<name>` error in the summary; the other outputs carry on.

## JSON Lines

One JSON object per line, keys sorted, UTF-8 (non-ASCII characters are kept, not escaped). Empty fields are omitted. `timestamp` is ISO 8601 UTC with microseconds.

```json
{"confidence": 1.0, "display": "fakeuser:FakePass-123", "dst": "198.51.100.20:21", "extra": {"secret_fingerprint": "6c24b7bbea132a77"}, "frame": 7, "kind": "credential", "plugin": "ftp", "protocol": "FTP", "risk": "high", "secret": "FakePass-123", "src": "192.0.2.10:50000", "tags": ["cleartext"], "timestamp": "2023-11-14T22:13:20.060000+00:00", "username": "fakeuser"}
{"confidence": 1.0, "display": "login succeeded", "dst": "198.51.100.20:21", "extra": {"reply": "230 Login successful."}, "frame": 8, "kind": "auth_result", "plugin": "ftp", "protocol": "FTP", "risk": "info", "src": "192.0.2.10:50000", "timestamp": "2023-11-14T22:13:20.070000+00:00", "username": "fakeuser", "value": "login succeeded"}
```

The fields are described in the [findings reference](findings.md#fields). The same object, without the `timestamp` format difference, is used by the generic webhook format and the syslog JSON body.

## Run summary JSON

`--summary-json PATH` writes one JSON document per run (overwriting `PATH`). It holds no findings and no secrets; use `--jsonl` for findings. Top-level keys:

| Key | Content |
| --- | --- |
| `tool`, `version`, `source` | `"netcreds-ng"`, the version, and the capture files or interface |
| `stats` | every [run statistics](findings.md#run-statistics) counter; `first_ts`/`last_ts` as ISO 8601 UTC |
| `capture_health` | `status` (`good`, `degraded`, `poor`), `verdict` (one sentence), `issues` (each with `code`, `severity`, `rate`, `message`), and `metrics` (the counters and rates behind them) |
| `analytics` | risk counts, weak and reused password counts, exposed hosts with their accounts and protocols, alerts and host scores |
| `errors` | the detailed warning messages kept for the run (the engine keeps about 100) |

Abridged output for a public sample capture whose SPAN port copied most segments twice (Zeek's `tcp/ssh-dups.pcap`):

```json
{
  "capture_health": {
    "status": "good",
    "verdict": "good, with notes: 75% of TCP data segments were captured twice: ...",
    "issues": [{"code": "duplicates", "severity": "info", "rate": 0.75, "message": "..."}],
    "metrics": {"tcp_flows": 1, "tcp_duplicate_segments": 162, "duplicate_rate": 0.75, "...": "..."}
  },
  "stats": {"frames": 377, "tcp_flows": 1, "...": "..."},
  "tool": "netcreds-ng",
  "version": "2.0.0.dev0"
}
```

Issue codes: `one-sided`, `gaps`, `duplicates`, `truncated`, `dropped`, `no-handshake`. See [capture health](../guide/analysing-captures.md#capture-health) for their meaning and thresholds.

## CSV

Columns: `timestamp, protocol, kind, risk, src, dst, username, domain, secret, value, tags, frame, plugin`. Tags are joined with `;`. `confidence`, `display` and `extra` are not included; use JSON Lines or SQLite when you need them.

```text
timestamp,protocol,kind,risk,src,dst,username,domain,secret,value,tags,frame,plugin
2023-11-14T22:13:20.060000+00:00,FTP,credential,high,192.0.2.66:51000,198.51.100.21:21,admin,,guess-0,,cleartext,7,ftp
2023-11-14T22:13:20.070000+00:00,FTP,auth_result,info,192.0.2.66:51000,198.51.100.21:21,admin,,,login failed,,8,ftp
```

## Log

```text
2023-11-14T22:13:20.060000+00:00 [HIGH] [FTP] credential 192.0.2.10:50000 -> 198.51.100.20:21: fakeuser:FakePass-123 [cleartext]
```

## SQLite

```sql
CREATE TABLE runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL, frames INTEGER, findings INTEGER, duplicates INTEGER, errors INTEGER,
    source TEXT, updated REAL, finished REAL, stats TEXT
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id),
    ts REAL, frame INTEGER, protocol TEXT, kind TEXT, risk TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
    username TEXT, domain TEXT, secret TEXT, value TEXT,
    tags TEXT, plugin TEXT, extra TEXT
);
CREATE INDEX idx_findings_proto ON findings(protocol, kind);
CREATE INDEX idx_findings_hosts ON findings(src_ip, dst_ip);
```

- Each run adds a `runs` row. `started`, `updated` and `finished` are Unix times; `source` is the capture file(s) or interface; `stats` is a JSON object with every run counter (the same counters as `--summary-json`, with raw timestamps). `finished` stays empty while the run is going, or if it never ended cleanly.
- The database uses WAL journaling and is committed about once a second while findings arrive, together with the run's counters. Other programs, and [`--attach`](../guide/dashboard.md#background-capture-and-attach), can read it during the run. Option `commit_interval` (seconds, default 1) changes how often.
- Databases made by earlier versions get the four new `runs` columns added the next time a run writes to them.
- `ts` is the capture time as a Unix timestamp; `tags` is comma-separated; `extra` is a JSON object.
- The database can be reused across runs, which gives you a history to compare. Example queries are in the [recipes](../guide/recipes.md#keep-a-queryable-history).

## CEF

```text
CEF:0|netcreds-ng|netcreds-ng|<version>|<kind>|<protocol> <kind>|<severity>|<extensions>
```

Severity: info 1, low 3, medium 6, high 9. Extensions:

| CEF key | Source |
| --- | --- |
| `rt` | capture time, milliseconds since the epoch |
| `src`, `spt`, `dst`, `dpt` | endpoints |
| `app` | protocol |
| `suser` | `domain\user` or user |
| `msg` | the display value, at most 1023 characters (masked when masking applies) |
| `cs1` (label `tags`) | tags, comma separated |
| `cs2` (label `plugin`) | plugin |
| `cn1` (label `frame`) | frame number |

Header values escape `\` and `|`; extension values escape `\`, `=`, carriage returns and newlines.

## Syslog

```bash
netcreds-ng -i eth0 --no-tui --syslog udp://siem.example:514
netcreds-ng -i eth0 --no-tui --syslog tcp://siem.example:514 --option syslog.format=json
```

- RFC 5424 messages: facility local0, APP-NAME `netcreds-ng`, MSGID set to the finding kind, timestamp set to the capture time.
- Severity from the risk: info 6, low 5, medium 4, high 2.
- UDP sends one datagram per finding (at most 65,000 bytes). TCP uses octet-counting framing (RFC 6587).
- Body: a CEF event (default) or the JSON object (`format=json`).

| Option | Default | Meaning |
| --- | --- | --- |
| `format` | `cef` | `cef` or `json` body |
| `min_risk` | `low` | findings below this are not sent |
| `include_secrets` | `false` | send secrets unmasked |
| `hostname` | the local host name | HOSTNAME field |
| `timeout` | 5 | TCP connect timeout in seconds |

## Webhooks

```bash
netcreds-ng -p cap.pcap --webhook https://example.invalid/hooks/netcreds
netcreds-ng -i eth0 --no-tui --webhook https://hooks.slack.com/services/... --webhook-format slack
```

Findings at `min_risk` or above are collected and POSTed as JSON in batches of `batch`, and at the end of the run.

| `format` | Body |
| --- | --- |
| `generic` (default) | `{"source": "netcreds-ng", "findings": [ ...JSON objects... ]}` |
| `slack` | `{"text": "*netcreds-ng: N new findings*\n```...```"}` |
| `discord` | `{"content": "**netcreds-ng: N new findings**\n```...```"}` |
| `teams` | `{"text": "**netcreds-ng: N new findings**\n\n..."}` |

Chat formats send one line per finding: `[HIGH] FTP credential 192.0.2.10:50000 → 198.51.100.20:21: fakeuser:F**********3 (12)`.

| Option | Default | Meaning |
| --- | --- | --- |
| `format` | `generic` | `generic`, `slack`, `teams` or `discord` (also `--webhook-format`) |
| `min_risk` | `medium` | findings below this are not sent |
| `batch` | 20 | findings per request |
| `include_secrets` | `false` | send secrets unmasked |
| `timeout` | 5 | request timeout in seconds |

A failed delivery is reported as a `sink:webhook` error; that batch is not retried.

## HTML report

A single file with no external resources, readable offline and printable ("Save as PDF" in a browser gives a PDF). It follows the system light/dark preference. It contains:

- an executive summary written from the numbers in the report;
- headline counts by risk;
- an activity timeline;
- alerts;
- the service inventory: which servers exposed cleartext secrets, to how many clients, with login successes and failures;
- accounts seen on several services;
- host exposure with the 0–100 score;
- every finding, and any analysis warnings.

| Option | Default | Meaning |
| --- | --- | --- |
| `include_secrets` | `false` | show secrets unmasked |
| `include_browsing` | `false` | include URL, POST and search findings |

The dashboard's ++h++ key writes the same report, unmasked unless masking is on in the dashboard.

## Evidence pcapng

```bash
netcreds-ng -p capture.pcapng --evidence proof.pcapng
```

The evidence file holds the packets of every connection that produced a finding: the recent packets before the finding, and the next `after` packets of that connection, so the server's answer is included. Packets are written in their original order with their original timestamps and link types. Each carries a pcapng packet comment, visible in Wireshark (`pkt_comment` / *Packet comments*):

```text
netcreds-ng: original frame 7; FTP credential for admin
netcreds-ng: original frame 8; FTP auth result: login failed
```

Comments never contain the secret itself. The packet bytes do, because that is the evidence: treat the file like the capture it came from.

| Option | Default | Meaning |
| --- | --- | --- |
| `frames_per_flow` | 64 | recent packets kept per connection |
| `bytes_per_flow` | 524288 | recent bytes kept per connection |
| `after` | 16 | packets selected after each finding |
| `max_flows` | 20000 | connections buffered at once |

When a finding's own frame has already left the rolling buffer of a very long connection, the most recent packet is selected and its comment says the trigger frame was not retained.

The evidence output needs every packet in one process, so it makes a run with `-j` sequential.

## Splunk

`inputs.conf`, monitoring a JSON Lines output:

```ini
[monitor:///var/log/netcreds-ng/findings.jsonl]
sourcetype = netcreds:finding
index = security
```

`props.conf`:

```ini
[netcreds:finding]
KV_MODE = json
TIME_PREFIX = "timestamp":\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%:z
MAX_TIMESTAMP_LOOKAHEAD = 40
SHOULD_LINEMERGE = false
```

Failed logins and alerts per server:

```text
index=security sourcetype=netcreds:finding (kind=auth_result OR kind=alert)
| stats count(eval(kind="alert")) AS alerts count(eval(like(value,"%fail%"))) AS failures BY dst protocol
```

## Elastic

An ingest pipeline that maps findings onto ECS fields:

```json
PUT _ingest/pipeline/netcreds-ng
{
  "processors": [
    { "date":   { "field": "timestamp", "formats": ["ISO8601"] } },
    { "grok":   { "field": "src", "patterns": ["\\[?%{IP:source.ip}\\]?(?::%{NUMBER:source.port:int})?"] } },
    { "grok":   { "field": "dst", "patterns": ["\\[?%{IP:destination.ip}\\]?(?::%{NUMBER:destination.port:int})?"] } },
    { "rename": { "field": "username", "target_field": "user.name", "ignore_missing": true } },
    { "rename": { "field": "protocol", "target_field": "network.application" } },
    { "set":    { "field": "event.kind", "value": "alert", "if": "ctx.kind == 'alert'" } },
    { "set":    { "field": "event.category", "value": ["authentication"] } },
    { "remove": { "field": "secret", "ignore_missing": true, "if": "ctx.tags != null && !ctx.tags.contains('keep-secret')" } }
  ]
}
```

Ship the JSON Lines file with Filebeat (a `filestream` input with an `ndjson` parser) or Elastic Agent, setting `pipeline: netcreds-ng`. The `remove` processor shows one way to keep secrets out of the index even when the file holds them. Simpler still, write the file with `--mask`.
