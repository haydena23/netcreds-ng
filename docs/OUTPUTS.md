# Outputs and integrations

Every output receives the same findings, after de-duplication and enrichment (analytics, detection). Outputs can be combined freely. Secrets are written in full unless `--mask` is given. The network outputs (webhook, syslog) mask secrets by default, and none of them run unless you request them.

| Option | Format | Masking |
| --- | --- | --- |
| `--jsonl PATH` | one JSON object per finding | `--mask` |
| `--csv PATH` | CSV with a header row | `--mask` |
| `--log PATH` | human-readable lines | `--mask` |
| `--sqlite PATH` | `findings` table | `--mask` |
| `--cef PATH` | ArcSight CEF lines | `--mask` |
| `--html PATH` | self-contained audit report | masked unless `--option html.include_secrets=true` |
| `--evidence PATH` | pcapng of the packets behind each finding | never (raw packets) |
| `--webhook URL` | JSON (or chat message) over HTTPS | masked unless `--option webhook.include_secrets=true` |
| `--syslog URL` | RFC 5424 syslog, CEF or JSON body | masked unless `--option syslog.include_secrets=true` |

`-` as PATH writes to stdout (jsonl/csv/log/cef). File outputs append; the HTML report and the evidence file are rewritten at the end of the run.

## Finding fields (JSONL, webhook generic format, syslog JSON)

Empty fields are omitted.

| Field | Type | Meaning |
| --- | --- | --- |
| `timestamp` | string | ISO 8601 UTC time the packet was captured |
| `protocol` | string | `FTP`, `HTTP`, `HTTP/2`, `SMTP`, `Kerberos`, `MSSQL`, `Cleartext` (generic detectors)… |
| `kind` | string | `credential`, `username`, `password`, `auth_event`, `token`, `api_key`, `cookie`, `community`, `auth_result`, `url`, `post`, `search`, `info`, `alert` |
| `risk` | string | `info`, `low`, `medium`, `high` |
| `src`, `dst` | string | `ip:port` (`[ipv6]:port`). Alerts that span many connections carry the client IP only |
| `username`, `domain` | string | account involved |
| `secret` | string | the cleartext secret as it crossed the wire (masked with `--mask`) |
| `value` | string | description or display value (URL, auth summary, alert text) |
| `display` | string | the one-line value shown on screen |
| `tags` | list | e.g. `cleartext`, `weak-password`, `password-reuse`, `nonstandard-port`, `tls-decrypted`, `heuristic`, `brute-force` |
| `frame` | int | frame number in the capture file (Wireshark numbering) |
| `plugin` | string | plugin that produced the finding |
| `confidence` | float | 1.0 unless heuristic |
| `extra` | object | protocol-specific details, e.g. `mechanism`, `database`, `nas_ip`, `secret_fingerprint` (per-run HMAC; for reuse correlation within one run only) |

`kind = auth_result` findings describe a login outcome: `value` reads like `login failed`. Consumers can use the same rule as `Finding.outcome`: `extra.outcome` if present; otherwise "fail", "reject" or "denied" means failure, and "succe" or "accept" means success.

`kind = alert` findings come from the detection enricher. `extra.detection` is `brute-force`, `password-spraying`, `targeted-account` or `login-after-failures`. `extra.attempts` is the attempt count in the window, `extra.frames` lists the frames of the attempts, and `extra.users` / `extra.clients` list who was involved.

## CSV columns

`timestamp, protocol, kind, risk, src, dst, username, domain, secret, value, tags, frame, plugin` (tags joined with `;`).

## CEF mapping

`CEF:0|netcreds-ng|netcreds-ng|<version>|<kind>|<protocol> <kind>|<severity>|…`. Severity is info=1, low=3, medium=6, high=9. Extensions:

| CEF key | Source |
| --- | --- |
| `rt` | capture time, ms since epoch |
| `src` / `spt` / `dst` / `dpt` | endpoints |
| `app` | protocol |
| `suser` | `domain\user` |
| `msg` | display value (masked when masking applies) |
| `cs1` (label `tags`) | tags, comma separated |
| `cs2` (label `plugin`) | plugin |
| `cn1` (label `frame`) | frame number |

## Syslog

`--syslog udp://host:514` or `tcp://host:514`. Messages are RFC 5424 with facility local0, a severity from the risk (info=6, low=5, medium=4, high=2), APP-NAME `netcreds-ng`, and MSGID set to the finding kind. TCP uses octet-counting framing (RFC 6587). Options: `format` (`cef` or `json`), `min_risk` (default `low`), `include_secrets`, `hostname`.

## Webhooks

`--webhook URL` posts batches (`batch`, default 20) of findings at `min_risk` (default `medium`) or above. `--webhook-format slack|teams|discord` (or `--option webhook.format=…`) sends a readable chat message to an incoming-webhook URL instead of the JSON findings.

## Evidence pcapng

`--evidence proof.pcapng` writes the packets of every connection that produced a finding: the recent packets before it, and the next 16 of that connection. That way the server's answer is included. Each packet carries a comment such as `netcreds-ng: original frame 4; FTP credential for alice`. Comments never contain the secret itself; the packet bytes do, because that is the evidence. Options: `frames_per_flow` (64), `bytes_per_flow` (512 KiB), `after` (16), `max_flows` (20000). Not available together with `-j`: per-packet outputs force sequential analysis.

## HTML report

A single file with no external resources and print-friendly styling (use the browser's "Save as PDF" for a PDF). It contains:
- an executive summary written from the numbers in the report;
- an activity timeline;
- alerts;
- the service inventory (which servers exposed cleartext secrets, to how many clients, with login successes/failures);
- accounts seen on several services;
- host exposure with a 0–100 score;
- every finding, and any analysis warnings.

## Splunk

`inputs.conf`, monitoring a JSONL output:

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

Example search, failed logins and alerts per server:

```
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

Ship the JSONL with Filebeat (`filestream` input with an `ndjson` parser) or Elastic Agent, setting `pipeline: netcreds-ng`. The `remove` processor shows one way to keep secrets out of the index even when the file holds them. Simpler still, write the file with `--mask`.
