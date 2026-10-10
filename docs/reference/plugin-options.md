# Plugin options

Options are set per plugin, either on the command line or in the configuration file:

```bash
netcreds-ng -p cap.pcap --option http.cookies=all --option detection.window=600
```

```toml
[plugins.http]
cookies = "all"

[plugins.detection]
window = 600

[output.webhook]          # outputs: [output.<name>] or [plugins.<name>]
min_risk = "high"
```

Values given with `--option` are parsed as TOML (`10`, `true`, `"text"`); anything else is a string. See [Configuration](../guide/configuration.md).

## Protocol plugins

### http and http2

| Option | Default | Values | Effect |
| --- | --- | --- | --- |
| `cookies` | `session` | `session`, `all`, `off` | which cookies to report: those whose names look like session identifiers (`sess`, `sid`, `token`, `auth`, `jwt`, `login`, `remember`, `PHPSESSID`, `JSESSIONID`, `ASP.NET`...), every cookie, or none |
| `urls` | `true` | bool | report request URLs (`url` findings) |

The options are read separately by each plugin: set `http.cookies` and `http2.cookies` to change both.

### telnet

| Option | Default | Effect |
| --- | --- | --- |
| `strict` | `false` | only honour login prompts on a Telnet port (23, 2323) or after real Telnet option negotiation. `--strict-heuristics` sets it |

The other built-in protocol plugins have no options.

## Enrichers

### detection

| Option | Default | Effect |
| --- | --- | --- |
| `window` | 300 | sliding window in seconds (capture time) |
| `bruteforce` | 5 | failures from one client against one service that raise `brute-force` |
| `spray` | 5 | distinct accounts failing from one client on one service that raise `password-spraying` |
| `targeted` | 5 | distinct clients failing for one account on one service that raise `targeted-account` |

See [alerts and analytics](../guide/detections.md).

### analytics

No options. Disable it with `--disable analytics`.

## Outputs

| Output | Option | Default | Effect |
| --- | --- | --- | --- |
| `webhook` | `format` | `generic` | `generic`, `slack`, `teams`, `discord` |
| `webhook` | `min_risk` | `medium` | lowest risk sent |
| `webhook` | `batch` | 20 | findings per request |
| `webhook` | `timeout` | 5 | seconds |
| `syslog` | `format` | `cef` | `cef` or `json` body |
| `syslog` | `min_risk` | `low` | lowest risk sent |
| `syslog` | `hostname` | local host name | RFC 5424 HOSTNAME |
| `syslog` | `timeout` | 5 | TCP connect timeout, seconds |
| `evidence` | `frames_per_flow` | 64 | recent packets kept per connection |
| `evidence` | `bytes_per_flow` | 524288 | recent bytes kept per connection |
| `evidence` | `after` | 16 | packets selected after each finding |
| `evidence` | `max_flows` | 20000 | connections buffered at once |

`jsonl`, `csv`, `log` and `cef` have no options. `sqlite` takes `commit_interval` (seconds between commits while findings arrive, default 1).
