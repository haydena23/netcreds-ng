# Command line

```text
netcreds-ng [-h] [-p PATH] [-i IFACE] [-f HOSTS] [-F FILE] [--bpf EXPR] [--attach DB] [-v] [-q] [--tui] [--no-tui] [--mask]
            [--no-browsing] [--min-risk {info,low,medium,high}] [--jsonl PATH] [--csv PATH] [--log PATH] [--sqlite PATH]
            [--html PATH] [--evidence PATH] [--cef PATH] [--summary-json PATH] [--webhook URL]
            [--webhook-format {generic,slack,teams,discord}]
            [--syslog URL] [-o FORMAT:PATH] [--legacy] [-j N] [--tls-keylog FILE] [--dedup {off,run,persistent}]
            [--dedup-db PATH] [--enable PLUGINS] [--disable PLUGINS] [--option PLUGIN.KEY=VALUE] [--plugin-dir DIR]
            [--config FILE] [--strict] [--strict-heuristics] [--list-plugins] [--list-interfaces] [--debug] [--version]
```

The program can also be run as `python -m netcreds_ng`.

**Mode selection.** `--list-interfaces` and `--list-plugins` print and exit. Otherwise `--legacy` selects [legacy mode](../guide/legacy.md). Otherwise `--attach` opens the dashboard on a findings database, `-p` analyses capture files, and without either netcreds-ng captures live on `-i` or the auto-detected interface.

## Sources

### `-p`, `--pcap PATH`

A capture file (pcap or pcapng) or a directory. Repeatable. Directories contribute their `.pcap`, `.pcapng`, `.cap` and `.dmp` files, sorted by name, not recursively. Files are analysed in the order given; a connection can continue from one file into the next. A missing file stops the run with exit code 1 before analysis starts. See [Analysing captures](../guide/analysing-captures.md).

### `-i`, `--interface IFACE`

Live capture interface. Without `-p` and without `-i`, the interface carrying the default route is used; if that cannot be determined, the first active interface with a routable IPv4 address (physical adapters first). Needs permission to capture: root or `CAP_NET_RAW` on Linux/macOS; on Windows only if Npcap is set to "administrators only". See [Live capture](../guide/live-capture.md).

### `-f`, `--filterip`, `--filter HOSTS`

Comma-separated IP addresses whose traffic is ignored (either endpoint). Applies to capture files and live capture; in live capture it also becomes a BPF filter. In legacy mode only the first host is used, and only for live capture.

### `-F`, `--filterfile FILE`

A file of IP addresses to ignore, one per line. Empty lines and lines starting with `#` are skipped. Combined with `-f`.

### `--bpf EXPR`

An additional BPF filter for live capture, combined with the `-f` hosts using `and`. Ignored for capture files.

### `--attach DB`

Open the [dashboard](../guide/dashboard.md#background-capture-and-attach) on a findings database written by `--sqlite`, instead of analysing traffic. While another netcreds-ng run is still writing to the database (for example a headless live capture), the dashboard follows it and shows new findings within about a second. Host, service and account analytics are rebuilt from the stored findings. Cannot be combined with `-p`, `-i`, `--legacy`, `--no-tui`, outputs or `--summary-json`. A missing file, or a file that is not a netcreds-ng database, exits with code 1.

## Output

### `-v`, `--verbose`

Do not truncate long values on screen. Without it, values are cut at 100 characters on the console and 80 in the dashboard.

### `-q`, `--quiet`

No console output, neither findings nor the summary. Outputs are still written. In live mode, `-q` also selects plain mode instead of the dashboard.

### `--tui` / `--no-tui`

Force the interactive [dashboard](../guide/dashboard.md) on or off. Default: on for live capture when standard output is a terminal and `-q` is not given; off for capture files.

### `--mask`

Mask secrets on screen and in every output that writes secrets (`jsonl`, `csv`, `log`, `sqlite`, `cef`). The HTML report, webhook and syslog outputs mask by default anyway. Does not apply to `--evidence`. See [masking secrets](../guide/analysing-captures.md#masking-secrets).

### `--no-browsing`

Hide `url`, `post` and `search` findings on the console. Outputs still receive them.

### `--min-risk {info,low,medium,high}`

Lowest risk shown on the console. Default `info`. Outputs still receive every finding.

### File outputs

| Option | Writes | Details |
| --- | --- | --- |
| `--jsonl PATH` | one JSON object per finding (appends) | [JSON Lines](outputs.md#json-lines) |
| `--csv PATH` | CSV with a header row (appends) | [CSV](outputs.md#csv) |
| `--log PATH` | human-readable lines (appends) | [Log](outputs.md#log) |
| `--sqlite PATH` | a SQLite database (adds a run) | [SQLite](outputs.md#sqlite) |
| `--html PATH` | a self-contained HTML report (rewritten at the end of the run) | [HTML report](outputs.md#html-report) |
| `--evidence PATH` | a pcapng file of the packets behind each finding (rewritten at the end) | [Evidence pcapng](outputs.md#evidence-pcapng) |
| `--cef PATH` | ArcSight CEF lines (appends) | [CEF](outputs.md#cef) |

`-` as PATH writes to standard output for `jsonl`, `csv`, `log` and `cef`. Combine it with `-q` to get clean machine-readable output on stdout.

### `--summary-json PATH`

Writes the run summary as one JSON document at the end of the run: every counter, the [capture health](../guide/analysing-captures.md#capture-health) assessment, and the analytics (hosts, accounts, alerts). It contains no secrets. `-` writes to standard output; add `-q` so the console summary does not mix with the JSON. It is written in plain console mode (`--no-tui`, `-q`, or file analysis without `--tui`), not from the dashboard, and cannot be combined with `--legacy`. Format: [run summary JSON](outputs.md#run-summary-json).

### `--webhook URL`

POST findings to an `http://` or `https://` URL, in batches. Medium risk and above by default; secrets masked. Opt-in: nothing is sent unless you give this option or configure it. See [Webhooks](outputs.md#webhooks).

### `--webhook-format {generic,slack,teams,discord}`

Payload style for `--webhook`. `generic` (default) posts the findings as JSON; the others post a chat message for an incoming-webhook URL.

### `--syslog URL`

Send findings to a syslog collector, `udp://host[:port]` or `tcp://host[:port]` (default port 514). RFC 5424 messages with a CEF body (or JSON with `--option syslog.format=json`); low risk and above; secrets masked. See [Syslog](outputs.md#syslog).

### `-o`, `--output FORMAT:PATH`

A generic output: any output plugin by name, including third-party ones. Repeatable. `-o jsonl:out.jsonl` is the same as `--jsonl out.jsonl`. An unknown format is a usage error (exit 2).

### `--legacy`

Reproduce the original net-creds output (stdout and `./credentials.txt`) exactly. See [Legacy mode](../guide/legacy.md).

## Analysis

### `-j`, `--jobs N`

Analyse up to N capture files in parallel worker processes. Default 1. Output is published in file order. Ignored when only one file is given, for live capture, and when `--evidence` (or another per-packet output) is active. Connections do not continue across files in parallel mode. See [parallel analysis](../guide/analysing-captures.md#parallel-analysis).

### `--tls-keylog FILE`

Decrypt TLS sessions whose secrets are in this NSS key-log file (`SSLKEYLOGFILE` format). Needs the `[tls]` extra. A missing file is an error (exit 1). See [TLS decryption](../guide/tls-decryption.md).

### `--dedup {off,run,persistent}`

Duplicate suppression. Default `run` (or the configuration file's `dedup`). See [de-duplication](../getting-started/concepts.md#de-duplication).

### `--dedup-db PATH`

State file for `--dedup persistent`. Default `netcreds-ng-state.sqlite3` in the current directory.

### `--enable PLUGINS`

Comma-separated plugin names to enable. Repeatable. `all` enables every plugin, including opt-in ones. It does not disable the others.

### `--disable PLUGINS`

Comma-separated plugin names to disable. Repeatable. Applies to protocol plugins and enrichers.

### `--option PLUGIN.KEY=VALUE`

Set a plugin, enricher or output option. Repeatable. The value is parsed as TOML when possible (`10`, `true`, `"text"`, `[1, 2]`), otherwise taken as a string. See [Plugin options](plugin-options.md).

### `--plugin-dir DIR`

Load `*.py` plugins from a directory. Repeatable. A missing directory is reported as a plugin load error.

### `--config FILE`

Read this TOML configuration file instead of searching for one. See [Configuration](../guide/configuration.md).

### `--strict`

Exit with code 3 if any plugin error or capture-source problem occurred.

### `--strict-heuristics`

Fewer false positives: sets `telnet.strict=true` (Telnet logins need a Telnet port or real option negotiation) and disables the `keyvalue` plugin.

## Information

### `--list-plugins`

Print every plugin with its kind, default state (`on`, `opt-in`, or `output`), source (`builtin`, `entry-point:<distribution>` or `file:<path>`) and description, then any plugin load errors. Respects `--plugin-dir` and the configuration file's `dirs`.

### `--list-interfaces`

Print network interfaces with their state and addresses. The default capture interface is marked `*`.

### `--debug`

Debug logging to standard error, including plugin tracebacks. Treat debug logs from real captures as sensitive: an exception message can quote the data that caused it.

### `--version`

Print the version and exit.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | error: capture file not found; unreadable configuration or filter file; an output, key log or capture could not be opened; every input unreadable; live capture without privileges or without an interface |
| `2` | usage error (bad option or value, malformed `--option` or `-o`, unknown output format) |
| `3` | `--strict` and a plugin or source warning occurred |
| `130` | interrupted (Ctrl+C) during file analysis |

Stopping a live capture with Ctrl+C is the normal way to end it and exits with 0 (or 3 with `--strict` and warnings).
