# Interactive dashboard

The dashboard is a terminal UI built with [Textual](https://textual.textualize.io/). It opens by default for live capture in a terminal, and with `--tui` for capture files:

```bash
netcreds-ng -p capture.pcapng --tui
sudo netcreds-ng -i eth0                 # live: the dashboard is the default in a terminal
sudo netcreds-ng -i eth0 --no-tui        # live, plain lines instead
```

Outputs given on the command line (`--jsonl`, `--html`, ...) are written as usual while the dashboard runs.

## Layout

```text
┌ netcreds-ng ─ live: eth0 ─────────────────────────────────────────────── 14:02:11 ┐
│  RUNNING   frames 18,204 (1,312/s)  flows 412  findings 37  high 9  alerts 1  ... │  status bar
│ ▁▂▂▃▅▇▆▅▃▂▁▁▂▃▃▂                                                                  │  packets/s sparkline
│ scope: host 192.0.2.66  (Esc to clear)                                            │  drill-down scope
├────────────────────────────────────────────────────────────┬──────────────────────┤
│ Time     Risk  Protocol What   Source → Destination  Detail│ Exposure analytics   │
│ 14:01:55 HIGH  FTP      cred.. 192.0.2.66:51000 → ...  ... │ high       9         │
│ ...                                                        │ ...                  │
├────────────────────────────────────────────────────────────┤ Alerts               │
│  timestamp: 2026-10-08T14:01:55.060000+00:00               │ Most exposed hosts   │  side panel (a)
│   protocol: FTP                                            │                      │
│   ...                                                      │                      │  detail pane
└────────────────────────────────────────────────────────────┴──────────────────────┘
  q Quit  p Pause/Resume  / Filter  s Session  o Src host  d Dst host  f Saved filters ...
```

- **Status bar**: state (`RUNNING`, `PAUSED`, `DONE`, `STOPPED`), frames and packets per second, flows, findings, high-risk count, alerts, suppressed duplicates, the current minimum risk, masking and browsing state, warnings, and dropped packets during live capture.
- **Sparkline**: packets per second over the last minute.
- **Findings table**: one row per finding, in arrival order.
- **Detail pane**: every field of the highlighted finding, including `extra`.
- **Side panel** (toggle with `a`): risk counts, weak and reused passwords, recent alerts, hosts ranked by exposure score, and warnings.

Alerts also pop up as notifications.

## Keys

| Key | Action |
| --- | --- |
| ++slash++ | open the filter box |
| ++escape++ | clear the filter and any drill-down scope |
| ++s++ | session view: every finding of the highlighted finding's connection |
| ++o++ | drill down to the highlighted finding's source host |
| ++d++ | drill down to its destination host |
| ++ctrl+s++ | save the current filter |
| ++f++ | cycle through saved filters |
| ++r++ | cycle the minimum risk: info → low → medium → high |
| ++b++ | show or hide browsing findings (URL, POST, search) |
| ++m++ | mask or unmask secrets |
| ++a++ | show or hide the analytics side panel |
| ++p++ | pause or resume analysis |
| ++e++ | export the visible findings to `netcreds-export-<timestamp>.jsonl` |
| ++h++ | write an HTML report to `netcreds-report-<timestamp>.html` |
| ++q++ | quit |

The dashboard starts with every finding visible: `--min-risk` and `--no-browsing` apply to plain console output only. `--mask` and `-v` do apply (values are cut at 80 characters without `-v`).

Pausing stops reading packets. During live capture, packets keep arriving in the capture queue while paused, and are dropped once it is full.

!!! warning "Export and report follow the mask toggle"

    `e` and `h` write secrets in full unless masking is on (`m` or `--mask`). This differs from `--html`, which masks by default. Turn masking on before exporting anything you intend to share.

## Filter language

Press ++slash++ and type. The table updates as you type. A filter is a list of space-separated terms; a finding must match **all** of them.

A term is either free text, matched case-insensitively against the protocol, kind, endpoints, user, domain, displayed value and tags, or `field:value`:

| Field | Matches when | Example |
| --- | --- | --- |
| `proto` (`protocol`) | the protocol contains the value | `proto:ftp` |
| `kind` | the kind equals the value (`auth_result` or `auth-result`) | `kind:credential` |
| `risk` | the risk equals the value, or is at least it with `+` | `risk:high`, `risk:medium+` |
| `host` | the source or destination IP contains the value | `host:192.0.2.` |
| `src` / `dst` | that endpoint (`ip:port`) contains the value | `dst::21` |
| `port` | the source or destination port equals the value | `port:3306` |
| `user` | the username (or `domain\user`) contains the value | `user:admin` |
| `tag` | any tag contains the value | `tag:weak` |
| `plugin` | the plugin name equals the value | `plugin:ldap` |

Prefix any term with `-` to negate it. Invalid terms (an unknown risk, a non-numeric port) are shown under the filter box and the previous filter stays active.

Examples:

| Filter | Shows |
| --- | --- |
| `risk:medium+ -tag:heuristic` | medium and high findings, without heuristic matches |
| `kind:credential tag:cleartext` | cleartext credentials only |
| `kind:alert` | behavioural alerts |
| `proto:kerberos tag:rc4` | Kerberos findings involving RC4 |
| `host:10.1. -proto:http` | everything involving 10.1.x.x except HTTP |
| `user:svc_` | every finding for accounts containing `svc_` |
| `dst::1433` | everything sent to port 1433 |

The same language is available in Python as `netcreds_ng.tui.filters.parse_filter`, which compiles an expression into a predicate over findings.

## Saved filters

++ctrl+s++ saves the current filter; ++f++ cycles through the saved ones. They are stored as a JSON list in `filters.json`, next to the [user configuration file](configuration.md#where-configuration-is-read-from):

| Platform | Location |
| --- | --- |
| Windows | `%APPDATA%\netcreds-ng\filters.json` |
| Linux/macOS | `~/.config/netcreds-ng/filters.json` (or `$XDG_CONFIG_HOME/netcreds-ng/filters.json`) |

You can edit the file by hand:

```json
[
  "risk:high -tag:heuristic",
  "kind:alert",
  "proto:kerberos tag:rc4"
]
```

## Drill-down

Highlight a finding and press:

- ++s++ to see the whole conversation it belongs to (both directions), for example a credential followed by its login result;
- ++o++ or ++d++ to see everything involving its source or destination host.

A scope line shows the active drill-down. Filters still apply inside a scope. ++escape++ clears both.
