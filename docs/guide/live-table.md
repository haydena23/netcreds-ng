# Live table (`--tui`)

By default netcreds-ng prints one line per finding, like the original net-creds. With `--tui` it shows the same findings in a table instead, which you can pause and filter:

```bash
sudo netcreds-ng -i eth0 --tui
netcreds-ng -p capture.pcapng --tui
```

```text
┌ netcreds-ng ─ live: eth0 ────────────────────────────────────────────── 14:02:11 ┐
│  RUNNING   frames 18,204  flows 412  findings 37  high 9  plugins 23             │  status bar
│ Time     Risk  Protocol What        Source → Destination        Detail     Tags  │
│ 14:01:55 HIGH  FTP      credential  192.0.2.66:51000 → ...:21   alice:...  ...   │  findings
│ ...                                                                              │
├──────────────────────────────────────────────────────────────────────────────────┤
│   timestamp: 2026-10-08T14:01:55.060000+00:00                                    │  every field of the
│    protocol: FTP ...                                                             │  highlighted finding
└──────────────────────────────────────────────────────────────────────────────────┘
  q Quit  p Pause/Resume  / Filter
```

- The **status bar** shows the state (`RUNNING`, `PAUSED`, `DONE`, `STOPPED`), frames, flows, findings, the high-risk count, how many protocol plugins are running, warnings, and packets dropped during live capture.
- The **table** follows new findings while the cursor is on the last row. Move up to read and it stays where you are; go back to the last row to follow again.
- The **detail pane** shows every field of the highlighted finding, including `extra`.

Plugin selection (`-P`, `--enable`, `--disable`) and every output option work the same as without `--tui`. `-v` stops values being cut at 80 characters. The end-of-run summary and `--summary-json` are only produced without `--tui`.

## Keys

| Key | Action |
| --- | --- |
| ++slash++ | open the filter box |
| ++escape++ | clear the filter |
| ++p++ | pause or resume analysis |
| ++q++ | quit |

Pausing stops reading packets. During live capture, packets keep arriving in the capture queue while paused, and are dropped once it is full.

## Filter language

Press ++slash++ and type; the table updates as you type. A filter is a list of space-separated terms, and a finding must match **all** of them.

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

Prefix any term with `-` to negate it. An invalid term (an unknown risk, a non-numeric port) is shown under the filter box, and the previous filter stays active.

| Filter | Shows |
| --- | --- |
| `risk:medium+ -tag:heuristic` | medium and high findings, without heuristic matches |
| `kind:credential tag:cleartext` | cleartext credentials only |
| `kind:alert` | behavioural alerts |
| `host:10.1. -proto:http` | everything involving 10.1.x.x except HTTP |

The same language is available in Python as `netcreds_ng.tui.filters.parse_filter`.
