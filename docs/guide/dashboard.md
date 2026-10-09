# Interactive dashboard

The dashboard is a terminal UI built with [Textual](https://textual.textualize.io/). It opens by default for live capture in a terminal, and with `--tui` for capture files:

```bash
netcreds-ng -p capture.pcapng --tui
sudo netcreds-ng -i eth0                 # live: the dashboard is the default in a terminal
sudo netcreds-ng -i eth0 --no-tui        # live, plain lines instead
netcreds-ng --attach run.db              # a findings database, followed while a capture writes to it
```

Outputs given on the command line (`--jsonl`, `--html`, ...) are written as usual while the dashboard runs.

## Layout

```text
┌ netcreds-ng ─ live: eth0 ─────────────────────────────────────────────── 14:02:11 ┐
│  RUNNING  follow  frames 18,204 (1,312/s)  flows 412  findings 37  high 9  ...    │  status bar
│ ▁▂▂▃▅▇▆▅▃▂▁▁▂▃▃▂                                                                  │  packets/s sparkline
│ scope: host 192.0.2.66  (Esc to clear)                                            │  drill-down scope
│ 1 Findings  2 Overview  3 Alerts  4 Hosts  5 Services  6 Accounts  7 Bookmarks ...│  tabs
├────────────────────────────────────────────────────────────┬──────────────────────┤
│ ★ Time     Risk  Protocol What   Source → Destination  ... │ Exposure analytics   │
│   14:01:55 HIGH  FTP      cred.. 192.0.2.66:51000 → ...    │ ...                  │  side panel (a)
├────────────────────────────────────────────────────────────┤                      │
│  why: Sent in cleartext · Weak password                    │                      │  detail pane
│  timestamp: 2026-10-08T14:01:55.060000+00:00 ...           │                      │
└────────────────────────────────────────────────────────────┴──────────────────────┘
  q Quit  ? Keys  / Filter  s Session  m Mask  t Follow  space Freeze  * Bookmark  n Note  e Export
```

- **Status bar**: state (`RUNNING`, `PAUSED`, `DONE`, `STOPPED`; with `--attach`, `ATTACHED` or `FOLLOWING`), the live-view mode (`follow`, or `FROZEN +N new`), frames and packets per second, flows, findings, high-risk count, alerts, suppressed duplicates, the current minimum risk, masking and browsing state, bookmarks, warnings, and dropped packets during live capture.
- **Sparkline**: packets per second over the last minute.
- **Tabs**: switch with the number keys `1` to `8`, or click them.
- **Findings table**: one row per finding, in arrival order. The first column marks bookmarks (★) and notes (✎).
- **Detail pane**: a one-line *why* (the reasons the finding matters, see below), then every field of the highlighted finding, including `extra`.
- **Side panel** (toggle with ++a++): risk counts, weak and reused passwords, recent alerts, hosts ranked by exposure score, and warnings.

Alerts also pop up as notifications. Press ++question++ for a panel listing every key of the current screen.

## Finding inspector

Press ++enter++ on a finding (in the findings, alerts or bookmarks table) to open it full-screen:

- **Why this matters**: what the risk level means, what this kind of finding means, and one entry per tag in plain language. Each entry says who set it: a protocol `plugin`, the `analytics` enricher (cleartext, weak or reused password), the `detection` enricher (alerts) or the `engine` (TLS decryption).
    - For a weak password it says which rule matched (shorter than 6 characters, or on the common-password list), without showing the password.
    - For an alert it states the rule that fired with its thresholds (for example "at least 5 failures from one client to one service within 300s"), the number of attempts, and the clients or accounts involved.
- **Context**: the service the finding was sent to (findings, clients, accounts, failed and successful logins, whether cleartext secrets were seen), the exposure score of the client and the server, and the other services the same account is used on.
- **Related findings**, strongest relation first:
    - the attempts behind an alert, or the alert a login result contributed to;
    - the rest of the same connection;
    - other findings with the same secret (matched by fingerprint, never by value);
    - the same account elsewhere.

    Press ++enter++ on one to open it; ++escape++ goes back one level.
- **Fields**: every field, as in the detail pane.

In the inspector, `*` bookmarks the finding, ++n++ adds a note, ++s++ returns to the findings table showing just this connection, and ++m++ toggles masking.

The explanations come from `netcreds_ng.explain`. Every tag a built-in plugin can set has an entry, and a test fails when a new tag has none. Tags from third-party plugins are shown with the plugin's name. The inspector explains why a finding matters; what to change is the job of the remediation milestone (M18).

## Analytics tabs

| Tab | Shows | ++enter++ on a row |
| --- | --- | --- |
| **1 Findings** | the findings table, detail pane and side panel | opens the inspector |
| **2 Overview** | findings per risk; a timeline per risk over capture time; the top reasons findings matter (tag counts); findings by protocol and by kind; the capture-health verdict | |
| **3 Alerts** | every behavioural alert with its detection, client, target and attempts | opens the inspector |
| **4 Hosts** | each host's exposure score (0-100), highest risk, findings as client and as server, protocols and accounts | shows that host's findings |
| **5 Services** | each server and protocol: cleartext secrets seen, findings, clients, accounts, failed and successful logins | shows that service's findings |
| **6 Accounts** | each account: highest risk, whether its secret was seen (and in cleartext), weak or reused password, services, clients, failed and successful logins, last seen | shows that account's findings |
| **7 Bookmarks** | bookmarked findings and their notes | opens the inspector |
| **8 Health** | the [capture-health](analysing-captures.md) verdict, issues and metrics, run counters and warnings; with `--attach`, the runs in the database | |

A drill-down from Hosts, Services or Accounts opens the findings tab with a scope; ++escape++ clears it and returns to the tab you came from. A tab refreshes about once a second while it is visible.

## Live view: follow and freeze

- ++t++ (**follow**) moves the cursor to each new finding as it arrives. It is on by default for live capture and `--attach`, and off for capture files.
- ++space++ (**freeze**) stops adding rows to the findings table while analysis continues, so the table stays still while you read. The status bar shows `FROZEN +N new`; press ++space++ again to catch up.
- ++p++ (**pause**) is different: it stops analysis itself. During live capture, packets keep arriving in the capture queue while paused, and are dropped once it is full. During live capture, freeze is usually what you want.

## Bookmarks and notes

`*` bookmarks the highlighted finding, or removes its bookmark. ++n++ adds or edits a one-line note; emptying a note keeps the bookmark. Both work in the findings, alerts and bookmarks tables and in the inspector.

Bookmarks last for the dashboard session. ++e++ exports them with the findings: a bookmarked finding gets `"bookmarked": true` in the JSONL, plus `"note"` when it has one.

## Background capture and attach

The dashboard runs in the terminal that started it. To keep a capture running without a terminal attached, run it headless into a SQLite database. Then open the dashboard on that database whenever you want, from any terminal, as often as you like:

```bash
# start a headless capture (in tmux/screen, as a service, or with nohup)
sudo netcreds-ng -i eth0 -q --sqlite /var/lib/netcreds/run.db

# later, from any terminal: no capture permissions needed, only read access to the file
netcreds-ng --attach /var/lib/netcreds/run.db
```

On Windows, start the capture in a hidden window:

```powershell
Start-Process netcreds-ng -ArgumentList '-i','Ethernet','-q','--sqlite','C:\netcreds\run.db' -WindowStyle Hidden
```

With `--attach`, the dashboard:

- loads every finding in the database (all runs), then follows it: findings the running capture adds appear within about a second;
- rebuilds the Hosts, Services and Accounts analytics and the exposure scores from the stored findings, with the same code a live run uses;
- shows the capture's counters and health from the database (the writer stores them about once a second, whenever findings arrive);
- shows `FOLLOWING` while a run in the database is still writing, and `ATTACHED` when none is;
- never writes to the database. Quitting the dashboard does not stop the capture.

If the capture used `--mask`, the database holds masked secrets, and so does the dashboard. Rows with a finding kind this version does not know are skipped and counted in the status bar.

## Keys

| Key | Action |
| --- | --- |
| ++enter++ | open the highlighted finding in the inspector, or drill down from an analytics row |
| `1` … `8` | switch tabs |
| ++slash++ | open the filter box |
| ++escape++ | clear the filter and any drill-down scope, and return to the tab the drill-down started from; in the inspector, go back |
| ++s++ | session view: every finding of the highlighted finding's connection |
| ++o++ | drill down to the highlighted finding's source host |
| ++d++ | drill down to its destination host |
| ++t++ | turn follow on or off |
| ++space++ | freeze or unfreeze the findings table |
| `*` | bookmark or un-bookmark the highlighted finding |
| ++n++ | add or edit a note on the highlighted finding |
| ++ctrl+s++ | save the current filter |
| ++f++ | cycle through saved filters |
| ++r++ | cycle the minimum risk: info → low → medium → high |
| ++b++ | show or hide browsing findings (URL, POST, search) |
| ++m++ | mask or unmask secrets |
| ++a++ | show or hide the analytics side panel |
| ++p++ | pause or resume analysis |
| ++e++ | export the visible findings to `netcreds-export-<timestamp>.jsonl` |
| ++h++ | write an HTML report to `netcreds-report-<timestamp>.html` |
| ++question++ | show every key of the current screen |
| ++q++ | quit (in the inspector: go back) |

The footer shows the most used keys; ++question++ lists the rest.

The dashboard starts with every finding visible: `--min-risk` and `--no-browsing` apply to plain console output only. `--mask` and `-v` do apply (values are cut at 80 characters without `-v`).

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

A scope line shows the active drill-down. Filters still apply inside a scope. ++escape++ clears both. The Hosts, Services and Accounts tabs drill down the same way with ++enter++ (see [Analytics tabs](#analytics-tabs)).
