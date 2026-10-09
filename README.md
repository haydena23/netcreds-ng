# netcreds-ng

**Find the credentials and weak authentication your network is exposing.**

netcreds-ng analyses packet captures or live traffic and reports every credential that crosses the wire in cleartext, along with authentication that is technically "protected" but weak (NTLMv1, Kerberos RC4/DES, SNMPv3 without authentication, RDP without NLA, VNC without a password...). It is a defensive auditing tool: it shows you the exposure so you can fix it. It does not crack anything.

It is the Python 3 successor of Dan McInerney's [net-creds](https://github.com/DanMcInerney/net-creds). It does everything the original did (verified by tests against the original's own output) and adds:

- **Real TCP stream reassembly.** Credentials split across packets, out-of-order or retransmitted segments, IPv4/IPv6 fragments (including jumbograms), any link type (Ethernet, VLAN, PPPoE, Linux cooked, loopback, raw IP). Streams picked up mid-connection, capture holes and connections with no handshake are handled.
- **23 protocol plugins.** Port-agnostic detection, with login success and failure tracking. They include HTTP/2, RADIUS, TACACS+, MSSQL, Oracle, RDP and cloud API keys.
- **TLS decryption** with a key-log file (`SSLKEYLOGFILE`) for traffic you are authorised to inspect, so plugins also see HTTPS, SMTPS, STARTTLS and the rest.
- **Behavioural alerts.** Brute force, password spraying, one account attacked from many hosts, and a success after a burst of failures.
- **Audit evidence.** A pcapng file holding exactly the packets behind each finding, annotated with Wireshark packet comments.
- **An interactive dashboard**, plus JSON Lines, CSV, SQLite, CEF, syslog, HTML audit reports (with an executive summary), and webhooks for Slack, Teams and Discord.
- **Risk analytics.** Weak passwords, password reuse across accounts and services, an inventory of services exposing cleartext secrets, and a 0–100 exposure score for each host.
- **A plugin system** for new protocols, outputs and enrichers.
- **Nothing dropped silently.** Parsing problems are counted and reported.

## Install

Requires Python 3.11 or newer.

```bash
pip install .          # from a checkout
pip install ".[tls]"   # plus TLS decryption (adds the 'cryptography' package)
pip install ".[dev]"   # plus test/lint tools
```

All dependencies are pure Python or ship prebuilt wheels: `rich`, `textual`, `scapy`, `psutil`, plus `cryptography` for `[tls]`. No compiler is needed.

Live capture needs a packet-capture driver: **Npcap** on Windows, libpcap (usually preinstalled) on Linux/macOS. It also needs root/administrator rights. Reading capture files needs neither.

## Usage

```bash
netcreds-ng -p capture.pcapng                      # analyse a capture file
netcreds-ng -p captures/ --html report.html        # a whole directory, plus an HTML audit report
netcreds-ng -p captures/ -j 4                      # analyse up to 4 files in parallel
netcreds-ng -p cap.pcap --jsonl findings.jsonl     # JSON Lines for a SIEM
netcreds-ng -p cap.pcap --evidence proof.pcapng    # the packets behind every finding
netcreds-ng -p cap.pcap --tls-keylog keys.log      # also look inside TLS sessions you hold keys for
netcreds-ng -p cap.pcap --tui                      # browse results interactively
sudo netcreds-ng -i eth0                           # live dashboard
sudo netcreds-ng -i eth0 --no-tui -f 10.0.0.5      # live, plain output, ignore a host
netcreds-ng --legacy -p cap.pcap                   # exactly what the original net-creds printed
netcreds-ng --list-plugins
netcreds-ng --list-interfaces
```

Useful options:

| Option | Effect |
| --- | --- |
| `-v` | do not truncate long values on screen |
| `--mask` | mask secrets on screen and in outputs (`P*******3 (9)`) |
| `--no-browsing` | hide URL / POST / search findings |
| `--min-risk high` | only show high-risk findings on screen |
| `--jsonl/--csv/--log/--sqlite/--html/--cef PATH` | outputs; repeat or combine freely; `-` writes to stdout |
| `--evidence PATH` | pcapng with the packets behind each finding (raw packets, so secrets included) |
| `--webhook URL` | POST findings (medium risk and up, secrets masked) to an endpoint |
| `--webhook-format slack\|teams\|discord` | send a chat message instead of the JSON findings |
| `--syslog udp://host:514` | send findings to a syslog collector as CEF (secrets masked); `tcp://` also works |
| `--tls-keylog FILE` | decrypt TLS sessions present in an NSS key-log file (needs `[tls]`) |
| `-j N`, `--jobs N` | analyse up to N capture files in parallel |
| `--dedup off\|run\|persistent` | duplicate suppression; `persistent` remembers across runs (`--dedup-db`) |
| `--enable/--disable PLUGINS` | choose plugins; `--enable all` includes opt-in ones |
| `--option http.cookies=all` | plugin options (e.g. `detection.bruteforce=10`) |
| `--strict-heuristics` | fewer false positives: Telnet needs a Telnet port or option negotiation; disables `keyvalue` |
| `--plugin-dir DIR` | load extra plugins from a directory |
| `--strict` | exit code 3 if any parsing or plugin warning occurred |

Network outputs (webhook, syslog) only run when you ask for them. Exit codes: `0` ok, `1` error, `2` usage, `3` warnings with `--strict`, `130` interrupted.

See [docs/OUTPUTS.md](docs/OUTPUTS.md) for the output formats, the JSON fields, and Splunk/Elastic examples.

### Interactive dashboard keys

| Key | Action |
| --- | --- |
| `/` | filter; supports `proto:ftp`, `risk:medium+`, `host:10.0.0.`, `user:admin`, `tag:weak`, `kind:alert`, and `-` to negate |
| `Esc` | clear the filter and any drill-down |
| `s` | session view: every finding of the selected connection |
| `o` / `d` | drill down to the selected finding's source / destination host |
| `Ctrl+S` / `f` | save the current filter / cycle through saved filters |
| `r` | cycle the minimum risk |
| `b` | hide browsing findings |
| `m` | mask secrets |
| `a` | analytics panel (alerts, host scores) |
| `p` | pause/resume |
| `e` | export visible findings (JSONL) |
| `h` | HTML report |
| `q` | quit |

The status bar shows packets per second, with a sparkline of recent throughput. Alerts pop up as notifications.

### Configuration file

Options can live in `./netcreds-ng.toml` or a user config file: `%APPDATA%\netcreds-ng\config.toml` on Windows, `~/.config/netcreds-ng/config.toml` elsewhere. Saved dashboard filters are kept next to it in `filters.json`.

```toml
[plugins]
enable = ["all"]
disable = ["keyvalue"]

[plugins.http]
cookies = "all"        # session | all | off

[plugins.detection]
bruteforce = 10        # failed logins from one client to one service...
window = 600           # ...within this many seconds

[output]
mask = true
html = "report.html"
jsonl = "findings.jsonl"
tls_keylog = "keys.log"

[output.webhook]
url = "https://hooks.slack.com/services/..."
format = "slack"
min_risk = "high"

[output.syslog]
url = "udp://siem.example:514"
```

## What it detects

| Protocol | Reported |
| --- | --- |
| FTP | USER/PASS/ACCT credentials, login result, non-standard ports |
| Telnet | usernames/passwords typed at login prompts (option negotiation and line editing handled), failed logins |
| SMTP / POP3 / IMAP | AUTH PLAIN/LOGIN, USER/PASS, IMAP LOGIN, XOAUTH2 tokens; CRAM-MD5/APOP/NTLM as auth events; results; STARTTLS |
| HTTP/1.x and HTTP/2 | Basic auth, form and JSON logins, bearer tokens, API keys, session cookies, JWTs, Digest/NTLM/Negotiate events, URLs, searches, POST bodies, login results |
| NTLM (SMB, LDAP, MSSQL, RPC, ... any TCP) | user, domain, workstation, NTLMv1 vs v2 |
| Kerberos (UDP/TCP) | principals, pre-auth encryption type (DES/RC4 flagged), accounts without pre-authentication, weak service tickets, failures |
| SNMP | v1/v2c community strings (default and write-access flagged), v3 users and security level |
| LDAP | simple-bind credentials, SASL PLAIN, other SASL mechanisms as events, results, StartTLS |
| MySQL / PostgreSQL | cleartext-password logins; native/caching_sha2/MD5/SCRAM as events; trust logins without a password; results; TLS |
| MSSQL (TDS) | SQL logins (the LOGIN7 password is only obfuscated, so it is reported as cleartext), Windows authentication events, encryption mode, results |
| Oracle (TNS) | connect descriptors (service, program, OS user), O5LOGON login events, refusals, native encryption, results |
| RADIUS | PAP/CHAP/MS-CHAP/EAP login events, EAP identities, NAS details, Accept/Reject |
| TACACS+ | unencrypted-mode credentials (ASCII and PAP), authorisation/accounting commands, results; encrypted sessions noted |
| RDP | `mstshash` cookie usernames; security negotiated (standard RDP security or TLS without NLA flagged) |
| Redis | AUTH / HELLO AUTH credentials and results |
| MQTT | CONNECT username/password, results |
| SIP | Digest auth events (user/realm), Basic credentials, results |
| VNC | sessions without authentication, VNC password auth, other security types, results |
| Cloud/API keys | AWS key pairs, GCP API keys and service accounts, Azure storage keys and SAS tokens, GitHub, Slack and Stripe tokens, PEM private keys, in any cleartext stream |
| Generic | `user=... pass=...` patterns in other cleartext protocols (low confidence) |

Challenge/response schemes are reported as *events*: who authenticated, to what, how weakly. The challenge/response material itself is never extracted.

**Alerts** come from the `detection` enricher, which watches login results across all protocols:
- `brute-force`: one client failing repeatedly against one service;
- `password-spraying`: one client failing across many accounts;
- `targeted-account`: one account failing from many clients;
- `login-after-failures`: a success after either of the first two.

Thresholds are plugin options.

## TLS decryption

Browsers, `curl`, and many TLS libraries write session secrets to the file named by the `SSLKEYLOGFILE` environment variable. Pass that file with `--tls-keylog`. netcreds-ng then decrypts the matching sessions, including after STARTTLS, and runs the normal plugins on the plaintext.

Supported versions are TLS 1.2 (AES-GCM, ChaCha20-Poly1305, AES-CBC) and TLS 1.3. Findings from decrypted traffic are tagged `tls-decrypted`. They are **not** counted as cleartext exposure, because they were encrypted on the wire. Sessions without keys are counted in the run summary and otherwise skipped.

## Legacy mode

`--legacy` reproduces the original net-creds byte for byte: the same coloured stdout lines and the same `credentials.txt` with its de-duplication. Use it if existing scripts parse the old output. Its parity with the original Python 2 tool is checked by the test suite against output recorded from the original.

## Plugins

Plugins are Python classes. They are loaded from installed packages (entry point group `netcreds_ng.plugins`), from `--plugin-dir`, or from the user plugin directory. See [docs/PLUGINS.md](docs/PLUGINS.md) for the API and a walkthrough, and [examples/netcreds-ng-example-plugin](examples/netcreds-ng-example-plugin) for an installable example.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
pytest                          # full suite (parity, protocols, engine, TLS, CLI, TUI, fuzzing)
ruff check src tests tools
mypy
python tools/bench.py --flows 20000   # throughput benchmark on a generated capture
python tools/gen_fixtures.py    # regenerate synthetic captures (deterministic)
python tools/make_goldens.py --py2 /path/to/python2 --original ../net-creds/net-creds.py
```

Synthetic fixtures use documentation IP ranges and obviously fake credentials. TLS tests create real TLS sessions in memory with Python's `ssl` module; no sockets are opened.

## Notes on output

- **What `--mask` covers.** Every secret field is masked. So are secret-looking values embedded in free text: form and JSON fields named like passwords or tokens, `api_key=` query parameters, and `Authorization`/`Cookie` header lines. It does not try to recognise secrets in arbitrary prose. It cannot mask the evidence pcapng, which holds the original packets.
- **Per-run fingerprints.** Password-reuse detection uses `secret_fingerprint`, a keyed hash with a fresh random key for each run. Fingerprints only correlate within a single run and cannot be used to test password guesses. As a result, JSONL/SQLite/HTML outputs differ between runs only in that field.
- **Capture gaps.** If packets are missing, a plugin never stitches the bytes on either side of the gap into a credential. It skips the damaged line, resynchronises on the next message (LDAP, Redis), or stops analysing that connection. Gap counts appear in the run summary.
- **Direction guessing.** When a connection has no handshake in the capture and both ports look alike, each plugin is offered both directions, and the first direction that produces a finding wins. The run summary counts these flows.
- **Parallel files.** With `-j`, each file is analysed on its own. Without it, a connection can continue from one file into the next (rotated captures).

## Responsible use

Only analyse traffic you are authorised to inspect. Captures, evidence files, key logs and outputs contain real credentials: store them securely, use `--mask` for reports you share, and delete what you no longer need.
