# netcreds-ng

**A blue-team network sniffer that prints the credentials crossing your wire.**

netcreds-ng watches live traffic or reads packet captures and reports every credential sent in cleartext, along with authentication that is technically "protected" but weak (NTLMv1, Kerberos RC4/DES, SNMPv3 without authentication, RDP without NLA, VNC without a password...). It shows you the exposure so you can fix it. It does not crack anything.

It is the Python 3 port of Dan McInerney's [net-creds](https://github.com/DanMcInerney/net-creds). It does everything the original did (verified by tests against the original's own output) and builds on it:

- **Plugin based.** Each protocol is a plugin. Run all of them, only the ones you name, or named sets of them (`databases`, `web`, `remote-access`, `legacy`, ...), and define your own sets. Third-party plugins install like any Python package.
- **23 protocol plugins.** Port-agnostic detection with login success and failure tracking, from the original's FTP, HTTP, mail, IRC, Telnet, SNMP, NTLM and Kerberos to LDAP, databases (MySQL, PostgreSQL, MSSQL, Oracle, Redis), RADIUS, TACACS+, RDP, VNC, SIP, MQTT, HTTP/2 and cloud API keys.
- **Real TCP stream reassembly.** Credentials split across packets, out-of-order or retransmitted segments, IPv4/IPv6 fragments, any link type (Ethernet, VLAN, PPPoE, Linux cooked, loopback, raw IP), streams picked up mid-connection.
- **TLS decryption** with a key-log file (`SSLKEYLOGFILE`) for traffic you are authorised to inspect.
- **Login-attack alerts**: brute force, password spraying, one account attacked from many hosts, and a success after a burst of failures. Weak and reused passwords are tagged.
- **Outputs** for keeping or forwarding what was seen: log, JSON Lines, CSV, SQLite, CEF, syslog, webhooks (Slack, Teams, Discord), and a pcapng of the packets behind each finding.
- **Nothing dropped silently.** Parsing problems are counted and reported, and the run summary says how complete the capture was.

## Install

Requires Python 3.11 or newer.

```bash
pip install .          # from a checkout
pip install ".[tls]"   # plus TLS decryption (adds the 'cryptography' package)
pip install ".[dev]"   # plus test/lint tools
```

All dependencies are pure Python or ship prebuilt wheels: `rich`, `textual`, `scapy`, `psutil`, plus `cryptography` for `[tls]`. No compiler is needed.

Live capture needs a packet-capture driver: **Npcap** on Windows, libpcap (usually preinstalled) on Linux/macOS. It also needs permission to capture: root (or `CAP_NET_RAW`) on Linux/macOS; on Windows a standard Npcap install lets any user capture. Reading capture files needs neither. Live capture is **beta** in 2.0.0: it has not yet been validated on a real network.

## Usage

```bash
sudo netcreds-ng                                   # sniff the default interface
sudo netcreds-ng -i eth0 -f 10.0.0.5               # a given interface, ignoring one host
sudo netcreds-ng -i eth0 --tui                     # live table you can pause and filter
netcreds-ng -p capture.pcapng                      # read a capture file
netcreds-ng -p captures/ -j 4                      # a directory, with 4 worker processes (default: one per core)
netcreds-ng -p cap.pcap --jsonl findings.jsonl     # also write JSON Lines
netcreds-ng -p cap.pcap --tls-keylog keys.log      # also look inside TLS sessions you hold keys for
netcreds-ng --legacy -p cap.pcap                   # exactly what the original net-creds printed
netcreds-ng --list-plugins                         # plugins and plugin sets
netcreds-ng --list-interfaces
```

### Choosing plugins

Without any selection, every built-in protocol plugin runs. To narrow it down:

```bash
netcreds-ng -i eth0 -P ftp,telnet                  # only these plugins
netcreds-ng -i eth0 -P databases                   # only a set: MySQL, PostgreSQL, MSSQL, Oracle, Redis
netcreds-ng -i eth0 -P legacy                      # what the original net-creds looked for
netcreds-ng -i eth0 -P databases,remote-access,ftp # mix plugins and sets
netcreds-ng -i eth0 --disable web,keyvalue         # everything except these
netcreds-ng -i eth0 -P all                         # everything, opt-in plugins included
```

| Set | Plugins |
| --- | --- |
| `legacy` | what the original net-creds covered: ftp, http, irc, kerberos, keyvalue, mail, ntlm, snmp, telnet |
| `web` | http, http2 |
| `email` | mail (SMTP, POP3, IMAP) |
| `file-transfer` | ftp |
| `remote-access` | telnet, vnc, rdp |
| `databases` | mysql, postgres, mssql, oracle, redis |
| `directory` | ntlm, kerberos, ldap |
| `aaa` | radius, tacacs |
| `network` | snmp, radius, tacacs |
| `chat`, `iot`, `voip` | irc; mqtt; sip |
| `generic` | keyvalue, secrets (pattern scanners over any cleartext stream) |
| `default`, `all` | every non-opt-in plugin; every plugin |

Define your own sets in the configuration file and use them anywhere a set name works:

```toml
[plugins]
select = ["office"]                 # like -P; -P on the command line overrides it

[sets]
office = ["email", "web", "ftp"]
```

`--list-plugins` shows every plugin, the sets it belongs to, and the resolved sets (yours included). Third-party plugins can join existing sets or declare new ones.

### Useful options

| Option | Effect |
| --- | --- |
| `-P`, `--plugins LIST` | run only these plugins and sets (comma separated) |
| `--enable` / `--disable LIST` | add / remove plugins or sets; `--disable detection` turns off alerts |
| `-v` | do not truncate long values on screen |
| `--no-browsing` | hide URL / POST / search findings on screen |
| `--min-risk high` | only show high-risk findings on screen |
| `--tui` | a live table with pause and filter instead of scrolling lines |
| `--jsonl/--csv/--log/--sqlite/--cef PATH` | outputs; repeat or combine freely; `-` writes to stdout |
| `--evidence PATH` | pcapng with the packets behind each finding |
| `--summary-json PATH` | end-of-run counters, capture health and analytics as JSON |
| `--webhook URL` | POST findings (medium risk and up) to an endpoint |
| `--webhook-format slack\|teams\|discord` | send a chat message instead of the JSON findings |
| `--syslog udp://host:514` | send findings to a syslog collector as CEF; `tcp://` also works |
| `--tls-keylog FILE` | decrypt TLS sessions present in an NSS key-log file (needs `[tls]`) |
| `-j N`, `--jobs N` | analyse with N worker processes, same output (default `0`: one per CPU core; `1`: none) |
| `--dedup off\|run\|persistent` | duplicate suppression; `persistent` remembers across runs (`--dedup-db`) |
| `--option http.cookies=all` | plugin options (e.g. `detection.bruteforce=10`) |
| `--strict-heuristics` | fewer false positives: Telnet needs a Telnet port or option negotiation; disables `keyvalue` |
| `--plugin-dir DIR` | load extra plugins from a directory |
| `--strict` | exit code 3 if any parsing or plugin warning occurred |

Every output writes what was seen, secrets included. Network outputs (webhook, syslog) only run when you ask for them. Exit codes: `0` ok, `1` error, `2` usage, `3` warnings with `--strict`, `130` interrupted.

See [docs/reference/outputs.md](docs/reference/outputs.md) for the output formats and JSON fields.

### Live table (`--tui`)

| Key | Action |
| --- | --- |
| `/` | filter: free text, or `proto:ftp`, `risk:medium+`, `host:10.0.0.`, `user:admin`, `tag:weak`, `kind:alert`; `-` negates |
| `Esc` | clear the filter |
| `p` | pause/resume |
| `q` | quit |

The table follows new findings while the cursor is on the last row; move up to read and it stays put. The pane below shows every field of the highlighted finding.

### Configuration file

Options can live in `./netcreds-ng.toml` or a user config file: `%APPDATA%\netcreds-ng\config.toml` on Windows, `~/.config/netcreds-ng/config.toml` elsewhere.

```toml
[plugins]
select = ["databases", "remote-access", "ftp"]
disable = ["keyvalue"]

[plugins.http]
cookies = "all"        # session | all | off

[plugins.detection]
bruteforce = 10        # failed logins from one client to one service...
window = 600           # ...within this many seconds

[sets]
mine = ["databases", "telnet"]

[output]
jsonl = "findings.jsonl"
tls_keylog = "keys.log"

[output.webhook]
url = "https://hooks.slack.com/services/..."
format = "slack"
min_risk = "high"
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

Thresholds are plugin options. `--disable detection` turns alerts off; `--disable analytics` turns off the weak/reused password tags and host profiles.

## TLS decryption

Browsers, `curl`, and many TLS libraries write session secrets to the file named by the `SSLKEYLOGFILE` environment variable. Pass that file with `--tls-keylog`. netcreds-ng then decrypts the matching sessions, including after STARTTLS, and runs the normal plugins on the plaintext.

Supported versions are TLS 1.2 (AES-GCM, ChaCha20-Poly1305, AES-CBC) and TLS 1.3. Findings from decrypted traffic are tagged `tls-decrypted`. They are **not** counted as cleartext exposure, because they were encrypted on the wire. Sessions without keys are counted in the run summary and otherwise skipped.

## Legacy mode

`--legacy` reproduces the original net-creds byte for byte: the same coloured stdout lines and the same `credentials.txt` with its de-duplication. Use it if existing scripts parse the old output. Its parity with the original Python 2 tool is checked by the test suite against output recorded from the original. Plugin selection does not apply to it.

## Plugins

Plugins are Python classes. They are loaded from installed packages (entry point group `netcreds_ng.plugins`), from `--plugin-dir`, or from the user plugin directory. A protocol plugin names the sets it belongs to with a `sets` class attribute. See [docs/plugins/](docs/plugins/index.md) for the API and a walkthrough, and [examples/netcreds-ng-example-plugin](examples/netcreds-ng-example-plugin) for an installable example.

## Documentation

The full documentation (user guide, CLI and protocol reference, architecture, plugin development and API reference) is in [`docs/`](docs/index.md) and builds into a website with MkDocs:

```bash
pip install ".[docs]"
mkdocs serve          # http://127.0.0.1:8000
```

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

- **Secrets are shown as seen**, on screen and in every output. Treat outputs like the capture they came from.
- **Per-run fingerprints.** Password-reuse detection uses `secret_fingerprint`, a keyed hash with a fresh random key for each run. Fingerprints only correlate within a single run. As a result, JSONL/SQLite outputs differ between runs only in that field.
- **Capture gaps.** If packets are missing, a plugin never stitches the bytes on either side of the gap into a credential. It skips the damaged line, resynchronises on the next message (LDAP, Redis), or stops analysing that connection. Gap counts appear in the run summary.
- **Direction guessing.** When a connection has no handshake in the capture and both ports look alike, each plugin is offered both directions, and the first direction that produces a finding wins. The run summary counts these flows.
- **Parallel files.** With `-j`, each file is analysed on its own. Without it, a connection can continue from one file into the next (rotated captures).

## Responsible use

Only sniff traffic you are authorised to inspect. Captures, evidence files, key logs and outputs contain real credentials: store them securely and delete what you no longer need.
