# netcreds-ng

**Find the credentials and weak authentication your network is exposing.**

netcreds-ng analyses packet captures or live traffic and reports every credential that crosses the wire in cleartext, along with authentication that is technically "protected" but weak (NTLMv1, Kerberos RC4/DES, SNMPv3 without authentication, VNC without a password...). It is a defensive auditing tool: it shows you the exposure so you can fix it. It does not crack anything.

It is the Python 3 successor of Dan McInerney's [net-creds](https://github.com/DanMcInerney/net-creds). It does everything the original did (verified by tests against the original's own output) and adds:

- **Real TCP stream reassembly.** Credentials split across packets, out-of-order or retransmitted segments, IPv4/IPv6 fragments, any link type (Ethernet, VLAN, PPPoE, Linux cooked, loopback, raw IP), IPv6.
- **17 protocol plugins.** Port-agnostic detection, with login success and failure tracking.
- **An interactive dashboard**, plus JSON Lines, CSV, SQLite, HTML audit reports and webhooks.
- **Risk analytics.** Weak passwords, password reuse across accounts and services, and a per-host exposure ranking.
- **A plugin system** for new protocols, outputs and enrichers.
- **Nothing dropped silently.** Parsing problems are counted and reported.

## Install

Requires Python 3.11 or newer.

```bash
pip install .          # from a checkout
pip install ".[dev]"   # plus test/lint tools
```

All dependencies are pure Python or ship wheels: `rich`, `textual`, `scapy` and `psutil`. No compiler is needed.

Live capture needs a packet-capture driver: **Npcap** on Windows, libpcap (usually preinstalled) on Linux/macOS. It also needs root/administrator rights. Reading capture files needs neither.

## Usage

```bash
netcreds-ng -p capture.pcapng                      # analyse a capture file
netcreds-ng -p captures/ --html report.html        # a whole directory, plus an HTML audit report
netcreds-ng -p cap.pcap --jsonl findings.jsonl     # JSON Lines for a SIEM
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
| `--jsonl/--csv/--log/--sqlite/--html PATH` | outputs; repeat or combine freely; `-` writes to stdout |
| `--webhook URL` | POST findings (medium risk and up, secrets masked) to an endpoint |
| `--dedup off\|run\|persistent` | duplicate suppression; `persistent` remembers across runs (`--dedup-db`) |
| `--enable/--disable PLUGINS` | choose plugins; `--enable all` includes opt-in ones |
| `--option http.cookies=all` | plugin options |
| `--plugin-dir DIR` | load extra plugins from a directory |
| `--strict` | exit code 3 if any parsing or plugin warning occurred |

Exit codes: `0` ok, `1` error, `2` usage, `3` warnings with `--strict`, `130` interrupted.

### Interactive dashboard keys

`/` filter · `Esc` clear filter · `r` cycle minimum risk · `b` hide browsing findings · `m` mask secrets · `a` analytics panel · `p` pause/resume · `e` export visible findings (JSONL) · `h` HTML report · `q` quit.

### Configuration file

Options can live in `./netcreds-ng.toml` or a user config file: `%APPDATA%\netcreds-ng\config.toml` on Windows, `~/.config/netcreds-ng/config.toml` elsewhere.

```toml
[plugins]
enable = ["all"]
disable = ["keyvalue"]

[plugins.http]
cookies = "all"        # session | all | off

[output]
mask = true
html = "report.html"
jsonl = "findings.jsonl"

[output.webhook]
url = "https://siem.example/hook"
min_risk = "high"
```

## What it detects

| Protocol | Reported |
| --- | --- |
| FTP | USER/PASS/ACCT credentials, login result, non-standard ports |
| Telnet | usernames/passwords typed at login prompts (option negotiation and line editing handled), failed logins |
| SMTP / POP3 / IMAP | AUTH PLAIN/LOGIN, USER/PASS, IMAP LOGIN, XOAUTH2 tokens; CRAM-MD5/APOP/NTLM as auth events; results; STARTTLS |
| HTTP | Basic auth, form and JSON logins, bearer tokens, API keys, session cookies, JWTs, Digest/NTLM/Negotiate events, URLs, searches, POST bodies, login results |
| NTLM (SMB, LDAP, MSSQL, RPC, ... any TCP) | user, domain, workstation, NTLMv1 vs v2 |
| Kerberos (UDP/TCP) | principals, pre-auth encryption type (DES/RC4 flagged), accounts without pre-authentication, weak service tickets, failures |
| SNMP | v1/v2c community strings (default and write-access flagged), v3 users and security level |
| LDAP | simple-bind credentials, SASL PLAIN, other SASL mechanisms as events, results, StartTLS |
| MySQL / PostgreSQL | cleartext-password logins; native/caching_sha2/MD5/SCRAM as events; trust logins without a password; results; TLS |
| Redis | AUTH / HELLO AUTH credentials and results |
| MQTT | CONNECT username/password, results |
| SIP | Digest auth events (user/realm), Basic credentials, results |
| VNC | sessions without authentication, VNC password auth, other security types, results |
| Generic | `user=... pass=...` patterns in other cleartext protocols (low confidence) |

Challenge/response schemes are reported as *events*: who authenticated, to what, how weakly. The challenge/response material itself is never extracted.

## Legacy mode

`--legacy` reproduces the original net-creds byte for byte: the same coloured stdout lines and the same `credentials.txt` with its de-duplication. Use it if existing scripts parse the old output. Its parity with the original Python 2 tool is checked by the test suite against output recorded from the original.

## Plugins

Plugins are Python classes. They are loaded from installed packages (entry point group `netcreds_ng.plugins`), from `--plugin-dir`, or from the user plugin directory. See [docs/PLUGINS.md](docs/PLUGINS.md) for the API and a walkthrough, and [examples/netcreds-ng-example-plugin](examples/netcreds-ng-example-plugin) for an installable example.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
pytest                          # full suite (parity, protocols, engine, CLI, TUI, fuzzing)
ruff check src tests tools
mypy
python tools/gen_fixtures.py    # regenerate synthetic captures (deterministic)
python tools/make_goldens.py --py2 /path/to/python2 --original ../net-creds/net-creds.py
```

Synthetic fixtures use documentation IP ranges and obviously fake credentials.

## Notes on output

- **What `--mask` covers.** Every secret field is masked. So are secret-looking values embedded in free text: form and JSON fields named like passwords or tokens, `api_key=` query parameters, and `Authorization`/`Cookie` header lines. It does not try to recognise secrets in arbitrary prose.
- **Per-run fingerprints.** Password-reuse detection uses `secret_fingerprint`, a keyed hash with a fresh random key for each run. Fingerprints only correlate within a single run and cannot be used to test password guesses. As a result, JSONL/SQLite/HTML outputs differ between runs only in that field.
- **Capture gaps.** If packets are missing, a plugin never stitches the bytes on either side of the gap into a credential. It skips the damaged line or stops analysing that connection. Gap counts appear in the run summary.

## Responsible use

Only analyse traffic you are authorised to inspect. Captures and outputs contain real credentials: store them securely, use `--mask` for reports you share, and delete what you no longer need.
