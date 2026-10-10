# Changelog

## 2.0.0.dev0 (unreleased)

Python 3 port of net-creds, rebuilt as a plugin-based blue-team sniffer. The original net-creds behaviour is the parity floor, verified by tests against output recorded from the original Python 2 tool.

### Faster analysis (2026-10-10)

Same findings, faster. Measured with `tools/bench.py --flows 20000` (188,000 frames) on an 8-core machine.

- **About 57% faster in one process** (13,300 to 20,900 frames/s); long bulk transfers about 80% faster. The engine skips detached plugins without looking at them, frees each closed connection's objects at once instead of leaving them to the cyclic garbage collector (which collected 3 million objects per benchmark run), and collects young objects less often while it works. `keyvalue`, `telnet`, `http`, `sip` and `ftp` skip work that cannot change their result; the HTTP response parser no longer rescans its whole buffer for every segment of a non-HTTP download.
- **`-j N` now splits one capture across N worker processes**, not only several files: about 79,000 frames/s with `-j 8` (3.8 times one process; 4.2 times on a 940,000-frame capture). The traffic is divided by host pair and merged back, so the output (findings, order, counters, warnings) is the same as with `-j 1`, and connections now continue across rotated files in parallel mode too. By default the command line uses one worker per physical core (`-j 0`); `-j 1` keeps the old single-process behaviour, and the Python API (`SessionConfig.jobs`) still defaults to 1. Inputs under 16 MB stay sequential. See "Parallel analysis" in the user guide.
- **Fixed** (old per-file `-j` mode): fragment counters (`ip_fragments_expired`, `ip_fragment_duplicates`) were reset to 0 after merging; cross-plugin secret merging (E-10) was off in workers.
- **Changed:** idle connections are swept every 2,048 frames *read*, not every 2,048 decoded frames, so that parallel workers sweep at the same frames. On captures with many non-IP frames (ARP, LLDP...) a connection idle for longer than the timeout is closed sooner, as the timeout intends. A login split across such an idle period is then reported as a user name and a separate password rather than one credential. In the real-traffic corpus this changed one file's flow counters (4 more UDP flows) and no findings.
- **Encrypted connections are skipped by cleartext parsers.** A TCP connection that opens with a TLS ClientHello (and no key log is loaded) or an SSH banner carries nothing they can read; the engine now detaches those plugins before they see it. On TLS-heavy traffic this is 6 times faster (12,500 to 79,000 frames/s in one process; 147,000 frames/s, about 200 MB/s, with `-j 8`). New plugin attribute `wants_encrypted` (default `True`, so third-party plugins still receive these connections; built-ins except `mssql` set `False`) and counter `encrypted_flows`; `tools/bench.py` prints the bypass ratio. Findings were unchanged on the real-traffic corpus.
- `RawFrame` is a named tuple instead of a frozen dataclass (same fields, immutable, faster to create).

### Better detection in the existing plugins (M32, 2026-10-09)

The existing plugins find more of what is on the wire, with fewer false positives and duplicates. No new protocols.

**Fixed**

- **Kerberos:** a PKINIT (certificate) or FAST-armored AS-REQ answered by an AS-REP was reported as "AS-REP issued without pre-authentication" (high). It is now a low-risk "Kerberos pre-authentication (PKINIT)" / "(FAST armored)" event; anonymous PKINIT is tagged `anonymous`. Found in real traffic (Zeek `krb/kinit.pcap`).
- **Oracle (E-9):** an AUTH request split across several TNS DATA packets lost its user name. The client's packets are now scanned together until the server answers.
- **One secret, one finding (E-10):** an API key in an HTTP request was reported twice, by `http` and by `secrets`. Within a connection, a secret already reported by another plugin is now counted as a duplicate instead, unless the later report adds a user name. `--dedup off` keeps both.
- **Capture gaps (E-5):** after a gap,
    - `mysql` and `postgres` resume at the next segment made of whole messages: `mysql` after a successful login (so a later `COM_CHANGE_USER` is found), `postgres` after the StartupMessage (so the login verdict is found);
    - `sip` over TCP resumes at the next SIP start line;
    - `mqtt` no longer stops when only client data after the CONNECT was lost.

  A PostgreSQL AuthenticationOk after a server-side gap is a plain success, not "trust".
- **TLS (E-12):**
    - A gap in the unencrypted handshake no longer stops decryption once the client random (now read as soon as it arrives) or the ServerHello was seen; decryption resumes at the next record. A lost ChangeCipherSpec still stops that direction.
    - A session decrypted in one direction only is now listed under warnings.
    - TLS 1.2 renegotiation now switches to the new handshake's keys at each side's ChangeCipherSpec.
- **False positives:**
    - `keyvalue` skips template and masked values (`****`, `%s`, `${VAR}`, `$VAR` in capitals, `{{ var }}`, `<password>`, `null`...).
    - `telnet` no longer reports binary data after a "Password:" prompt on a non-Telnet port as a typed password.
- **Plugin selection (M31 follow-up):**
    - An empty `-P` (`-P ,`, `-P ""`) is a usage error instead of selecting everything.
    - A plugin declaring `sets = "name"` (a string) gets one set rather than one per letter, with a warning.
    - Config `select` may be a string.
    - Nested user sets resolve in linear time.

### Refocus: a sniffer built from plugins you choose (2026-10-09)

netcreds-ng is back to what net-creds was: a sniffer that prints the credentials it sees, now made of plugins you pick. Features that had grown it into a reporting and dashboard product were removed. The full-featured state is kept in git history (local tag `archive/full-featured`, commit `75b8b5f`).

**Added**

- **Plugin sets and "only these" selection.**
    - `-P`/`--plugins LIST` runs only the named protocol plugins and sets.
    - `--enable` and `--disable` now accept set names too.
    - Built-in sets: `legacy` (the original's coverage), `web`, `email`, `file-transfer`, `remote-access`, `databases`, `directory`, `aaa`, `network`, `chat`, `iot`, `voip`, `generic`, plus `default` and `all`.
    - The config file takes `[plugins] select = [...]` and user-defined sets in `[sets]`; sets can nest and extend built-in ones.
    - Protocol plugins declare their sets with a `sets` class attribute, which third-party plugins can use too. `--list-plugins` shows each plugin's sets and the resolved sets.
- SQLite output:
    - WAL journaling;
    - a commit about once a second while findings arrive (option `commit_interval`);
    - new `runs` columns `source`, `updated`, `finished` and `stats` (every run counter as JSON), added in place to existing databases.
- `RunStats.snapshot()` / `RunStats.from_snapshot()`, and `netcreds_ng.session.combine_summary()`.

**Removed**

- **Masking and redaction**: `--mask`, `[output] mask`, the `mask` and `include_secrets` output options, and `netcreds_ng.output.masking`. Every output now records findings as seen. **This includes `--webhook` and `--syslog`, which used to mask by default and now send secrets to the configured destination.**
- **The HTML report**: `--html`, the `html` output and its options.
- **The interactive dashboard.** `--tui` is now a minimal live table (status bar, findings table that follows new rows, detail pane, `/` filter, `p` pause, `q` quit). Removed with it:
    - the finding inspector and its explanations (`netcreds_ng.explain`), the analytics tabs, bookmarks and notes, follow/freeze;
    - the side panel, saved filters, session and host drill-down, risk and browsing toggles, and JSONL/HTML export keys;
    - the sparkline and `--attach`.
- The enrichers' `observe()` replay methods (they existed only for `--attach`).

**Changed**

- Live capture prints findings one line each by default, like the original. The table appears only with `--tui`; `--no-tui` is still accepted and does nothing.
- `-P`, `--enable` and `--disable` are a usage error with `--legacy`, which always runs the original's parsers.
- `mask` and `html` under `[output]` in a config file are ignored, with a note on stderr naming them.
- `test_installed_entry_point_subprocess` decodes the child's output as UTF-8, so it no longer fails in a cp1252 console (E-29).

**Fixed**

- `--tui` together with `--sqlite` stored no findings. The sink was opened on the UI thread and written from the analysis thread, so SQLite rejected every write, and each one was counted as a sink error (E-25).

### Live capture start-up

- Typing just `netcreds-ng` now finds the default interface. scapy's routing table was never loaded, so the interface was always unknown and the run stopped with "could not find an active interface". If scapy cannot tell, netcreds-ng picks the first active interface with a routable IPv4 address, preferring physical adapters.
- The blanket root/administrator check is replaced by a check of what capture really needs:
  - on Windows, Npcap must be installed, and Administrator rights are needed only when Npcap is set to "administrators only";
  - on Linux, root or `CAP_NET_RAW`;
  - on macOS, access to `/dev/bpf*`.

  The error says what is missing. `--legacy` keeps the original's root check.

### Real-traffic validation and capture health (M13)

- **Capture health.** The run summary ends with a verdict on how much of the traffic the capture saw (`good`, `degraded`, `poor`). It covers:
  - one-sided TCP flows (asymmetric routing, or a SPAN port that sees one direction);
  - missing stream bytes;
  - segments captured twice (SPAN copying both ingress and egress);
  - truncated frames, live drops, and flows picked up mid-stream.

  New `RunStats` counters: `tcp_data_segments`, `tcp_payload_bytes`, `tcp_duplicate_segments`, `tcp_one_sided_flows`, `tcp_unanswered_syn_flows`, `tcp_no_handshake_flows`, `dropped_packets`. Duplicates are informational: they never hide findings. Analysis is about 3% slower (`tools/bench.py --flows 20000`, measured side by side with the previous commit).
- **`--summary-json PATH`** writes the run summary as JSON: counters, capture health and analytics, with no secrets.
- **`tools/corpus.py`** and **`tools/corpus.toml`** run every plugin over 113 public sample captures (Zeek, the Wireshark wiki, and the Wireshark test suite, pinned by SHA-256 and downloaded outside the repository) and compare the identities found with tshark's. See *Development → Real-traffic validation*.
- **Fixes found on real traffic:**
  - Kerberos errors 1 (account expired), 18 (account disabled or locked out) and 23 (password expired) are now reported as failed logins.
  - MySQL `COM_CHANGE_USER` re-authentication is reported (tag `change-user`), including empty and cleartext passwords. The plugin now follows the command phase of a connection after login. It reads only packets with sequence id 0 as commands, so `LOAD DATA` contents are never mistaken for a command, skips packets over 64 KiB, and stops on the compressed protocol.
  - Space padding in RDP `mstshash` cookies is removed from the username.

### Release preparation (M6)

- Live capture is marked **beta** for 2.0.0: it has not been validated on a real network yet. Capture-file analysis is the supported workflow.
- gzip-compressed `.pcap.gz` / `.pcapng.gz` captures are read directly (detected by content). Previously they were picked up from directories and then rejected (E-16).
- An unknown plugin name in `--enable`/`--disable` or the config file is now a usage error (exit 2) instead of a `KeyError` traceback (E-15).

### Added in round 2 (milestones M7–M12, engine fixes E-1..E-7)

- **Engine**
  - Ambiguous client/server direction: if a connection has no handshake and both ports look alike, plugins are offered both orientations, and the first one to produce a finding wins. New `ambiguous_flows` and `orientation_resolved` counters.
  - Streams picked up without their SYN briefly hold their first segments, so a segment reordered before the first captured one is not lost.
  - A hole the peer has already ACKed (lost by the capture, not the network) is skipped at once, keeping request/response order.
  - Interval-based IP defragmentation (no per-byte work), with exact late-duplicate detection.
  - IPv6 jumbograms, and IPv6 packets with a zero payload length from offload captures.
  - Packet observers for per-packet sinks.
  - TLS decryption with an NSS key log (`--tls-keylog`, optional `[tls]` extra): TLS 1.2 (AES-GCM, ChaCha20-Poly1305, AES-CBC with or without encrypt-then-MAC) and TLS 1.3, including KeyUpdate and STARTTLS. Findings from decrypted data are tagged `tls-decrypted`, and are not counted as cleartext exposure.
  - Parallel analysis of several capture files with `-j/--jobs`; output is identical to a sequential run.
- **Protocols**
  - HTTP/2, with a full HPACK decoder checked against the RFC 7541 vectors.
  - RADIUS (PAP/CHAP/MS-CHAP/EAP events, EAP identities, results).
  - TACACS+ (unencrypted-mode credentials, authorisation/accounting commands).
  - MSSQL TDS (LOGIN7 passwords, which are only obfuscated; Windows authentication events; encryption mode).
  - Oracle TNS (connect metadata, O5LOGON events, refusals, native encryption).
  - RDP (`mstshash` usernames, flags for no NLA or standard RDP security).
  - `secrets` detector for cloud/API credentials in any cleartext stream: AWS, GCP, Azure, GitHub, Slack, Stripe, PEM private keys.
- **Resynchronisation**
  - LDAP and Redis resynchronise on the next message after a capture gap instead of stopping.
  - Mail, LDAP, PostgreSQL and MySQL keep parsing after STARTTLS when TLS is being decrypted.
- **Heuristics:** Telnet logins without a Telnet port or option negotiation are tagged `heuristic` (confidence 0.6). `--strict-heuristics` ignores them and disables `keyvalue`.
- **Detection enricher:**
  - alerts for brute force, password spraying, targeted accounts, and a successful login after failures (new `alert` kind; thresholds are options);
  - a service inventory, accounts shared across services, and 0–100 host exposure scores.
  - `Finding.outcome` gives a uniform success/failure for login results.
- **Outputs**
  - `--evidence` pcapng with the packets behind each finding and Wireshark packet comments.
  - `--cef` file output.
  - `--syslog` (RFC 5424 over UDP/TCP, CEF or JSON body; opt-in, masked).
  - Slack/Teams/Discord webhook formats (`--webhook-format`).
  - HTML report: executive summary, activity timeline, alerts, service inventory, shared accounts, host scores, print styling.
  - Console summary: alerts, cleartext services, TLS and direction counters.
  - `docs/reference/outputs.md` documents the field reference and Splunk/Elastic examples.
- **Dashboard:**
  - filter language (`proto:`, `risk:medium+`, `host:`, `user:`, `tag:`, `kind:`, negation);
  - session view (`s`) and host drill-down (`o`/`d`);
  - saved filters (`Ctrl+S`, `f`);
  - packets/s with a sparkline, alert notifications, alerts and host scores in the analytics panel.
- **Documentation:** a MkDocs (Material) site in `docs/` with `mkdocs.yml`: getting started, user guide, CLI/protocol/findings/outputs/plugin-option references, architecture, plugin development, and an API reference generated from docstrings. New `[docs]` extra and a `docs` workflow that builds with `--strict` and publishes to GitHub Pages. `docs/OUTPUTS.md` and `docs/PLUGINS.md` moved into `docs/reference/outputs.md` and `docs/plugins/`.
- **Tooling:**
  - `tools/bench.py` (throughput benchmark and profiler);
  - `netcreds_ng.testing.tls_lab`, which creates real in-memory OpenSSL sessions for tests.

### Fixed in round 2 (protocol review and validation gate)

- Reassembly:
  - a pure ACK captured before reordered data no longer makes that data lost;
  - findings cite the frame that carried the bytes.
- TLS:
  - detected on SYN-less flows whatever orientation was guessed;
  - handshake messages split across TLS 1.3 records no longer trigger a false KeyUpdate;
  - `tls-decrypted` is tagged per chunk;
  - no-key TLS 1.2 sessions stop parsing after CCS.
- Dual-orientation plugin errors are surfaced when unresolved.
- RDP no longer misreads ISO-TSAP/S7comm traffic.
- Evidence:
  - multi-file runs no longer collide;
  - all IP fragments are included.
- IPv6 extension headers after a Fragment header are handled.
- Defragmenter losses are counted.
- Detection:
  - bursts expire;
  - account names are compared case- and domain-insensitively.
- Secrets:
  - documentation sample keys are info;
  - a lone AWS key id is medium.
- RADIUS tolerates a malformed datagram on a known flow.
- TACACS+ optional arguments are parsed correctly.
- NTLM `event_id` is stable under `-j`.

### Changed in round 2

- Telnet option decoding and the secrets scanner have fast paths for bulk traffic. On the same 188k-frame benchmark, throughput is the same as the M5 baseline (about 13k frames/s) even with 7 more plugins and the detection enricher.
- License metadata: `GPL-3.0-or-later`.

### Added

- **Engine**
  - Native pcap/pcapng reader that handles multiple interfaces and timestamp resolutions, and reports truncation.
  - Link-type-aware decoder: Ethernet, 802.1Q/QinQ, PPPoE, Linux SLL/SLL2, BSD loopback, raw IPv4/IPv6.
  - IPv4/IPv6 defragmentation.
  - Byte-exact TCP reassembly, covering wraparound, retransmissions, overlaps, out-of-order segments and explicit gaps.
  - Bounded flow table with idle eviction.
- **Plugin system**
  - Protocol, enricher and sink plugins, behind a versioned API.
  - Discovery from built-ins, the `netcreds_ng.plugins` entry points, and plugin directories.
  - Per-plugin error isolation; errors are counted and shown in summaries, never swallowed.
  - The `netcreds_ng.testing` SDK for packet crafting and a one-call analysis harness.
- **Protocols**
  - Parity protocols, rebuilt on streams: FTP, Telnet (option negotiation and line editing handled), IRC (NickServ, SASL), SMTP/POP3/IMAP (PLAIN, LOGIN, IMAP LOGIN with literals, XOAUTH2, STARTTLS), HTTP (Basic, forms, JSON, bearer tokens, API keys, session cookies, JWTs, Digest/NTLM events, URLs, searches, POST bodies), NTLM over any TCP carrier, Kerberos UDP/TCP, SNMP v1/v2c/v3.
  - New protocols: LDAP, MySQL, PostgreSQL, Redis, MQTT, SIP, VNC.
  - A generic key=value heuristic.
  - Login success/failure tracking where the protocol reports it.
- **Authentication hygiene findings**
  - NTLMv1 use.
  - Kerberos pre-auth encryption type (DES/RC4 flagged), accounts answered without pre-authentication, weak service tickets.
  - SNMPv3 security levels.
  - Trust and passwordless database logins.
  - VNC sessions without authentication.
- **Analytics enricher**
  - Weak passwords, using a packaged list.
  - Password reuse across accounts and services, detected by a per-run keyed fingerprint; plaintext is never compared or stored.
  - Risk escalation and per-host exposure profiles.
- **Outputs**
  - Rich console renderer with a run summary.
  - Interactive Textual dashboard: filtering, risk levels, masking, analytics panel, pause, JSONL/HTML export.
  - JSON Lines, CSV and log files, a SQLite session database, a self-contained HTML audit report, and opt-in webhooks.
  - `--mask` for shareable output.
- **Configuration**
  - TOML config file, `--option plugin.key=value`, `--enable`/`--disable`, `--plugin-dir`.
  - Dedup modes off/run/persistent.
  - `--strict` exit codes.
  - `--list-plugins`, `--list-interfaces`.
- **`--legacy` mode** reproduces the original net-creds stdout and `credentials.txt` byte for byte, including its de-duplication and Windows text-mode line endings.

### Changed

- `-v` keeps the original meaning: do not truncate long values. In 1.x it toggled the analytics panel; that panel is now the `a` key in the dashboard.
- `-f` accepts a comma-separated host list, and now also applies to capture files (outside `--legacy`).
- Findings are structured records with protocol, kind, risk, tags and frame number, instead of free-text lines.
- Requires Python 3.11+.
- Dependencies are now `rich`, `textual`, `scapy` (live capture only) and `psutil`. `impacket`, `pyasn1`, `netifaces` and `pywin32` are no longer needed.

### Fixed (from independent protocol review and release gate)

- **Capture gaps.** Lost segments are never spliced into a reported credential. The default `on_gap` detaches the plugin from the flow; line protocols resynchronise on the next line.
- **TCP port reuse.** A reused 4-tuple without FIN/RST no longer drops the new connection.
- **Cross-protocol false positives:**
  - FTP no longer reports POP3 logins.
  - Redis no longer reports FTP `AUTH TLS`.
  - Telnet no longer reports prompts that appear inside HTTP responses.
- **HTTP login verdicts:**
  - 1xx responses are ignored.
  - Form logins only report failures.
  - HEAD responses no longer desync the parser.
- **Mail.** Abandoned `AUTH LOGIN` exchanges and non-text decodes are not reported as credentials. CRAM-MD5 never puts digest material in the username.
- **NTLM.** Events carry a metadata-only `event_id` instead of a hash over the message, which included the response.
- **Dedup.** Repeated login failures are kept as separate events.
- **`--mask`** also redacts secrets inside POST bodies, URLs and extras.
- **Packaging.** The sdist now includes test fixtures and goldens. License metadata uses PEP 639 `license-files`.

### Removed

- The 1.x port-first dispatcher and the string-based reassembly, which together dropped multi-packet and non-standard-port credentials.
