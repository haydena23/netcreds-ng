# Changelog

## 2.0.0.dev0 (unreleased)

Complete rewrite as a next-generation, defensive credential-exposure auditing tool. The original net-creds behaviour is the parity floor, verified by tests against output recorded from the original Python 2 tool.

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
  - `docs/OUTPUTS.md` documents the field reference and Splunk/Elastic examples.
- **Dashboard:**
  - filter language (`proto:`, `risk:medium+`, `host:`, `user:`, `tag:`, `kind:`, negation);
  - session view (`s`) and host drill-down (`o`/`d`);
  - saved filters (`Ctrl+S`, `f`);
  - packets/s with a sparkline, alert notifications, alerts and host scores in the analytics panel.
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
