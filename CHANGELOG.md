# Changelog

## 2.0.0.dev0 (unreleased)

Complete rewrite as a next-generation, defensive credential-exposure auditing tool. The original net-creds behaviour is the parity floor, verified by tests against output recorded from the original Python 2 tool.

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
