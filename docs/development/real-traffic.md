# Real-traffic validation

The unit and parity tests use synthetic traffic built to the protocol specifications. `tools/corpus.py` checks the plugins against **real captures** as well: public sample captures from other projects, compared with what Wireshark's dissectors (tshark) see in the same files.

## Running it

```bash
python tools/corpus.py fetch              # download the captures listed in tools/corpus.toml
python tools/corpus.py run                # analyse them, compare with tshark, write a report
python tools/corpus.py run --only mysql/  # a subset, by name
python tools/corpus.py list
```

- The captures are downloaded **outside the repository**: `%LOCALAPPDATA%\netcreds-ng\corpus` on Windows, `~/.cache/netcreds-ng/corpus` elsewhere, or `--dir` / `NETCREDS_CORPUS`. `fetch` refuses a directory inside the repository. Never commit them.
- Every file is pinned by SHA-256 in `tools/corpus.toml`. A mismatch is an error, and the file is not used.
- tshark is optional. The runner looks for it on `PATH` and in the usual install locations, or takes `--tshark PATH`. Without it, the netcreds-ng side still runs: findings, plugin errors and capture health.
- Reports go to `<corpus dir>/report/corpus-report.md` and `corpus-report.json`.

## Sources and licences

| Source | Files | Licence |
| --- | --- | --- |
| [Zeek](https://github.com/zeek/zeek) `testing/btest/Traces`, pinned to a commit | 81 | BSD-3-Clause (repository licence) |
| [Wireshark wiki SampleCaptures](https://wiki.wireshark.org/SampleCaptures) | 21 | none stated: downloaded for local testing only, never redistributed |
| [Wireshark](https://gitlab.com/wireshark/wireshark) `test/captures` and `test/keys`, pinned to a commit | 16 (5 of them TLS key logs) | GPL-2.0-or-later |

Five captures come with an NSS key log. The runner gives the key log to netcreds-ng (`--tls-keylog`) and to tshark, so TLS decryption is checked on real sessions too.

## Reading the report

For each capture, the runner extracts the identities tshark's dissectors expose and compares them with netcreds-ng's findings, ignoring case. The identities are login names (FTP, HTTP Basic/Digest, POP3, IMAP, SMTP AUTH, LDAP bind, Kerberos AS exchange, NTLM, MySQL, PostgreSQL, RADIUS, SIP, MQTT, RDP cookie, TDS, TNS, TACACS+, HTTP/2 Basic) and SNMP communities. Passwords are never compared or printed, and communities are shown masked.

| Result | Meaning |
| --- | --- |
| matched | netcreds-ng reports the same identity (`DOMAIN\user` and `user@domain` count as the same user) |
| partial | one contains the other, for example a DN and its CN |
| missed | tshark sees it and netcreds-ng does not. Investigate it: it may be deliberate (anonymous logins) |
| extra | netcreds-ng reports it and tshark does not. tshark dissects by port, so extras on non-standard ports are expected |
| unreferenced | the protocol has no tshark reference here (IRC, Telnet, Redis, VNC, secrets) |

The report also lists, per capture, the findings by plugin, plugin errors, the [capture health](../guide/analysing-captures.md#capture-health) verdict and, with a key log, how many TLS sessions were decrypted. The plugin-coverage table shows how many captures each plugin produced findings for.

## Results (2026-10-08, 113 captures)

- **Plugin errors: 0**, including the PROTOS LDAP and SNMP robustness suites (about 2,000 deliberately malformed packets).
- **tshark identities:** 308 matched, 56 partial, 14 missed; 31 reported only by netcreds-ng.
  - All 14 misses are explained. Ten are SNMP communities in the PROTOS suite that differ only in how they are displayed: tshark replaces invalid UTF-8 and stops at NUL bytes, while netcreds-ng keeps the exact bytes. Three are Kerberos principals with no authentication verdict: anonymous PKINIT, and error 14 (no key for the encryption type). One is a capture in Microsoft NetMon format, which netcreds-ng does not read.
  - The extras are logins on non-standard ports, `AUTH PLAIN` (tshark does not decode it), an Oracle TTI login name, and a Kerberos machine account. 23 of them are PROTOS SNMP fuzz values.
- **TLS with a key log:** TLS 1.3 (RFC 8446), TLS 1.2 with ChaCha20-Poly1305, and HTTP/2 over TLS decrypt. Sessions using PSK cipher suites, a TLS 1.3 draft version or TLS 1.0 are reported as not decrypted, with the reason.
- **Capture health:**
  - Three captures rated "degraded" really are one-sided: Zeek's `smtp-one-side-only.pcap`, and two Wireshark samples filtered to client packets.
  - A fourth is degraded because it lost 93% of its stream bytes (`NTLM-wenchao.pcap`; tshark independently marks 35 lost segments).
  - Zeek's `tcp/ssh-dups.pcap` gets an informational note that 75% of its segments were captured twice.
- **Fixed as a result:**
  - Kerberos errors 1, 18 and 23 (account expired, disabled or locked out, password expired) are now reported as failed logins.
  - MySQL `COM_CHANGE_USER` re-authentication is now reported.
  - RDP cookie padding is now removed.
  - Capture health now warns about small captures that are mostly one-sided.
- **No public sample with credentials found:**
  - TACACS+ and MSSQL LOGIN7: no sample at all. The only MSSQL sample contains RPC requests, not a login.
  - MQTT: the only sample has no username.
  - HTTP/2: the only sample (TLS with a key log) fetches an image, so it decrypts but has nothing to report.
  - The `secrets` and `keyvalue` heuristics ran on every capture and reported nothing, so there were no false positives.

## Adding captures

Add an entry to `tools/corpus.toml` with its `url`, `sha256`, `size`, `license`, the `plugins` it should exercise and optional `notes`. A key log is an entry with `kind = "keylog"`; a capture refers to it with `keylog = "<name>"`. Pin files from source repositories to a commit, never to a branch (a test checks this). Only use sources whose terms allow downloading for testing, and never commit the files.
