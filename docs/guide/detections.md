# Alerts and analytics

Two built-in **enrichers** look at every finding after de-duplication, before it reaches the outputs:

| Enricher | Priority | Adds |
| --- | --- | --- |
| `analytics` | 10 | `cleartext`, `weak-password` and `password-reuse` tags; risk escalation; per-host exposure profiles |
| `detection` | 20 | behavioural `alert` findings; the service inventory; shared accounts; 0–100 host exposure scores |

Both are on by default. Disable them with `--disable analytics` or `--disable detection`.

## Cleartext exposure

`analytics` tags a finding `cleartext` when it carries a secret (credential, password, token, API key, cookie or community) from a protocol that is cleartext on the wire: FTP, Telnet, HTTP, SMTP, POP3, IMAP, IRC, SNMP, LDAP, Redis, MQTT, MySQL, PostgreSQL, and the generic `Cleartext` detectors. Findings tagged `tls-decrypted` are never tagged `cleartext`.

## Weak passwords

A credential or password is tagged `weak-password`, and raised to **high** risk, when:

- it is shorter than 6 characters, or
- it appears (case-insensitively) in the packaged list `netcreds_ng/data/weak_passwords.txt`.

## Password reuse

To detect reuse without comparing or storing passwords, `analytics` computes a **fingerprint** of each secret: an HMAC-SHA256 keyed with 32 random bytes generated at the start of the run, truncated to 16 hex characters. It is stored as `extra.secret_fingerprint`.

When the same fingerprint appears for more than one account, or for the same account on more than one service (`protocol@server`), the finding is tagged `password-reuse`.

Because the key is new every run:

- fingerprints correlate findings within one run only;
- they cannot be compared across runs or used to test password guesses;
- JSONL, SQLite and HTML outputs of the same capture differ between runs in this field only.

## Default and write SNMP communities

The `snmp` plugin tags well-known community strings (`public`, `private`, `community`, `admin`, `cisco`, `manager`, `snmp`) `default-community`, and communities used in a SetRequest `write-access`. `analytics` raises default communities to high risk.

## Behavioural alerts

`detection` watches login results (`auth_result` findings) from every protocol, using the `success`/`failure` outcome each plugin reports. It raises an `alert` finding, risk **high**, when a pattern crosses a threshold within a sliding time window. Time is capture time, so results are identical whether a capture is analysed live or later.

| Detection | Fires when | Option (default) |
| --- | --- | --- |
| `brute-force` | one client fails N times against one service (`server ip`, `port`, `protocol`) | `bruteforce` (5) |
| `password-spraying` | one client fails against N or more **distinct accounts** on one service | `spray` (5) |
| `targeted-account` | one account on one service fails from N or more **distinct clients** (distributed guessing) | `targeted` (5) |
| `login-after-failures` | a login succeeds from a client that previously triggered brute force or spraying against that service | (none) |

The window is `window` seconds (default 300) for all of them. Change thresholds with options:

```bash
netcreds-ng -p cap.pcap --option detection.bruteforce=10 --option detection.window=600
```

Rules:

- When the failures of one client in the window span 5 or more accounts, spraying is reported instead of brute force.
- Each detection fires **once per run** for a given client and service (or account and service). Later failures do not repeat it.
- Account names are compared case-insensitively for `targeted-account`.

### Alert findings

```text
16:13:20 HIGH   FTP       ALERT      192.0.2.66 > 198.51.100.21:21 Brute force: 5 failed logins for 'admin' from 192.0.2.66 in under 1s  #brute-force
16:13:20 HIGH   FTP       ALERT      192.0.2.66 > 198.51.100.21:21 Successful login as 'admin' after brute force from 192.0.2.66  #login-after-failures
```

An alert's `src` is the client IP without a port, because the attempts span many connections. For `targeted-account`, `src` is the most recent client, and every client is listed in `extra.clients`.

| `extra` field | Content |
| --- | --- |
| `detection` | `brute-force`, `password-spraying`, `targeted-account` or `login-after-failures` |
| `attempts` | failed attempts in the window when the alert fired |
| `window_seconds` | the window used |
| `frames` | frame numbers of the attempts (the last 50) |
| `users` | accounts tried (brute force, spraying) |
| `clients` | clients involved (targeted account) |
| `preceded_by` | the detection that preceded the success (login after failures) |

### Which protocols report results

Alerts need login results. Plugins that report success and failure: FTP, Telnet (failure), IMAP/POP3/SMTP, HTTP (Basic, Digest, NTLM and Bearer: success and failure; forms: failure only), HTTP/2, Kerberos (failures), LDAP, MySQL, PostgreSQL, MSSQL, Oracle, Redis, MQTT, SIP, VNC, RADIUS, TACACS+.

Third-party plugins take part automatically if they emit `auth_result` findings worded `login succeeded` / `login failed`, or set `extra["outcome"]`. See [protocol plugins](../plugins/protocol-plugins.md#reporting-login-results).

## Service inventory

`detection` builds an inventory of every server (`ip`, `port`, `protocol`) that appears as the destination of a finding (browsing findings excluded):

| Field | Meaning |
| --- | --- |
| `cleartext` | the service exposed a secret in cleartext |
| `findings` | findings involving the service |
| `accounts` | accounts seen (up to 50) |
| `clients` | number of distinct client IPs |
| `successes` / `failures` | login results |

The console summary shows the services with `cleartext` set under **Services exposing cleartext secrets**. The HTML report shows the whole inventory.

## Shared accounts

An account seen on more than one service (compared case-insensitively, `domain\user` when a domain is known) is listed under *accounts seen on several services* in the HTML report. These are the accounts whose exposure on one service puts others at risk.

## Host exposure scores

Each host gets a 0–100 score from the findings it took part in, as client or server:

| Contribution | Points |
| --- | --- |
| each high-risk finding | 10 |
| each medium-risk finding | 4 |
| each low-risk finding | 1 |
| each alert, for the target server | 15 |
| each brute-force, spraying or login-after-failures alert, for the attacking client | 15 |

The score is capped at 100. Login results and browsing findings do not score. The console's **Most exposed hosts** table is ordered by the worst risk seen and then by finding count; the dashboard's side panel and the HTML report show the scores.

## Using the analysis in Python

```python
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig

session = Session(load_registry(), SessionConfig())
session.open()
session.run_files(["capture.pcapng"])
session.close()

summary = session.summary()
for alert in summary["alerts"]:
    print(alert["detection"], alert["src"], "->", alert["dst"], alert["value"])
for host in summary["hosts"]:
    print(host["ip"], host["score"], host["max_risk"])
```

`Session.summary()` combines both enrichers: `weak_passwords`, `reused_secrets`, `risk_counts`, `hosts` (with `score`), `alerts`, `services`, `shared_accounts` and `host_scores`. See the [Session API](../api/session.md).
