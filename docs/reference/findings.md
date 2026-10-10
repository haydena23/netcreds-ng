# Findings

A finding is an instance of `netcreds_ng.model.Finding`. Every output serialises the same fields. See [Core concepts](../getting-started/concepts.md) for what they mean in practice and the [data model API](../api/model.md) for the Python class.

## Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `protocol` | string | protocol label: `FTP`, `HTTP`, `HTTP/2`, `SMTP`, `POP3`, `IMAP`, `Telnet`, `IRC`, `NTLM`, `Kerberos`, `SNMP`, `LDAP`, `MySQL`, `PostgreSQL`, `MSSQL`, `Oracle`, `Redis`, `MQTT`, `SIP`, `VNC`, `RDP`, `RADIUS`, `TACACS+`, `Cleartext` (generic detectors), or a third-party label |
| `kind` | string | one of the [kinds](#kinds) |
| `src`, `dst` | endpoint | client and server, `ip:port` (`[ipv6]:port`). A port of 0 means a host rather than a connection (alerts) and is written as the bare IP |
| `timestamp` | float / ISO 8601 | capture time of the packet that completed the finding; outputs write ISO 8601 UTC |
| `frame` | int | 1-based frame number in the capture file, as Wireshark numbers it; frames are numbered per file |
| `username` | string | account involved |
| `secret` | string | the secret as it crossed the wire (cleartext kinds only) |
| `domain` | string | Windows domain or Kerberos realm |
| `value` | string | description or display value for non-credential kinds (URL, event text, alert text) |
| `risk` | string | `info`, `low`, `medium` or `high` |
| `plugin` | string | name of the plugin that produced it |
| `confidence` | float | 1.0, or lower for heuristics |
| `tags` | list of strings | see [tags](#tags) |
| `extra` | object | protocol-specific details; JSON-serialisable |
| `display` | string | derived: the one-line value shown on screen (`user:secret` for credentials, `domain\user:secret` with a domain) |

Text fields are decoded from wire bytes as UTF-8; undecodable bytes appear as `\xNN` escapes. Empty fields are omitted from JSON output.

## Kinds

| Kind | Secret | Typical producers |
| --- | --- | --- |
| `credential` | yes | every cleartext login |
| `username` | no | FTP USER, IRC NICK, RDP cookie, EAP identity, LDAP unauthenticated bind |
| `password` | yes | a password without a username |
| `token` | yes | HTTP bearer tokens and JWTs, XOAUTH2 |
| `api_key` | yes | HTTP API-key headers and parameters, `secrets` detectors |
| `cookie` | yes | HTTP session cookies |
| `community` | yes | SNMP v1/v2c |
| `auth_event` | no | challenge/response and weak-authentication observations |
| `auth_result` | no | login outcomes |
| `url`, `post`, `search` | no | HTTP browsing |
| `info` | no | Oracle connect data, TACACS+ commands, RADIUS accounting |
| `alert` | no | the `detection` enricher only |

### Outcome of a result

For `auth_result` findings, `Finding.outcome` returns:

1. `extra["outcome"]` if it is `"success"` or `"failure"`;
2. otherwise `"failure"` if `value` contains "fail", "reject" or "denied";
3. otherwise `"success"` if it contains "succe" or "accept", or ends in " ok";
4. otherwise `None`.

Consumers of JSON output can apply the same rule.

## Risk

| Risk | Console style | CEF severity | Syslog severity |
| --- | --- | --- | --- |
| `high` | bold red | 9 | 2 (critical) |
| `medium` | yellow | 6 | 4 (warning) |
| `low` | cyan | 3 | 5 (notice) |
| `info` | dim | 1 | 6 (informational) |

## Tags

### Added by enrichers and the engine

| Tag | Added by | Meaning |
| --- | --- | --- |
| `cleartext` | analytics | a secret from a protocol that is cleartext on the wire |
| `weak-password` | analytics | shorter than 6 characters or on the weak-password list; risk raised to high |
| `password-reuse` | analytics | the same secret seen for another account or service in this run |
| `tls-decrypted` | engine | only visible because a TLS key log was supplied |
| `brute-force`, `password-spraying`, `targeted-account`, `login-after-failures` | detection | the alert type |

### Added by protocol plugins

| Tag | Plugins | Meaning |
| --- | --- | --- |
| `nonstandard-port` | most | the service runs on an unusual port |
| `heuristic` | telnet | login prompt without Telnet evidence (confidence 0.6) |
| `ntlmv1` | ntlm | NTLMv1 in use |
| `no-preauth` | kerberos | an account answered without pre-authentication |
| `weak-preauth-<etype>` | kerberos | pre-authentication with DES or RC4 |
| `weak-etype-offered` | kerberos | the client offers DES or RC4 |
| `weak-service-ticket` | kerberos | a service ticket encrypted with DES or RC4 |
| `default-community` | snmp | a well-known community string |
| `write-access` | snmp | community used for a SetRequest |
| `snmpv3-noAuthNoPriv`, `snmpv3-authNoPriv` | snmp | SNMPv3 without authentication or without privacy |
| `unauthenticated-bind` | ldap | LDAP bind with a DN and no password |
| `cleartext-password` | mysql, postgres, mssql, tacacs | the protocol's cleartext-password method |
| `empty-password` | mysql, mssql | the login used an empty password |
| `change-user` | mysql | a `COM_CHANGE_USER` re-authentication on an open connection |
| `no-authentication` | postgres, vnc | login without any authentication |
| `password-change` | mssql | the LOGIN7 also carried a new password |
| `new-password` | tacacs | a new password in a password change |
| `encrypted`, `login-only` | mssql, oracle | the login (or only the login) was encrypted |
| `ano-encryption`, `auth-phase-one`, `auth-phase-two` | oracle | Oracle native encryption, O5LOGON phases |
| `no-nla`, `standard-rdp-security`, `tls`, `rdp-cookie`, `negotiation-failed`, `no-response` | rdp | RDP negotiation results |
| `challenge-response`, `unencrypted-session`, `non-vnc-auth` | vnc | VNC security types |
| `eap-identity` | radius | EAP-Response/Identity |
| `obfuscated-body`, `sensitive-arguments` | tacacs | encrypted TACACS+ body; command arguments containing secrets |
| `basic-auth`, `digest` | sip | SIP authentication scheme |
| `key-id-only` | secrets | an AWS key id without its secret |

## Common `extra` keys

| Key | Present on | Meaning |
| --- | --- | --- |
| `mechanism` | HTTP, mail, IRC, LDAP, RADIUS, MSSQL... | authentication mechanism (`Basic`, `form`, `PLAIN`, `CRAM-MD5`, `NTLM`, ...) |
| `secret_fingerprint` | credentials and passwords | per-run keyed hash for reuse correlation within one run |
| `url`, `host`, `header`, `param` | HTTP | where in the request the item was found |
| `reply` | FTP, Redis | the server's reply line |
| `outcome` | results | explicit `success`/`failure` |
| `error_code`, `result_code`, `sqlstate`, `return_code` | results | protocol error codes |
| `ntlm_version`, `workstation`, `event_id`, `target` | NTLM | NTLM metadata |
| `realm`, `service`, `preauth_etype`, `offered_etypes`, `ticket_etype` | Kerberos | Kerberos metadata |
| `version`, `pdu`, `security_level`, `engine_id` | SNMP | SNMP metadata |
| `detector`, `paired_secret`, `pem_type`, `length` | secrets | which detector matched |
| `detection`, `attempts`, `window_seconds`, `frames`, `users`, `clients`, `preceded_by` | alerts | see [alerts](../guide/detections.md#alert-findings) |

## De-duplication key

Two findings are duplicates when these match: `protocol`, `kind`, source IP, destination IP and port, `username`, `secret`, `domain`, `value`, and, for `auth_result` only, `frame` (so every login attempt is kept). The source port is not part of the key, so the same login over many connections is reported once.

## Run statistics

`netcreds_ng.model.RunStats` holds the counters shown in the run summary:

| Counter | Meaning |
| --- | --- |
| `frames`, `decoded` | frames read; frames decoded to IP |
| `undecodable` | non-IP or malformed frames |
| `truncated_frames` | frames captured shorter than their wire length (snap length) |
| `filtered` | frames dropped by `-f`/`-F` |
| `tcp_flows`, `udp_flows` | connections and conversations tracked |
| `ip_fragments`, `ip_reassembled` | fragments seen; datagrams reassembled |
| `ip_fragments_expired`, `ip_fragment_duplicates` | incomplete datagrams dropped; late duplicate fragments |
| `tcp_gaps`, `tcp_gap_bytes` | holes in TCP streams and their size |
| `tcp_retransmitted_bytes` | duplicate bytes discarded |
| `tcp_data_segments`, `tcp_payload_bytes` | TCP segments carrying data, and their payload bytes |
| `tcp_duplicate_segments` | data segments captured twice within 10 ms (a SPAN port copying both ways) |
| `tcp_one_sided_flows` | connections where only one direction was captured, although it shows the other answered |
| `tcp_unanswered_syn_flows` | connection attempts (bare SYNs) that nobody answered |
| `tcp_no_handshake_flows` | connections picked up mid-stream (no SYN seen) |
| `dropped_packets` | live capture: packets lost because analysis fell behind |
| `evicted_flows` | connections closed because the flow table was full |
| `ambiguous_flows`, `orientation_resolved` | connections with unknown client/server roles; plugin orientations settled by a finding |
| `encrypted_flows` | TCP connections opening with TLS (without a key log) or SSH, skipped by cleartext-only plugins |
| `tls_sessions`, `tls_decrypted`, `tls_no_key`, `tls_unsupported`, `tls_failed` | TLS sessions with a key log loaded |
| `findings`, `duplicates` | findings published; duplicates suppressed |
| `plugin_errors` | errors per plugin, enricher (`enricher:<name>`) and sink (`sink:<name>`) |
| `suppressed_orientation_errors` | errors in a guessed orientation of an ambiguous connection |
| `source_errors` | capture-file and capture-backend problems |
| `by_protocol`, `by_kind` | finding counts |
| `first_ts`, `last_ts` | capture time span |
