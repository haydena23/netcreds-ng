# Protocols

netcreds-ng ships 23 protocol plugins. This page describes, for each one, what it reports, at which risk, with which tags, and where its limits are.

## Overview

| Plugin | Protocol label | Transport | Port hints | Reports |
| --- | --- | --- | --- | --- |
| [`ftp`](#ftp) | FTP | TCP | 21 | USER/PASS/ACCT, results |
| [`mail`](#smtp-pop3-imap) | SMTP, POP3, IMAP | TCP | 25, 110, 143, 465, 587, 993, 995, 2525 | SASL PLAIN/LOGIN, USER/PASS, IMAP LOGIN, XOAUTH2 tokens, challenge/response events, results |
| [`telnet`](#telnet) | Telnet | TCP | 23, 2323 | typed usernames and passwords, failures |
| [`irc`](#irc) | IRC | TCP | 194, 6667, 6697 | PASS, NICK, NickServ IDENTIFY, SASL PLAIN |
| [`http`](#http) | HTTP | TCP | 80, 3128, 8000, 8008, 8080, 8081, 8888 | Basic, forms, JSON, tokens, API keys, cookies, JWTs, Digest/NTLM/Negotiate events, URLs, searches, POST bodies, results |
| [`http2`](#http2) | HTTP/2 | TCP | 80, 443, 8080, 8443 | as `http`, for h2c and decrypted h2 |
| [`ntlm`](#ntlm) | NTLM | TCP | 135, 139, 389, 445, 593, 1433, 3268 | NTLM authentications in any binary carrier |
| [`kerberos`](#kerberos) | Kerberos | UDP, TCP | 88 | pre-auth encryption types, no-preauth accounts, weak tickets, failures |
| [`snmp`](#snmp) | SNMP | UDP | 161, 162 | v1/v2c communities, v3 security levels |
| [`ldap`](#ldap) | LDAP | TCP | 389, 3268 | simple binds, SASL PLAIN, SASL events, results |
| [`mysql`](#mysql) | MySQL | TCP | 3306 | cleartext-password logins, login events, results |
| [`postgres`](#postgresql) | PostgreSQL | TCP | 5432 | cleartext-password logins, MD5/SCRAM/trust events, results |
| [`mssql`](#mssql) | MSSQL | TCP | 1433 | LOGIN7 credentials, Windows-auth events, encryption mode, results |
| [`oracle`](#oracle) | Oracle | TCP | 1521 | connect descriptors, O5LOGON events, refusals, results |
| [`redis`](#redis) | Redis | TCP | 6379 | AUTH / HELLO AUTH, results |
| [`mqtt`](#mqtt) | MQTT | TCP | 1883 | CONNECT username/password, results |
| [`sip`](#sip) | SIP | UDP, TCP | 5060 | Basic credentials, Digest events, results |
| [`vnc`](#vnc) | VNC | TCP | 5900–5906 | security type, unauthenticated sessions, results |
| [`rdp`](#rdp) | RDP | TCP | 3389 | negotiated security (NLA or not), `mstshash` usernames |
| [`radius`](#radius) | RADIUS | UDP | 1645, 1646, 1812, 1813 | PAP/CHAP/MS-CHAP/EAP events, EAP identities, results |
| [`tacacs`](#tacacs) | TACACS+ | TCP | 49 | unencrypted-mode credentials, authorisation/accounting, results |
| [`secrets`](#secrets) | Cleartext | TCP | any | cloud and API keys, PEM private keys |
| [`keyvalue`](#keyvalue) | Cleartext | TCP | any | `user=... pass=...` patterns (heuristic) |

## Common behaviour

**Detection is by content.** Every TCP plugin is offered every TCP connection, and every UDP plugin every UDP conversation, whatever the ports. The port hints only help the engine decide which side is the server. A plugin stops receiving a connection (it *detaches*) as soon as the traffic is clearly not its protocol. None of the built-in plugins is restricted to its ports.

**Non-standard ports.** Most plugins tag findings `nonstandard-port` when the service runs on a port other than its usual one.

**Login results.** Where a protocol reports the outcome of a login, the plugin emits an `auth_result` finding with `login succeeded` or `login failed` (or a protocol-specific wording that contains it). Results are reported from client to server, like the login they belong to.

**Capture gaps.** When bytes are missing from a stream, a plugin never joins the bytes on either side of the hole into a credential. What it does instead:

| Behaviour | Plugins |
| --- | --- |
| drop the damaged line and continue at the next one | `ftp`, `mail`, `irc`, `telnet`, `keyvalue` |
| resynchronise on the next message | `http`, `ldap`, `redis`, `sip` (TCP), `mysql` (after login), `postgres` (after the StartupMessage) |
| discard buffered bytes and keep scanning | `ntlm`, `kerberos` (TCP), `secrets` |
| ignore gaps in data it no longer reads | `mqtt` (client data after the CONNECT) |
| stop analysing the connection | `http2`, `vnc`, `mssql`, `oracle`, `tacacs`, `rdp`; `mysql`, `postgres`, `sip` and `mqtt` before the points above |

Length-framed protocols have no sync marker. `mysql` and `postgres` therefore resume at the next TCP segment that consists of whole messages (data after a gap always starts a segment), and wait for another segment otherwise. `sip` resumes at the next line that is a SIP request or status line.

**One secret, one finding.** When two plugins report the same secret in the same connection (an API key in an HTTP request is found by both `http` and `secrets`), the later report is counted as a duplicate, unless it adds a user name the earlier one lacked (an HTTP form login whose password `secrets` already saw as a bare token is still reported as a credential). Usually `http` reports first, because it runs earlier; if the request body arrives in pieces, `secrets` may see the complete key first. `--dedup off` keeps both.

**TLS.** When a key log is supplied, plugins receive decrypted data after a TLS handshake or STARTTLS, and their findings are tagged `tls-decrypted`. Without keys, plugins stop at STARTTLS. See [TLS decryption](../guide/tls-decryption.md).

**Challenge/response material is never extracted.** For every protocol below, digests, challenges, responses, tickets, salts, nonces and obfuscated fields are consumed only to stay aligned with the stream. They are never placed in a finding.

---

## FTP

Plugin `ftp`. Cleartext FTP logins.

| Finding | Kind | Risk | Notes |
| --- | --- | --- | --- |
| `USER` + `PASS` | `credential` | high | |
| `PASS` without `USER` | `password` | high | only once an FTP greeting or port 21 confirms the protocol |
| `USER` without `PASS` | `username` | info | reported when the connection ends |
| `ACCT` | `password` | medium | `extra.command = "ACCT"` |
| reply 230 / 530 / 430 | `auth_result` | info | `extra.reply` holds the server line (120 characters max) |

Tags: `nonstandard-port` when the server port is not 21.

Look-alike protocols: the plugin detaches when it sees a POP3 or IMAP greeting, a POP3/IMAP port without an FTP greeting, IRC/SMTP commands (`NICK`, `EHLO`, `HELO`, `CAP`), or an IRC-style `USER` with several arguments. It also detaches after 16 KiB of client data without a `USER`.

## SMTP, POP3, IMAP

Plugin `mail`. The protocol label is `SMTP`, `POP3` or `IMAP`, decided from the greeting and commands.

| Finding | Kind | Risk |
| --- | --- | --- |
| `AUTH PLAIN` (initial response or continuation) | `credential` | high |
| `AUTH LOGIN` username + password | `credential` | high |
| POP3 `USER` + `PASS` | `credential` | high |
| IMAP `LOGIN` (atoms, quoted strings and literals) | `credential` | high |
| IMAP `AUTHENTICATE PLAIN`/`LOGIN` | `credential` | high |
| `AUTH XOAUTH2` / `OAUTHBEARER` | `token` | high |
| `AUTH CRAM-MD5` | `auth_event` "CRAM-MD5 (challenge-response)" | medium |
| POP3 `APOP` | `auth_event` "APOP (MD5 challenge-response)" | medium |
| `AUTH NTLM` | `auth_event` "NTLMv1/NTLMv2 authentication" | high for NTLMv1, else medium |
| server verdict after a login (SMTP `235`/`535`, POP3 `+OK`/`-ERR`, IMAP tagged `OK`/`NO`) | `auth_result` | info |

`extra.mechanism` names the SASL mechanism. An `AUTH LOGIN` exchange abandoned before the password is not reported as a credential, and CRAM-MD5 never puts digest material in the username.

STARTTLS: parsing stops when the session upgrades to TLS, unless TLS is being decrypted with a key log.

## Telnet

Plugin `telnet`. Usernames and passwords typed after login prompts.

| Finding | Kind | Risk |
| --- | --- | --- |
| username and password typed after `login:` / `Password:` prompts | `credential` | high |
| password without a username prompt | `password` | high |
| username alone | `username` | info |
| failure message after the password ("Login incorrect", "Authentication failed", "Access denied", "% Bad passwords", "Login failed") | `auth_result` "login failed" | info |

How it works:

- Telnet option negotiation (IAC sequences, RFC 854) is stripped statefully, so it never hides keystrokes.
- Character-by-character input is collected and backspace/delete editing is applied, so the reported value is what the user finally submitted.
- Prompts are recognised in server output: `username:`, `user name:`, `login:`, and `password:`/`passcode:` (optionally `for <user>`).
- Streams that start like another protocol (HTTP, SIP, RTSP, POP3, IMAP, FTP/SMTP `220`) are ignored, so prompts inside an HTTP response are not taken for a Telnet login.

**Heuristic matches.** On a port other than 23/2323 and without real Telnet option negotiation, findings are tagged `heuristic` with confidence 0.6. With `--option telnet.strict=true` (or `--strict-heuristics`) they are not reported at all. On such connections a "typed" value that contains control bytes is binary protocol data, not keyboard input, and is not reported.

## IRC

Plugin `irc`.

| Finding | Kind | Risk |
| --- | --- | --- |
| `PASS` (server password) | `password` | high |
| `NICK` | `username` | info |
| `PRIVMSG NickServ :IDENTIFY ...`, `NS IDENTIFY ...` | `credential` (nick + password) | high |
| `AUTHENTICATE PLAIN` (SASL) | `credential` | high |

## HTTP

Plugin `http`. HTTP/1.0 and 1.1 requests and responses are parsed as real messages: Content-Length and chunked bodies, pipelining, `HEAD` responses without bodies, interim `1xx` responses, and resynchronisation on the next request after a gap.

| Finding | Kind | Risk | Notes |
| --- | --- | --- | --- |
| `Authorization: Basic` | `credential` | high | `extra.mechanism = "Basic"`; also `Proxy-Authorization` |
| `Authorization: Bearer` | `token` | high | `extra.token_type = "JWT"` when it is a JWT |
| `Authorization: Digest` | `auth_event` "HTTP Digest (MD5)" | medium | user and realm only |
| `Authorization: NTLM`/`Negotiate` with NTLM | `auth_event` "NTLMv2 authentication over HTTP" | high for NTLMv1, else medium | user, domain, workstation |
| `Negotiate` with Kerberos | `auth_event` "Kerberos (SPNEGO) authentication over HTTP" | low | |
| form, JSON or query-string login fields | `credential` (or `password`) | high | `extra.mechanism` is `form` or `query string` |
| API-key header (`X-API-Key`, `Api-Key`, `X-Auth-Token`, `X-Access-Token`, `Private-Token`, ...) | `api_key` | high | |
| API-key parameter (`api_key`, `apikey`, `access_token`, `auth_token`, `token`, `key`; 8+ characters) | `api_key` or `token` | high | |
| session cookie | `cookie` | medium | see the `cookies` option |
| JWT anywhere else in headers or body | `token` | high | `extra.token_type = "JWT"` |
| request URL | `url` | info | static resources (images, CSS, JS, fonts) are skipped |
| search parameter (`q`, `query`, `search`, `keywords`, ...) | `search` | info | |
| printable POST body | `post` | info | |
| response 401/403/407 after credentials | `auth_result` "... login failed (HTTP 401)" | info | |
| other final response after Basic/Digest/NTLM/Bearer | `auth_result` "... login succeeded (HTTP 200)" | info | |

Login field names come from the original net-creds list (`user`, `username`, `login`, `email`, `pass`, `password`, `passwd`, `pwd`, `j_username`, `user[password]`, ...) and are matched exactly, case-insensitively. JSON bodies are flattened, so `{"user": {"email": ..., "password": ...}}` is found.

**Form logins report only failures.** Sites answer a failed form login with 200 or 302 as often as a successful one, so only 401/403/407 are reported.

Options: `cookies` (`session`, `all`, `off`) and `urls` (true/false). See [plugin options](plugin-options.md#http-and-http2).

## HTTP/2

Plugin `http2`. The same findings as `http`, with protocol `HTTP/2` and results worded "(HTTP/2 401)".

- Followed connections are those that start with the HTTP/2 client connection preface: prior-knowledge h2c, or h2 inside TLS once decrypted with a key log.
- Frames are parsed per direction, header blocks are decompressed with a full HPACK decoder (checked against the RFC 7541 test vectors), and each request stream is analysed when it ends.
- Not followed: h2c reached through an HTTP/1.1 `Upgrade: h2c` exchange (the upgrade request itself is seen by `http`), and connections captured mid-stream, because the HPACK state is unknown.
- A gap ends analysis of the connection: HPACK state cannot be recovered.

Options: as for `http`.

## NTLM

Plugin `ntlm`. NTLMSSP messages in any binary TCP carrier: SMB, SMB2, LDAP, MSSQL, DCE-RPC, HTTP... It scans for the `NTLMSSP\0` signature, so it works without understanding the carrier.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| NTLM AUTHENTICATE message | `auth_event` "NTLMv1 authentication" / "NTLMv2 authentication" | high for NTLMv1, else medium | `ntlmv1` for v1 |

`extra`: `workstation`, `ntlm_version`, `target` (from the server's CHALLENGE), `server_port`, and `event_id`. The event id is a hash of non-secret metadata (endpoints, time, frame, identity), never of the message, which contains the NT response.

Anonymous authentications are not reported. Each identity is reported once per connection. NTLM inside HTTP or SMTP headers is base64 and is reported by `http` and `mail` instead. NTLM inside an MSSQL login is reported by both `ntlm` and `mssql`, with complementary details.

## Kerberos

Plugin `kerberos`. AS-REQ, AS-REP, TGS-REP and KRB-ERROR over UDP and TCP (record-marked). Only metadata is reported; encrypted parts are never extracted.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| AS-REQ with encrypted-timestamp pre-authentication | `auth_event` "Kerberos pre-authentication (*etype*)" | high for DES, medium for RC4, low for AES | `weak-preauth-<etype>` for DES/RC4; `weak-etype-offered` if the client offers DES/RC4 |
| AS-REQ with PKINIT (certificate) or FAST-armored pre-authentication | `auth_event` "Kerberos pre-authentication (PKINIT)" / "(FAST armored)" | low | `pkinit` or `fast`; `anonymous` for `WELLKNOWN/ANONYMOUS` |
| AS-REP to a request without any pre-authentication | `auth_event` "AS-REP issued without pre-authentication" | high | `no-preauth` |
| TGS-REP with a DES/RC4 service ticket | `auth_event` "service ticket for *service* issued with *etype*" | per etype | `weak-service-ticket` |
| KRB-ERROR: pre-authentication failed (24), unknown principal (6), account expired (1), account disabled or locked out (18), password expired (23) | `auth_result` | info | `extra.outcome = "failure"`, `extra.error_code` |

Encryption types: `des-cbc-crc` (1), `des-cbc-md5` (3), `aes128-cts-hmac-sha1-96` (17), `aes256-cts-hmac-sha1-96` (18), `aes128-cts-hmac-sha256-128` (19), `aes256-cts-hmac-sha384-192` (20), `rc4-hmac` (23), `rc4-hmac-exp` (24). DES and `rc4-hmac-exp` are high risk, `rc4-hmac` medium.

The principal is in `username` and the realm in `domain`. `extra` carries `preauth_etype` (or `preauth` for PKINIT/FAST), `offered_etypes`, `service`, `ticket_etype` as relevant. Other KRB-ERROR codes, such as 14 (no key for the offered encryption types), are not login results.

## SNMP

Plugin `snmp`. UDP only.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| v1/v2c request with a community string | `community` | high | `write-access` for SetRequest; `default-community` for `public`, `private`, `community`, `admin`, `cisco`, `manager`, `snmp` |
| v3 noAuthNoPriv | `auth_event` "SNMPv3 noAuthNoPriv" | high | `snmpv3-noAuthNoPriv` |
| v3 authNoPriv | `auth_event` "SNMPv3 authNoPriv" | medium | `snmpv3-authNoPriv` |
| v3 authPriv | `auth_event` "SNMPv3 authPriv" | info | |

`extra`: `version`, `pdu`, and for v3 `security_level` and `engine_id`. Each community or v3 user is reported once per conversation.

## LDAP

Plugin `ldap`. BER-encoded LDAP over TCP, resynchronising on the next message after a gap.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| simple bind with a password | `credential` (DN as username) | high | |
| simple bind with a DN and an empty password (unauthenticated bind) | `username` | medium | `unauthenticated-bind` |
| SASL PLAIN bind | `credential` | high | |
| other SASL mechanisms (GSSAPI, GSS-SPNEGO, DIGEST-MD5, EXTERNAL...) | `auth_event` "LDAP SASL bind (*mechanism*)" | low | |
| bind response | `auth_result` | info | `extra.result_code`; any code except 0 and 14 (saslBindInProgress) is a failure |

StartTLS: a successful StartTLS ends parsing unless TLS is decrypted; a failed one keeps parsing. NTLM inside SASL is reported by `ntlm`.

## MySQL

Plugin `mysql`. MySQL and MariaDB: server greeting, HandshakeResponse41, AuthSwitch, COM_CHANGE_USER, OK/ERR.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| `mysql_clear_password` login | `credential` | high | `cleartext-password` |
| login with an empty auth response | `auth_event` | high | `empty-password` |
| `mysql_native_password`, `caching_sha2_password`, other plugins | `auth_event` "MySQL login (*plugin*)" | medium | |
| AuthSwitch to another plugin | a second `auth_event` | | |
| `COM_CHANGE_USER` on an open connection | `auth_event` "MySQL change user (*plugin*)", then its own result | as for a login | `change-user` |
| OK / ERR during authentication | `auth_result` | info | `extra.error_code` on failure |

Pre-4.1 logins are reported as events (the wire field is a scramble). TLS (SSL request) ends parsing unless decrypted. After a successful login the plugin follows the command phase only to catch `COM_CHANGE_USER`: only packets with sequence id 0 are read as commands, so `LOAD DATA` contents and continuation packets are never mistaken for one. Queries are not looked at, and packets over 64 KiB are skipped. The compressed protocol (`CLIENT_COMPRESS`), whose framing changes after the login, ends parsing. A capture gap during the first login ends parsing; after it, the plugin resumes at the next client segment that starts with a command (sequence id 0) and the next server segment made of whole packets with consecutive sequence ids, so a later `COM_CHANGE_USER` is still found.

## PostgreSQL

Plugin `postgres`. StartupMessage, authentication requests, PasswordMessage.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| cleartext password authentication | `credential` | high | `cleartext-password` |
| MD5 password authentication | `auth_event` "PostgreSQL MD5 password authentication" | medium | |
| SCRAM authentication | `auth_event` "PostgreSQL SCRAM authentication" | low | |
| `AuthenticationOk` without any challenge (trust) | `auth_event` "PostgreSQL login without password (trust)" | high | `no-authentication` |
| result | `auth_result` | info | `extra.sqlstate` on failure |

The user and database come from the StartupMessage. Kerberos/GSS/SSPI produce no event of their own; a following AuthenticationOk is reported as success. An SSLRequest answered `S` ends parsing unless decrypted. After a capture gap the plugin resumes at the next segment made of whole messages. If the gap was on the server side, an AuthenticationOk is reported as a plain success, not as trust, because the lost bytes may have held an authentication request; a password message after a lost request is not reported.

## MSSQL

Plugin `mssql`. Microsoft SQL Server TDS: PRELOGIN, LOGIN7, login acknowledgement and errors.

The LOGIN7 password is only *obfuscated* with a fixed public transform (nibble swap and XOR 0xA5), which is not encryption. A LOGIN7 seen in cleartext exposes the password, so it is de-obfuscated and reported.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| SQL login (LOGIN7 in cleartext) | `credential` | high | `cleartext-password`, `empty-password`, `password-change` as applicable |
| Windows (SSPI) login | `auth_event` "MSSQL Windows authentication" | medium with NTLM, else low | user and domain from an NTLM AUTHENTICATE if present |
| login inside TLS (encryption negotiated in PRELOGIN) | `auth_event` "MSSQL login (*encryption mode*)" | info | `encrypted`; `login-only` when only the login packet is encrypted |
| LOGINACK / login error | `auth_result` | info | failure codes 18456, 18452, 18470, 18486, 18487, 18488 |

`extra`: `encryption`, `tds_version`, `mechanism`, `error_code`, `message`. Encryption modes follow MS-TDS: when encryption is negotiated the LOGIN7 travels inside TLS and is only visible with a key log; `ENCRYPT_OFF` on both sides still encrypts the login packet alone, after which the session continues in cleartext. Federated (Azure AD) authentication is not parsed.

## Oracle

Plugin `oracle`. Oracle Net (TNS) CONNECT, ACCEPT, REFUSE and DATA packets.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| CONNECT descriptor (service or SID, client program, host, OS user) | `info` "Oracle TNS connect (...)" | low | |
| REFUSE | `info` "Oracle TNS connect refused (ORA-nnnnn)" | info | |
| O5LOGON authentication | `auth_event` "Oracle O5LOGON login" | medium | `auth-phase-one`, `auth-phase-two` |
| native network encryption | `auth_event` "Oracle login (native network encryption)" | info | `encrypted`, `ano-encryption` |
| login result | `auth_result` | info | `extra.error_code` (for example ORA-01017) |

Only allow-listed client attributes of the AUTH request are read (terminal, program, machine, PID, OS user). `AUTH_SESSKEY`, `AUTH_PASSWORD`, `AUTH_VFR_DATA` and every other `AUTH_*` value are never read into a finding. The username is taken heuristically from the TTI layout, which varies between client libraries. TTI messages carry no length of their own, so the client's DATA packets are collected until the server answers (or the connection ends) and scanned as one request: an AUTH request split across several DATA packets is found, and the finding points at the request's last packet.

## Redis

Plugin `redis`. RESP arrays and inline commands.

| Finding | Kind | Risk |
| --- | --- | --- |
| `AUTH password` | `password` | high |
| `AUTH user password` (ACL) or `HELLO ... AUTH user password` | `credential` | high |
| reply to AUTH (`+OK` / `-ERR`, `-WRONGPASS`) | `auth_result` | info |

Replies are matched to commands in order. The plugin resynchronises on the next message after a gap; AUTH commands pending at the gap get no result. A server that speaks first means the flow is not Redis. RESP3 push messages are not handled.

## MQTT

Plugin `mqtt`. MQTT 3.1, 3.1.1 and 5.

| Finding | Kind | Risk |
| --- | --- | --- |
| CONNECT with username and password | `credential` | high |
| CONNECT with a password only | `password` | high |
| CONNECT with a username only | `username` | info |
| CONNACK | `auth_result` | info |

`extra`: `client_id`, `protocol_level`, `return_code`. Results are reported only when the CONNECT carried a username. Return codes 4/5 (v3.1/3.1.1) and 0x86/0x87 (v5) are failures. Client bytes lost after the CONNECT do not stop the plugin from reading the CONNACK. MQTT over WebSocket is not handled.

## SIP

Plugin `sip`. SIP over UDP and TCP.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| `Authorization: Basic` | `credential` | high | `basic-auth` |
| `Authorization`/`Proxy-Authorization: Digest` | `auth_event` "SIP Digest authentication (*method*)" | medium | `digest` |
| final response to an authenticated request | `auth_result` "SIP authentication succeeded/failed" | info | |

Digest events report user, realm, method, URI and algorithm (MD5 when absent, as the RFC specifies); nonces and responses are never read. Each (user, realm) is reported once per conversation. Over TCP, after a capture gap the plugin skips to the next SIP request or status line; a response only counts as a result if its Call-ID and CSeq match a request that carried credentials. LF-only line endings and SIP over TLS (5061) are not supported.

## VNC

Plugin `vnc`. The RFB handshake: version, security types, VNC authentication and SecurityResult.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| security type None | `auth_event` "VNC session without authentication" | high | `no-authentication` |
| VNC Authentication (DES challenge/response) | `auth_event` | medium | `challenge-response`, `unencrypted-session` |
| other security types (VeNCrypt, TLS, RA2, ...) | `auth_event` "VNC security type *name*" | low | `non-vnc-auth` |
| SecurityResult | `auth_result` | info | result 2 ("too many attempts") is a failure |

The 16-byte challenge and response are consumed to stay aligned, never retained. Analysis stops after a non-VNC security type.

## RDP

Plugin `rdp`. Only the cleartext start of a connection (MS-RDPBCGR 2.2.1.1–2.2.1.2): the X.224 Connection Request with its routing cookie and requested protocols, and the server's Connection Confirm.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| `Cookie: mstshash=<user>` | `username` | low | `rdp-cookie` |
| standard RDP security selected | `auth_event` | high | `no-nla`, `standard-rdp-security` |
| TLS without NLA | `auth_event` "RDP over TLS without Network Level Authentication" | medium | `no-nla`, `tls` |
| NLA (CredSSP) | `auth_event` "RDP with ... authentication over TLS" | low | |
| negotiation failure | `auth_event` "RDP negotiation failed (...)" | info | `negotiation-failed` |
| no server confirm; the client offered only standard security | `auth_event` "RDP client offered only standard RDP security (no NLA, no TLS)" | low | `no-nla`, `no-response` |
| no server confirm, otherwise | `auth_event` "RDP negotiation incomplete (no server response)" | info | `no-response` |

Everything after negotiation is TLS/CredSSP or RDP's own RC4 encryption; the plugin stops there. Load-balancer `msts=` routing tokens are not usernames. Clients pad short cookie names with spaces; the padding is removed. NTLM inside CredSSP is visible only with a key log, through `ntlm`.

## RADIUS

Plugin `radius`. RADIUS authentication and accounting over UDP (RFC 2865/2866/3579).

RADIUS hides `User-Password` with an MD5 keystream derived from the shared secret. The secret is never guessed or derived and the hidden bytes are never extracted.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| Access-Request with PAP, CHAP or MS-CHAP | `auth_event` "RADIUS *method* login" | medium | |
| EAP, non-tunnelled methods (MD5, GTC, OTP, LEAP, MS-CHAPv2...) | `auth_event` "RADIUS EAP (*method*) login" | medium | |
| EAP, tunnelled methods (TLS, TTLS, PEAP, FAST, TEAP) | `auth_event` | info | |
| EAP-Response/Identity | `username` | low | `eap-identity` |
| Accounting-Request | `info` "RADIUS accounting *status*" | info | |
| Access-Accept / Access-Reject | `auth_result` | info | |

NAS details (`nas_ip`, `nas_id`, port) are added to `extra`. Retransmissions are reported once. Trailing padding after the RADIUS length is accepted only on standard ports.

## TACACS+

Plugin `tacacs`. TACACS+ over TCP (RFC 8907).

Bodies are only parsed when the header carries `TAC_PLUS_UNENCRYPTED_FLAG`. In that mode ASCII and PAP passwords cross the wire in cleartext.

| Finding | Kind | Risk | Tags |
| --- | --- | --- | --- |
| ASCII or PAP login with user | `credential` | high | `cleartext-password` |
| ASCII or PAP password without user | `password` | high | `cleartext-password` |
| password change | `password` | high | `new-password` |
| CHAP, MS-CHAP, ARAP login | `auth_event` "TACACS+ *type* login" | medium | |
| authorisation / accounting request | `info` "TACACS+ *what*: *command*" | low | `sensitive-arguments` when arguments contain password, secret, key or community |
| authentication reply PASS / FAIL | `auth_result` | info | |
| encrypted (obfuscated) body | `auth_event` "TACACS+ session (encrypted body)" | info | `obfuscated-body`; once per connection |

Encrypted bodies are never decrypted and the shared key is never guessed.

## Secrets

Plugin `secrets`, protocol label `Cleartext`. Scans every cleartext TCP stream, in both directions and on any port, for credential formats with distinctive shapes.

| Detector (`extra.detector`) | Matches |
| --- | --- |
| `aws_access_key` | `AKIA...`/`ASIA...` key ids. Paired with a 40-character secret access key found within 200 bytes: the key id goes in `username`, the secret in `secret`, and `extra.paired_secret` is true. A key id alone is reported at medium risk, tagged `key-id-only` |
| `gcp_api_key` | `AIza...` API keys |
| `gcp_service_account` | a service-account key file (`private_key_id` and a `client_email` ending in `.gserviceaccount.com`) |
| `azure_storage_key` | `AccountKey=...` in a connection string (with `AccountName` when present) |
| `azure_sas_token` | SAS tokens (`sig=...`) |
| `github_token`, `github_pat` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` tokens and fine-grained `github_pat_...` tokens |
| `slack_token` | `xoxb-`/`xoxa-`/`xoxp-`/`xoxr-`/`xoxs-` tokens |
| `stripe_secret_key` | `sk_live_`/`rk_live_` keys |
| `pem_private_key` | `-----BEGIN ... PRIVATE KEY-----` blocks |

All are `api_key` findings, at high risk unless noted. The token goes in `secret`. PEM blocks are reported by type and length only ("PEM RSA PRIVATE KEY block (1679 bytes)"); the key body is never kept.

Scanning uses a sliding window, so tokens split across segments are found. It is capped at 1 MiB per direction per connection, skips connections that start with a TLS record, and resets at capture gaps. Each token is reported once per connection. JWTs are left to `http`. An API key that `http` also reports in the same connection is reported once (see *One secret, one finding* above).

## Keyvalue

Plugin `keyvalue`, protocol label `Cleartext`. A heuristic that keeps the original net-creds' coverage of `user=...` / `pass=...` pairs in arbitrary protocols.

| Finding | Kind | Risk | Confidence |
| --- | --- | --- | --- |
| a password field, with a user field on the same line | `credential` | medium | 0.5 |
| a password field alone | `password` | medium | 0.5 |

Field names are the same as the HTTP form fields. Streams that start like HTTP are skipped (the `http` plugin parses them properly). `extra.pattern` shows which fields matched. Template and masked values are not secrets and are skipped: `****`, `xxxx` (four or more), `%s`, `%(name)s`, `${VAR}`, an all-capitals `$VAR`, `{{ var }}`, `<password>`, `[REDACTED]`, `null`, `none`, `nil`, `undefined`, and empty quotes. Values such as `$Secret1` or `xx` are reported. A real value later on the same line is still reported. Disable with `--disable keyvalue` or `--strict-heuristics`.
