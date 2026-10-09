# Quickstart

This walkthrough uses the synthetic captures shipped in the repository under `tests/fixtures/synthetic/`. They contain obviously fake credentials and documentation IP addresses (`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`), so you can follow along from a checkout without any capture of your own. All output below is real output from those files.

## 1. Analyse a capture

```console
$ netcreds-ng -p tests/fixtures/synthetic/ftp_basic.pcap
16:13:20 HIGH   FTP       credential 192.0.2.10:50000 > 198.51.100.20:21 fakeuser:FakePass-123  #cleartext
16:13:20 INFO   FTP       result     192.0.2.10:50000 > 198.51.100.20:21 login succeeded
```

Each line is one **finding**:

| Column | Example | Meaning |
| --- | --- | --- |
| time | `16:13:20` | when the packet was captured (local time) |
| risk | `HIGH` | `INFO`, `LOW`, `MEDIUM` or `HIGH`; see [risk levels](concepts.md#risk) |
| protocol | `FTP` | the protocol the finding came from |
| kind | `credential` | what was found; see [kinds](concepts.md#kinds) |
| endpoints | `192.0.2.10:50000 > 198.51.100.20:21` | client > server |
| value | `fakeuser:FakePass-123` | the credential, or a description |
| tags | `#cleartext` | extra facts added by plugins and enrichers |

The second line is a *login result*: the server accepted the login. netcreds-ng tracks results for most protocols, so you know which exposed credentials actually work.

## 2. Analyse a whole directory

Point `-p` at a directory to analyse every capture file in it (`.pcap`, `.pcapng`, `.cap`, `.dmp`), in name order:

```console
$ netcreds-ng -p tests/fixtures/synthetic/
16:13:20 HIGH   FTP       credential 192.0.2.10:50000 > 198.51.100.20:21 fakeuser:FakePass-123  #cleartext
16:13:20 INFO   FTP       result     192.0.2.10:50000 > 198.51.100.20:21 login succeeded
16:13:20 HIGH   FTP       credential 192.0.2.10:50001 > 198.51.100.20:2121 nonstd:Nonstd-Pass-9  #nonstandard-port #cleartext
16:13:20 INFO   FTP       result     192.0.2.10:50001 > 198.51.100.20:2121 login failed
16:13:20 INFO   HTTP      url        192.0.2.10 GET www.example.com/admin
16:13:20 HIGH   HTTP      credential 192.0.2.10:50008 > 198.51.100.20:80 basicuser:Basic-Fake-Pass  #cleartext
16:13:20 INFO   HTTP      result     192.0.2.10:50008 > 198.51.100.20:80 Basic login succeeded (HTTP 200)
...
16:13:20 MEDIUM Kerberos  auth       192.0.2.10:51001 > 198.51.100.20:88 Kerberos pre-authentication (rc4-hmac)  #weak-etype-offered #weak-preauth-rc4-hmac
16:13:20 HIGH   Kerberos  auth       192.0.2.10:51003 > 198.51.100.20:88 AS-REP issued without pre-authentication  #no-preauth
16:13:20 HIGH   NTLM      auth       192.0.2.10:50012 > 198.51.100.20:445 NTLMv1 authentication  #ntlmv1
16:13:20 HIGH   SNMP      community  192.0.2.10:50101 > 198.51.100.20:161 public  #write-access #default-community #cleartext
16:13:20 HIGH   SNMP      auth       192.0.2.10:50102 > 198.51.100.20:161 SNMPv3 noAuthNoPriv  #snmpv3-noAuthNoPriv
16:13:20 HIGH   Telnet    credential 192.0.2.10:50002 > 198.51.100.20:23 telnetuser:Telnet-Fake-1  #cleartext
```

Note the FTP login on port 2121: detection is by content, not by port, so it is found anyway and tagged `nonstandard-port`.

## 3. Read the run summary

After the findings, netcreds-ng prints a summary. Here is the one for the directory above, shortened:

```text
Run summary
  Frames       246        Decoded                  246
  TCP flows    19         UDP flows                11
  Findings     47         Duplicates suppressed    1
  TCP gaps     0 (0 B)    Retransmitted            10 B
Findings by protocol
| HTTP     |       15 |
| FTP      |        9 |
| Kerberos |        6 |
...
Risk: 20 high  4 medium  1 low   weak passwords: 0   reused secrets: 0
Most exposed hosts
| Host          | Risk | As client | As server | Protocols                              | Accounts            |
| 192.0.2.10    | high | 26        | 0         | FTP, HTTP, IMAP, IRC, Kerberos, NTLM,  | EXAMPLE.TEST\...    |
Services exposing cleartext secrets
| Server             | Protocol | Accounts                          | Logins ok/failed |
| 198.51.100.20:80   | HTTP     | FAKEDOM\ntlmuser, basicuser, ...  | 2/1              |
| 198.51.100.20:21   | FTP      | fakeuser, splituser, vlanuser     | 2/0              |
...
```

- **Run summary**: what the engine processed. Gaps, retransmissions, truncated frames and errors are counted here rather than hidden.
- **Risk**: findings per risk level, plus weak and reused passwords.
- **Most exposed hosts**: hosts ranked by the worst exposure they were involved in.
- **Services exposing cleartext secrets**: the servers you should fix first, with how many of their logins succeeded.
- **Alerts** and **Warnings** sections appear when there is something to show.

## 4. Write outputs

Outputs can be combined freely:

```bash
netcreds-ng -p tests/fixtures/synthetic/ --html report.html --jsonl findings.jsonl
```

- `report.html` is a self-contained audit report with an executive summary, timeline, service inventory and host scores. Secrets are masked in it by default.
- `findings.jsonl` has one JSON object per finding:

```json
{"confidence": 1.0, "display": "fakeuser:FakePass-123", "dst": "198.51.100.20:21", "extra": {"secret_fingerprint": "6c24b7bbea132a77"}, "frame": 7, "kind": "credential", "plugin": "ftp", "protocol": "FTP", "risk": "high", "secret": "FakePass-123", "src": "192.0.2.10:50000", "tags": ["cleartext"], "timestamp": "2023-11-14T22:13:20.060000+00:00", "username": "fakeuser"}
```

`frame` is the frame number in the capture, as Wireshark numbers it, so you can jump straight to the packet. See [outputs and integrations](../reference/outputs.md) for every format.

## 5. Mask secrets before sharing

```console
$ netcreds-ng -p tests/fixtures/synthetic/http_form.pcap --mask
16:13:20 INFO   HTTP      url        192.0.2.10 POST app.example.com/login
16:13:20 HIGH   HTTP      credential 192.0.2.10:50009 > 198.51.100.20:8080 formuser:F************s (14)  #cleartext
16:13:20 INFO   HTTP      post       192.0.2.10 username=formuser&password=F************s (14)&remember=1
```

A masked value keeps its first and last character and its length. Secrets embedded in POST bodies, URLs and headers are masked too.

## 6. See alerts: simulate a brute-force attack

The `netcreds_ng.testing` package builds packets without any capture hardware. This script writes a capture in which one client fails six FTP logins and then succeeds with a weak password:

```python title="brute.py"
import sys

from netcreds_ng.testing.packets import TCPConversation, write_pcap

frames = []
for i in range(6):
    c = TCPConversation("192.0.2.66", 51000 + i, "198.51.100.21", 21).handshake()
    c.server(b"220 FTP ready\r\n").client(b"USER admin\r\n").server(b"331 Password required\r\n")
    c.client(b"PASS guess-%d\r\n" % i).server(b"530 Login incorrect.\r\n").close()
    frames += c.frames

c = TCPConversation("192.0.2.66", 51009, "198.51.100.21", 21).handshake()
c.server(b"220 FTP ready\r\n").client(b"USER admin\r\n").server(b"331 Password required\r\n")
c.client(b"PASS password1\r\n").server(b"230 Login successful.\r\n").close()
frames += c.frames

write_pcap(sys.argv[1], frames)
```

```console
$ python brute.py brute.pcap
$ netcreds-ng -p brute.pcap --no-browsing
16:13:20 HIGH   FTP       credential 192.0.2.66:51000 > 198.51.100.21:21 admin:guess-0  #cleartext
16:13:20 INFO   FTP       result     192.0.2.66:51000 > 198.51.100.21:21 login failed
...
16:13:20 HIGH   FTP       credential 192.0.2.66:51004 > 198.51.100.21:21 admin:guess-4  #cleartext
16:13:20 INFO   FTP       result     192.0.2.66:51004 > 198.51.100.21:21 login failed
16:13:20 HIGH   FTP       ALERT      192.0.2.66 > 198.51.100.21:21 Brute force: 5 failed logins for 'admin' from 192.0.2.66 in under 1s  #brute-force
16:13:20 HIGH   FTP       credential 192.0.2.66:51005 > 198.51.100.21:21 admin:guess-5  #cleartext
16:13:20 INFO   FTP       result     192.0.2.66:51005 > 198.51.100.21:21 login failed
16:13:20 HIGH   FTP       credential 192.0.2.66:51009 > 198.51.100.21:21 admin:password1  #cleartext #weak-password
16:13:20 INFO   FTP       result     192.0.2.66:51009 > 198.51.100.21:21 login succeeded
16:13:20 HIGH   FTP       ALERT      192.0.2.66 > 198.51.100.21:21 Successful login as 'admin' after brute force from 192.0.2.66  #login-after-failures
```

- The fifth failure triggers a `brute-force` alert (the default threshold is 5 failures within 300 seconds).
- `password1` is on the packaged weak-password list, so that credential is tagged `weak-password`.
- The success after the burst raises `login-after-failures`, the alert that most deserves a look: someone guessed a working password.

See [alerts and analytics](../guide/detections.md) for every detection and its thresholds.

## Next steps

- [Core concepts](concepts.md): what the kinds, risks and tags mean.
- [Interactive dashboard](../guide/dashboard.md): `netcreds-ng -p capture.pcapng --tui`.
- [Recipes](../guide/recipes.md): common tasks, from SIEM ingestion to CI gates.
