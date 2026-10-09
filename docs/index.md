---
hide:
  - navigation
---

# netcreds-ng

**Find the credentials and weak authentication your network is exposing.**

netcreds-ng reads packet captures or live traffic and reports every credential that crosses the wire in cleartext. It also reports authentication that is technically protected but weak: NTLMv1, Kerberos RC4/DES, SNMPv3 without authentication, RDP without NLA, VNC without a password, and so on.

It is a **defensive auditing tool**. It shows you the exposure so you can fix it. It does not crack anything.

```console
$ netcreds-ng -p office.pcapng
16:13:20 HIGH   FTP       credential 192.0.2.10:50000 > 198.51.100.20:21 fakeuser:FakePass-123  #cleartext
16:13:20 INFO   FTP       result     192.0.2.10:50000 > 198.51.100.20:21 login succeeded
16:13:20 HIGH   HTTP      credential 192.0.2.10:50008 > 198.51.100.20:80 basicuser:Basic-Fake-Pass  #cleartext
16:13:20 MEDIUM Kerberos  auth       192.0.2.10:51001 > 198.51.100.20:88 Kerberos pre-authentication (rc4-hmac)  #weak-etype-offered #weak-preauth-rc4-hmac
16:13:20 HIGH   SNMP      community  192.0.2.10:50101 > 198.51.100.20:161 public  #write-access #default-community #cleartext
16:13:20 HIGH   NTLM      auth       192.0.2.10:50012 > 198.51.100.20:445 NTLMv1 authentication  #ntlmv1
```

<div class="grid cards" markdown>

-   :material-rocket-launch: **Get started**

    ---

    Install netcreds-ng and analyse your first capture in a few minutes.

    [:octicons-arrow-right-24: Installation](getting-started/installation.md) ·
    [Quickstart](getting-started/quickstart.md)

-   :material-book-open-variant: **User guide**

    ---

    Capture files, live capture, the dashboard, configuration, TLS decryption and alerts.

    [:octicons-arrow-right-24: User guide](guide/index.md)

-   :material-format-list-bulleted-type: **Reference**

    ---

    Every CLI option, every protocol, every finding field, every output format.

    [:octicons-arrow-right-24: Reference](reference/index.md)

-   :material-puzzle: **Extend it**

    ---

    Write protocol, enricher and output plugins against a versioned API, with a test SDK.

    [:octicons-arrow-right-24: Plugins](plugins/index.md) ·
    [API](api/index.md)

</div>

## What it does

**23 protocol plugins.**
:   FTP, Telnet, IRC, SMTP/POP3/IMAP, HTTP/1.x and HTTP/2, NTLM in any TCP carrier, Kerberos, SNMP, LDAP, MySQL, PostgreSQL, MSSQL, Oracle, Redis, MQTT, SIP, VNC, RDP, RADIUS and TACACS+. A detector also finds cloud and API keys (AWS, GCP, Azure, GitHub, Slack, Stripe, PEM private keys) in any cleartext stream. Detection is by content, so services on non-standard ports are found too. See the [protocol reference](reference/protocols.md).

**Real TCP stream reassembly.**
:   Credentials split across packets, out-of-order or retransmitted segments, IPv4/IPv6 fragments, VLAN, PPPoE, Linux cooked captures, loopback and raw IP. Streams picked up mid-connection and capture holes are handled without ever splicing bytes from both sides of a gap into a credential. See [the packet engine](architecture/engine.md).

**TLS decryption.**
:   With a key-log file (`SSLKEYLOGFILE`), plugins also see HTTPS, SMTPS, STARTTLS and the rest. TLS 1.2 and 1.3 are supported. See [TLS decryption](guide/tls-decryption.md).

**Behavioural alerts and risk analytics.**
:   Brute force, password spraying, one account attacked from many clients, and a success after a burst of failures. Weak passwords, password reuse, an inventory of services exposing cleartext secrets, and a 0–100 exposure score per host. See [alerts and analytics](guide/detections.md).

**Outputs for people and machines.**
:   A coloured console, an interactive dashboard, JSON Lines, CSV, SQLite, CEF, syslog, webhooks for Slack/Teams/Discord, a self-contained HTML audit report with an executive summary, and an evidence pcapng holding exactly the packets behind each finding. See [outputs and integrations](reference/outputs.md).

**Nothing dropped silently.**
:   Parsing problems, capture gaps, plugin errors, undecryptable TLS sessions and ambiguous connections are all counted and shown in the run summary. `--strict` turns them into a non-zero exit code.

**A plugin system.**
:   Protocols, enrichers and outputs are all plugins, discovered from installed packages, a directory, or the built-ins. See [writing plugins](plugins/index.md).

**Backwards compatible.**
:   It is the Python 3 successor of Dan McInerney's [net-creds](https://github.com/DanMcInerney/net-creds). `--legacy` reproduces the original's output byte for byte, which the test suite checks against output recorded from the original Python 2 tool. See [legacy mode](guide/legacy.md).

## What it does not do

netcreds-ng reports exposure. It never extracts or formats material for password cracking:

- Challenge/response authentication (NTLM, Kerberos, Digest, CRAM-MD5, SCRAM, MySQL native, O5LOGON, VNC, CHAP...) is reported as an **authentication event**: who authenticated, to what, and how weakly. The challenge, response, hash or ticket is never put in a finding.
- There is no hashcat/John export, no Kerberos roasting, and nothing that tests whether captured material is crackable.
- Obfuscated secrets protected by a shared key (RADIUS User-Password, encrypted TACACS+ bodies) are never decrypted and the key is never guessed.

Cleartext credentials, on the other hand, are reported in full, because they *are* the exposure. Use [`--mask`](guide/analysing-captures.md#masking-secrets) for anything you share.

!!! warning "Responsible use"

    Only analyse traffic you are authorised to inspect. Captures, evidence files, key logs and outputs contain real credentials: store them securely, use `--mask` for reports you share, and delete what you no longer need.
