# Testing plugins

`netcreds_ng.testing` builds deterministic network traffic in Python, without capture hardware or scapy, and runs it through the real engine. Every built-in plugin is tested this way.

## The harness

```python
from netcreds_ng.testing.harness import analyze

findings = analyze(frames)                                  # all built-in plugins and enrichers
findings = analyze(frames, plugins=[MyPlugin()], enrichers=[])  # only yours, no enrichment
findings = analyze("capture.pcapng")                        # a capture file
```

`analyze()` runs frames (or a capture file) through `Engine` and `Pipeline` and returns the findings in order. It raises `AssertionError` if any plugin raised an exception, so silent failures cannot pass a test.

| Argument | Default | Meaning |
| --- | --- | --- |
| `plugins` | all built-in protocol plugins | protocol plugin instances |
| `enrichers` | `analytics` and `detection` | enricher instances; `[]` for raw plugin output |
| `enable`, `disable`, `options` | | as on the command line, used when `plugins`/`enrichers` are not given |
| `dedup` | `"run"` | `"off"` to see every finding |
| `linktype` | 1 (Ethernet) | link type of the frames |
| `stats` | new | pass a `RunStats` to inspect counters afterwards |

## Building TCP conversations

`TCPConversation` produces Ethernet frames with correct sequence and acknowledgement numbers:

```python
from netcreds_ng.testing.packets import TCPConversation

c = TCPConversation("192.0.2.10", 50000, "198.51.100.20", 21).handshake()
c.server(b"220 FTP ready\r\n")
c.client(b"USER alice\r\n").server(b"331 Password required\r\n")
c.client(b"PASS Fake-Pass-1\r\n", segment=3)    # split into 3-byte segments
c.server(b"230 Login successful.\r\n").close()
frames = c.frames
```

| Method | Effect |
| --- | --- |
| `handshake()` | SYN, SYN+ACK, ACK |
| `client(data, segment=None)` / `server(...)` | send data, optionally split into segments of `segment` bytes |
| `raw_segment(from_client, data, rel_offset=0)` | emit a segment at an offset from the current sequence number without advancing it: retransmissions, overlaps, out-of-order delivery |
| `advance(from_client, n)` | move the sequence number forward by `n` without sending anything: after `raw_segment()` calls, or to simulate bytes the capture lost (a gap) |
| `close()` | FIN exchange |

IPv6 addresses work too (`"2001:db8::10"`). Other builders in `netcreds_ng.testing.packets`: `udp_frame()`, `ipv4()`, `ipv6()` (with fragmentation fields), `tcp()`, `udp()`, `ether()` (with VLAN tags), `frame_for()` (wrap an IP packet for another link type), and `write_pcap(path, frames)` to save a fixture for the CLI.

### Out-of-order, retransmission and gap scenarios

```python
from acme import AcmePlugin   # the tutorial plugin

from netcreds_ng.model import RunStats
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

stats = RunStats()
c = TCPConversation("192.0.2.10", 50000, "198.51.100.20", 7777).handshake()
c.raw_segment(True, b"Fake-Pass-1\r\n", rel_offset=12)   # bytes 12-24 arrive first
c.raw_segment(True, b"LOGIN alice ", rel_offset=0)       # then bytes 0-11
c.advance(True, 25)                                      # move past those 25 bytes
c.client(b"LOGIN bob Fake-")                             # bob's line starts...
c.advance(True, 6)                                       # ...6 bytes the capture lost...
c.client(b"\r\nLOGIN carol Fake-Pass-3\r\n")             # ...then the rest
c.close()

found = analyze(c.frames, plugins=[AcmePlugin()], enrichers=[], stats=stats)
assert [(f.username, f.secret) for f in found] == [("alice", "Fake-Pass-1"), ("carol", "Fake-Pass-3")]
assert (stats.tcp_gaps, stats.tcp_gap_bytes) == (1, 6)
```

The reordered login is reassembled; bob's damaged line is dropped rather than reported with a spliced password; the plugin resynchronises on carol's line.

## Message builders

Structurally valid messages for the built-in protocols, with every encrypted or response field filled with obvious placeholder bytes. Nothing here performs cryptography.

| Module | Builds |
| --- | --- |
| `testing.protocols` | DER/BER primitives, Kerberos AS-REQ/AS-REP/TGS-REP/KRB-ERROR (with TCP record marking), NTLM CHALLENGE/AUTHENTICATE, SNMP v1/v2c/v3 |
| `testing.aaa_msgs` | RADIUS packets and attributes, EAP, TACACS+ authentication/authorisation/accounting |
| `testing.db_msgs` | MSSQL TDS (PRELOGIN, LOGIN7 with the real obfuscation, responses, SSPI) and Oracle TNS (CONNECT, ACCEPT, REFUSE, DATA, O5LOGON phases) |
| `testing.rdp_msgs` | RDP X.224 Connection Request/Confirm with negotiation |
| `testing.h2_msgs` | HTTP/2 frames and an explicit HPACK encoder (indexed, literal, never-indexed, Huffman) |

## Testing behind TLS

`testing.tls_lab.tls_conversation()` runs a real TLS 1.2 or 1.3 session through OpenSSL in memory (no sockets), records every byte into a `TCPConversation`, and returns the key log OpenSSL wrote. Use it to test that your plugin works behind `--tls-keylog`. It needs the `cryptography` package (included in the `dev` extra).

## Testing the ACME plugin

The tests for the [tutorial plugin](protocol-plugins.md#the-complete-plugin):

```python title="test_acme.py"
from acme import AcmePlugin

from netcreds_ng.model import Kind
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation


def test_login_split_across_segments():
    c = TCPConversation("192.0.2.10", 50000, "198.51.100.20", 7777).handshake()
    c.client(b"LOGIN alice Fake-Pass-1\r\n", segment=3)   # 3-byte segments
    c.server(b"OK welcome\r\n").close()
    cred, result = analyze(c.frames, plugins=[AcmePlugin()], enrichers=[])
    assert (cred.kind, cred.username, cred.secret) == (Kind.CREDENTIAL, "alice", "Fake-Pass-1")
    assert str(cred.src) == "192.0.2.10:50000" and str(cred.dst) == "198.51.100.20:7777"
    assert result.outcome == "success"


def test_nonstandard_port_and_failure():
    c = TCPConversation("192.0.2.10", 50001, "198.51.100.20", 9000).handshake()
    c.client(b"LOGIN bob Fake-Pass-2\r\n").server(b"ERR denied\r\n").close()
    cred, result = analyze(c.frames, plugins=[AcmePlugin()], enrichers=[])
    assert "nonstandard-port" in cred.tags
    assert result.outcome == "failure"


def test_other_traffic_is_ignored():
    c = TCPConversation("192.0.2.10", 50002, "198.51.100.20", 7777).handshake()
    c.client(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n").close()
    assert analyze(c.frames, plugins=[AcmePlugin()], enrichers=[]) == []
```

```console
$ pytest -q test_acme.py
...                                                                      [100%]
3 passed
```

## What to test

For every plugin, cover at least:

- **positive cases**: each message variant your plugin reports, with the exact fields;
- **segmentation**: messages split into tiny segments (`segment=1` is a good stress test);
- **out of order and retransmission**: with `raw_segment()`;
- **gaps**: with `advance()`; check that nothing is reported across the hole;
- **negative cases**: other protocols on your port, your protocol's keywords inside other protocols, random bytes, truncated messages;
- **non-standard ports**: your plugin should still find the protocol;
- **property tests**: [Hypothesis](https://hypothesis.readthedocs.io/) with random bytes and random segmentations must never make your plugin raise.

Use documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and obviously fake credentials in fixtures.
