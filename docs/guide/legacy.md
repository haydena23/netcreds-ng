# Legacy mode

`--legacy` reproduces the original [net-creds](https://github.com/DanMcInerney/net-creds) (Python 2) byte for byte: the same coloured stdout lines, and the same `credentials.txt` log with its de-duplication. Use it when existing scripts parse the old output.

```console
$ netcreds-ng --legacy -p tests/fixtures/synthetic/ftp_basic.pcap
[192.0.2.10:50000 > 198.51.100.20:21] FTP User: fakeuser
[192.0.2.10:50000 > 198.51.100.20:21] FTP Pass: FakePass-123
[198.51.100.20:21 > 192.0.2.10:50000] Authentication: successful.
$ cat credentials.txt
INFO:root:[192.0.2.10:50000 > 198.51.100.20:21] FTP User: fakeuser
INFO:root:[192.0.2.10:50000 > 198.51.100.20:21] FTP Pass: FakePass-123
INFO:root:[198.51.100.20:21 > 192.0.2.10:50000] Authentication: successful.
```

On a terminal the stdout lines are coloured with the original ANSI codes.

## How it works

Legacy mode does not use the new engine, plugins or outputs. It is a separate, faithful port of the original algorithm (`netcreds_ng.legacy`): the same per-packet heuristics and regular expressions, the same message texts, and the same `credentials.txt` handling, including its substring de-duplication and Windows text-mode line endings. Wire data stays `bytes` throughout, as Python 2 `str` was.

It shares only the capture-file reader and the IP/TCP/UDP decoder with the rest of netcreds-ng.

## Guarantee and how it is checked

The test suite runs the original `net-creds.py` under Python 2.7 with scapy 2.4.4 on a set of synthetic captures and records its stdout and `credentials.txt` as **golden files** (`tests/golden/legacy/`). `--legacy` must reproduce them exactly. See [Parity testing](../development/parity.md).

## Options in legacy mode

| Option | Behaviour |
| --- | --- |
| `-p PATH` | read captures; repeatable. Directories are **not** expanded |
| `-i IFACE` | live capture, as the original |
| `-f HOST` | live capture only, and only the first host is used (as the original). With `-p` a note is printed and the filter is ignored |
| `-v` | do not truncate long values (the original's meaning) |

Every other option (outputs, plugins, dashboard, `--mask`...) is ignored in legacy mode.

## Documented deviations from Python 2

A handful of behaviours could not or should not be reproduced literally. They are recorded in the module docstring of `netcreds_ng.legacy` and in the project's migration plan:

- TCP payloads are always treated as raw data. The original was written for scapy 2.3; later scapy versions dissect SMB, NetBIOS and others and hid those payloads from it. The port keeps the intended, port-agnostic behaviour.
- SNMP is recognised the way scapy binds it (UDP ports 161/162), with a strict BER check of version, community and PDU. SNMPv3 messages are not dissected.
- Messages Python 2 built as `unicode` (Telnet, HTTP form credentials, `Decoded:` mail lines) are written as UTF-8. Python 2 wrote UTF-8 to the log file but crashed or used the console code page on stdout.
- HTTP headers are visited in wire order (Python 2 used dictionary hash order).
- The NTLM structure format uses explicit little-endian (identical on x86).
- An unreadable capture prints `[-] ...` instead of a scapy traceback.

Where the original would have crashed on some input, legacy mode stops with `[-] aborted (as the original would): ...` and exit code 1.

## What changed outside legacy mode

Without `--legacy`, netcreds-ng is a different tool with the original as its floor. The main differences for users of the original net-creds and of netcreds-ng 1.x:

| Area | Before | netcreds-ng 2.x |
| --- | --- | --- |
| Packet handling | one packet at a time, a parser chosen by port (1.x: by port, then first match) | reassembled TCP streams; every plugin sees every flow; detection by content |
| Output | free-text lines | structured findings with protocol, kind, risk, tags and frame number |
| Credentials split across packets or on non-standard ports | often missed | found |
| `-v` | original: do not truncate; 1.x: toggled the analytics panel | do not truncate (the analytics panel is the `a` key in the dashboard) |
| `-f` | original: live capture only, one host | comma-separated host list, also applies to capture files |
| Log file | original: `credentials.txt` always | the outputs you choose (`--log`, `--jsonl`, ...); `credentials.txt` only in legacy mode |
| Weak authentication | not reported | NTLM version, Kerberos encryption types, SNMPv3 levels, RDP NLA, VNC authentication... |
| Python | original: 2.7 | 3.11+ |
| Dependencies | 1.x: also impacket, pyasn1, netifaces, pywin32 | rich, textual, scapy (live capture only), psutil |

See the [changelog](../about/changelog.md) for the full list.
