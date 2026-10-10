# Analysing captures

Offline analysis of capture files is the main use of netcreds-ng. It needs no privileges and no capture driver.

## Choosing input files

`-p/--pcap` takes a file or a directory and can be repeated:

```bash
netcreds-ng -p monday.pcapng                     # one file
netcreds-ng -p captures/                         # every capture file in a directory
netcreds-ng -p site-a/ -p site-b/core.pcap       # several sources, in the order given
```

- **Formats.** pcap (microsecond and nanosecond, either byte order) and pcapng (several interfaces, any timestamp resolution, mixed link types). netcreds-ng reads them natively, without scapy.
- **Compressed captures.** gzip-compressed pcap and pcapng files are read directly. Compression is detected from the file content, not the name. A truncated `.gz` file is reported like a truncated capture, after its complete frames have been analysed.
- **Directories** contribute the files whose names end in `.pcap`, `.pcapng`, `.cap`, `.dmp`, `.pcap.gz` or `.pcapng.gz`, sorted by name. Subdirectories are not searched.
- **Link types.** Ethernet (with 802.1Q/QinQ VLAN tags and PPPoE), Linux cooked capture (SLL and SLL2), BSD loopback/null, and raw IPv4/IPv6. Frames of other link types are counted as *non-IP/undecodable*.

### Rotated captures

Files are analysed in order, and connections continue from one file into the next. A capture split by `tcpdump -C` or `dumpcap -b` therefore behaves like one long capture: a login that starts at the end of one file and finishes in the next is still found.

Give files in chronological order (directories are read in name order, which suits the timestamped names rotation tools produce). The behavioural detections use sliding time windows and assume findings arrive roughly in capture order.

### Parallel analysis

Large inputs are analysed by one worker process per physical CPU core by default. `-j N` sets the number of workers, and `-j 1` keeps everything in one process:

```bash
netcreds-ng -p big-capture.pcapng          # one worker per core
netcreds-ng -p captures/ -j 4 --jsonl findings.jsonl
netcreds-ng -p big-capture.pcapng -j 1     # no workers
```

This works for a single capture as well as for many: the traffic is divided by host pair, so every connection (and every IP fragment) between two hosts is analysed by one worker. The output is the same as with `-j 1`: the same findings, in the same order, with the same counters and warnings. Rotated captures still behave like one long capture.

Speed-up depends on the traffic. On the synthetic benchmark, 8 workers on an 8-core machine analyse about 4 times as many frames per second as one. The work cannot be divided more finely than one host pair, so a capture dominated by a single conversation gains little.

`-j` is ignored, and the run is sequential, when:

- the input is smaller than 16 MB (starting the workers would cost more than it saves);
- a per-packet output such as [`--evidence`](../reference/outputs.md#evidence-pcapng) is active, since it needs every packet in one process;
- capturing live.

Some limits apply per worker rather than per run: the flow table cap (100,000 flows by default) and the IP fragment buffers. Fragment expiry follows the fragments each worker sees, so in a capture whose timestamps go backwards, a fragmented datagram that a single process would give up on can still be reassembled. A third-party plugin that correlates traffic between *different* host pairs only sees the share of its worker; no built-in plugin does that.

Dedup, enrichers and outputs always run in the main process, so alerts and analytics see every finding.

## Ignoring hosts

Exclude traffic to or from specific hosts, such as your own scanner or a monitoring system:

```bash
netcreds-ng -p cap.pcap -f 192.0.2.5,192.0.2.6
netcreds-ng -p cap.pcap -F ignore.txt          # one IP per line; lines starting with # are skipped
```

Excluded packets are counted as *filtered*. The match is on the exact IP address string. In live mode the same list also becomes a BPF filter, so the packets are not even captured.

## Controlling console output

| Option | Effect |
| --- | --- |
| `-v` | do not truncate long values (they are cut at 100 characters by default) |
| `-q` | no console output at all, outputs only |
| `--min-risk LEVEL` | only show findings at or above `info`, `low`, `medium` or `high` |
| `--no-browsing` | hide URL, POST and search findings |

These options affect the screen only. Outputs always receive every finding, secrets included. To filter what an output receives, use its own options (`min_risk` for the webhook and syslog outputs) or post-process the JSON.

Line breaks inside values are shown as `\r` and `\n`, so one finding is always one line.

## Choosing plugins

All protocol plugins and both enrichers run by default. Narrow it down with plugin and set names:

```bash
netcreds-ng -p cap.pcap -P databases,ftp              # only these
netcreds-ng -p cap.pcap --disable keyvalue,telnet     # everything except these
netcreds-ng --list-plugins                            # plugins and sets
```

See [choosing plugins](choosing-plugins.md).

`--strict-heuristics` cuts the two noisiest sources of false positives: it disables `keyvalue` and makes `telnet` ignore login prompts that are neither on a Telnet port nor preceded by Telnet option negotiation.

Plugins have options too, such as `--option http.cookies=all`. See [plugin options](../reference/plugin-options.md).

## Capture health

A capture can be incomplete in ways that silently hide credentials: a SPAN port that mirrors only one direction, a switch that drops packets under load, a snapshot length that cuts payloads short. The run summary ends with a one-line verdict on how much of the traffic the capture really saw:

```text
Capture health: degraded - the capture misses the return path for 40% of TCP flows (10 of 25): asymmetric
routing, or a SPAN port or tap that sees only one direction. Logins may be seen without their result.
```

The status is `good`, `degraded` or `poor`. Informational notes keep the status `good` and read "good, with notes: ...". Further issues are listed below it as `also: ...`.

| Issue | Measured as | Warning / poor at | What to do |
| --- | --- | --- | --- |
| one-sided flows | TCP flows where only one direction was captured, although that direction shows the other one answered | 10% / 30% of answered flows | mirror both directions (SPAN source "both", or a tap that aggregates both); check for asymmetric routing |
| gaps | TCP stream bytes missing from the capture | 1% / 5% of stream bytes; in a small capture, a warning at 5%. Any gap is at least listed as information | the capture point is dropping packets: reduce load on the SPAN port, use a tap, or capture to a faster disk |
| duplicates | data segments captured twice: same sequence, length and IP ID within 10 ms (without an IP ID, as in IPv6, within 0.2 ms) | information at 5%: findings are unaffected | the SPAN port copies ingress and egress of the same traffic; mirror one of them |
| truncated frames | frames shorter than their wire length | 1% / 10% of frames | capture with a full snapshot length (`tcpdump -s 0`) |
| dropped packets | live capture only: packets lost because analysis fell behind | any / 5% | capture to a file and analyse it with `-p` |
| no handshake | flows picked up mid-stream | information only, at 50% | normal for short captures; logins made before the capture started are not visible |

Rates are judged only on enough evidence: at least 20 TCP flows, 100 data segments or 100 frames, depending on the measure. In a smaller capture, one-sided flows are still reported (as a warning) when most of the flows are one-sided. Connection attempts that were never answered (a bare SYN) are not counted as one-sided, because the network, not the capture, is the cause. Neither are stray packets without data, such as a late ACK after a reset.

The same assessment, with every counter and rate, is written by [`--summary-json`](../reference/outputs.md#run-summary-json).

## Understanding warnings

When something went wrong, the summary ends with a **Warnings** section:

```text
Warnings:
  - captures/broken.pcap: truncated record header after frame 5120
  - ldap: 2 error(s)
    plugin ldap failed on flow 192.0.2.10:50000 -> 198.51.100.20:389: IndexError: ...
```

| Warning | What happened | What it means for results |
| --- | --- | --- |
| *file*: truncated ... / corrupt ... | the capture ends mid-record | every complete frame before it was analysed |
| *file*: not a pcap or pcapng file | another format (for example Microsoft NetMon or snoop) | the file was skipped; convert it with `editcap -F pcapng in out.pcapng` |
| *plugin*: N error(s) | a plugin raised an exception | that plugin stopped analysing that connection; other plugins and connections were unaffected |
| TLS not decrypted: ... | a TLS session uses an unsupported version or cipher | see [TLS decryption](tls-decryption.md) |
| N packets dropped | live capture only: analysis fell behind the capture | see [live capture](live-capture.md#dropped-packets) |

Up to 100 detailed messages are kept per run. The summary prints the first five; run with `--debug` to log everything, including tracebacks, to stderr.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success (warnings may have been printed) |
| `1` | error: a capture file not found, an unreadable config or filter file, an output that could not be opened, or every input unreadable |
| `2` | usage error: bad option or value, malformed `--option`/`--output`, unknown output format |
| `3` | `--strict` was given and at least one plugin or source warning occurred |
| `130` | interrupted with Ctrl+C |

Exit codes do not depend on what was found. To fail a pipeline when credentials are exposed, inspect the output; see the [CI gate recipe](recipes.md#fail-a-pipeline-when-cleartext-credentials-appear).
