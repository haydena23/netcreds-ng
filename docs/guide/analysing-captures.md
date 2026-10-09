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

`-j N` analyses up to N files at once in worker processes:

```bash
netcreds-ng -p captures/ -j 8 --jsonl findings.jsonl
```

Findings are published in file order, so the output is the same as a sequential run, with two differences:

- each file is analysed on its own, so a connection split across two files is seen as two partial connections;
- per-packet outputs such as [`--evidence`](../reference/outputs.md#evidence-pcapng) need every packet in one process, so they make the run sequential and `-j` is ignored.

Dedup, enrichers and outputs always run in the main process, so alerts and analytics see every finding from every file.

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
| `--mask` | mask secrets |

These options affect the screen only, except `--mask`, which also applies to outputs. Outputs always receive every finding. To filter what an output receives, use its own options (`min_risk` for the webhook and syslog outputs) or post-process the JSON.

Line breaks inside values are shown as `\r` and `\n`, so one finding is always one line.

## Masking secrets

`--mask` replaces each secret with its first and last character and its length:

```text
formuser:F************s (14)
```

It covers:

- every secret field (`secret`, and therefore `display`);
- secret-looking values inside free text: form and JSON fields named like passwords or tokens, `api_key=`-style query parameters, and `Authorization`, `Proxy-Authorization`, `Cookie` and `X-API-Key` header lines in `value` and `extra`.

It does not try to recognise secrets in arbitrary prose, and it cannot mask the [evidence pcapng](../reference/outputs.md#evidence-pcapng), which holds the original packets.

Some outputs mask by default even without `--mask`:

| Output | Default |
| --- | --- |
| console, `--jsonl`, `--csv`, `--log`, `--sqlite`, `--cef` | full secrets unless `--mask` |
| `--html` | masked unless `--option html.include_secrets=true` |
| `--webhook`, `--syslog` | masked unless `--option <name>.include_secrets=true` |
| `--evidence` | never masked (raw packets) |

## Choosing plugins

All protocol plugins and both enrichers run by default.

```bash
netcreds-ng -p cap.pcap --disable keyvalue,telnet     # turn some off
netcreds-ng -p cap.pcap --enable all                  # include any opt-in plugins (third-party)
netcreds-ng --list-plugins                            # see what is available
```

`--strict-heuristics` cuts the two noisiest sources of false positives: it disables `keyvalue` and makes `telnet` ignore login prompts that are neither on a Telnet port nor preceded by Telnet option negotiation.

Plugins have options too, such as `--option http.cookies=all`. See [plugin options](../reference/plugin-options.md).

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
| *file*: not a pcap or pcapng file | unsupported or compressed file | the file was skipped |
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
