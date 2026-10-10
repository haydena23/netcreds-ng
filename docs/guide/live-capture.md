# Live capture

netcreds-ng can watch a network interface and report findings as they happen.

!!! warning "Authorisation"

    Capture only on networks you are authorised to monitor. Live findings contain real credentials.

!!! note "Beta in 2.0.0"

    Live capture is a **beta** feature in 2.0.0. Protocol detection is the same code that is tested on capture files, but the live path (interface selection, BPF filters, the live table, dropped-packet accounting, stopping with Ctrl+C, re-reading a TLS key log while it grows) has not yet been validated on a real network. For audits, the most reliable workflow is to capture with tcpdump, dumpcap or Wireshark and analyse the file with `-p`. Please report problems you find.

## Requirements

- A capture driver: Npcap on Windows, libpcap elsewhere. Capture goes through scapy's sniffer.
- Permission to capture, which netcreds-ng checks before it starts:
  - **Windows:** none beyond Npcap's own setting. A standard Npcap install lets any user capture; if Npcap was installed with "Restrict Npcap driver's access to Administrators only", run from an Administrator terminal.
  - **Linux:** root, or the `CAP_NET_RAW` capability.
  - **macOS:** root, or read access to `/dev/bpf*` (Wireshark's ChmodBPF).

  When something is missing, the error says what (for example `[ERROR] live capture needs Npcap: install it from https://npcap.com and try again`).

## Starting a capture

Typing just `netcreds-ng` starts a live capture on the interface carrying the default route and prints each finding as it is seen. If netcreds-ng cannot tell which interface that is, it picks the first active interface with a routable IPv4 address, preferring physical adapters over virtual switches and VPNs.

```bash
netcreds-ng                            # auto-detect the interface (Linux/macOS: sudo netcreds-ng)
sudo netcreds-ng -i eth0               # a specific interface
netcreds-ng --list-interfaces          # see what is available (no privileges needed)
```

`--list-interfaces` marks the auto-detected interface with `*`:

```text
* eth0                           up    192.0.2.15, fe80::1
  lo                             up    127.0.0.1, ::1
  wlan0                          down
```

## Output

Findings are printed one line each as they are seen, and the run summary is printed when you stop with Ctrl+C. `--tui` shows them in a [live table](live-table.md) instead.

```bash
sudo netcreds-ng -i eth0
sudo netcreds-ng -i eth0 -P databases,ftp                                   # only some plugins
sudo netcreds-ng -i eth0 --tui                                             # live table
sudo netcreds-ng -i eth0 -q --jsonl /var/log/netcreds-ng/findings.jsonl     # headless, file only
```

Every output option works in live mode. Files are appended to as findings arrive; the evidence file is written when the capture stops.

## Filtering traffic

Two filters reduce what is captured:

```bash
sudo netcreds-ng -i eth0 -f 192.0.2.5,192.0.2.6        # ignore these hosts
sudo netcreds-ng -i eth0 --bpf "tcp or udp port 88"    # an extra BPF expression
```

Both are compiled into one BPF filter, for example `not (host 192.0.2.5 or host 192.0.2.6) and (tcp or udp port 88)`, so excluded packets never reach netcreds-ng. Avoid port-based BPF filters unless you need them: netcreds-ng detects protocols on any port, and a filter on standard ports hides services running elsewhere.

## Long-running captures

- **Memory is bounded.** At most 100,000 connections are tracked; the oldest is closed when the table is full (counted as *evicted*). TCP connections idle for 10 minutes and UDP conversations idle for 2 minutes are closed. Each direction buffers at most 1 MiB of out-of-order data.
- **De-duplication.** In the default `run` mode, the set of findings already seen grows with the run. For captures that run for weeks, consider `--dedup persistent`, which keeps hashed keys in SQLite and also suppresses findings already reported by earlier runs.
- **Key logs are re-read.** With `--tls-keylog`, a lookup that fails re-reads the key-log file if it changed, so a browser can keep appending to `SSLKEYLOGFILE` during the capture.
- **Alerts use capture time.** The behavioural detections use packet timestamps, so their results are the same live and offline.

## Dropped packets

Capture runs in a background thread that feeds a queue of up to 100,000 frames. If analysis falls behind for long enough to fill it, new frames are dropped and counted. The count is shown as a warning when the capture stops:

```text
Warnings:
  - 3120 packets dropped (analysis slower than capture)
```

To reduce drops, narrow the capture with `--bpf` or `-f`, disable plugins you do not need, or capture to a file with `tcpdump`/`dumpcap` and analyse it afterwards.

## Legacy live mode

`--legacy -i IFACE` behaves like the original net-creds: it prints `[*] Using interface: ...`, honours only the first host given to `-f`, and writes `credentials.txt`. See [Legacy mode](legacy.md).
