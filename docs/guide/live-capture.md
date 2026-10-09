# Live capture

netcreds-ng can watch a network interface and report findings as they happen.

!!! warning "Authorisation"

    Capture only on networks you are authorised to monitor. Live findings contain real credentials.

## Requirements

- Root on Linux/macOS, an elevated terminal on Windows. netcreds-ng checks this first and exits with `[ERROR] live capture needs root/administrator privileges` otherwise.
- A capture driver: Npcap on Windows, libpcap elsewhere. Capture goes through scapy's sniffer.

## Starting a capture

```bash
sudo netcreds-ng                       # auto-detect the interface carrying the default route
sudo netcreds-ng -i eth0               # a specific interface
netcreds-ng --list-interfaces          # see what is available (no privileges needed)
```

`--list-interfaces` marks the auto-detected interface with `*`:

```text
* eth0                           up    192.0.2.15, fe80::1
  lo                             up    127.0.0.1, ::1
  wlan0                          down
```

## Dashboard or plain output

When standard output is a terminal, live capture opens the [interactive dashboard](dashboard.md). Otherwise, or with `--no-tui`, findings are printed as plain lines, and the run summary is printed when you stop with Ctrl+C:

```bash
sudo netcreds-ng -i eth0 --no-tui
sudo netcreds-ng -i eth0 -q --jsonl /var/log/netcreds-ng/findings.jsonl     # headless, file only
```

Every output option works in live mode. Files are appended to as findings arrive; the HTML report and the evidence file are written when the capture stops.

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
