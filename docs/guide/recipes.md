# Recipes

Short answers to common tasks. Each links to the page with the details.

## Produce a shareable audit report

```bash
netcreds-ng -p captures/ --mask -q --html audit.html
```

The HTML report is a single file with no external resources. It masks secrets by default even without `--mask`; `--mask` also keeps them out of any other output in the same run. Print it from a browser ("Save as PDF") for a PDF. See [HTML report](../reference/outputs.md#html-report).

## Find which servers expose cleartext logins

```bash
netcreds-ng -p captures/ --no-browsing --min-risk high
```

Read the **Services exposing cleartext secrets** table in the summary. For the full inventory, write `--html` or use the [Python API](detections.md#using-the-analysis-in-python).

## Hunt weak Windows authentication

```bash
netcreds-ng -p dc-traffic.pcapng --no-browsing --min-risk medium
```

`--enable` only switches on opt-in plugins; it does not restrict the run to the plugins you name. To narrow a run, `--disable` what you do not need.

Look for `#ntlmv1`, `#weak-preauth-rc4-hmac`, `#weak-service-ticket` and `#no-preauth`. In the dashboard, the filter `proto:ntlm tag:ntlmv1` or `proto:kerberos risk:medium+` does the same.

With a SQLite output:

```sql
-- Hosts still using NTLMv1
SELECT DISTINCT src_ip, domain, username FROM findings
WHERE protocol = 'NTLM' AND value LIKE 'NTLMv1%';

-- Kerberos findings at medium risk or above
SELECT username, domain, value, tags FROM findings
WHERE protocol = 'Kerberos' AND risk IN ('medium', 'high');
```

## Fail a pipeline when cleartext credentials appear

Exit codes report errors, not findings, so check the output:

```python title="gate.py"
import json
import sys

exposed = [
    f for line in open(sys.argv[1], encoding="utf-8")
    if (f := json.loads(line))
    and "cleartext" in f.get("tags", [])
    and f["kind"] in ("credential", "password", "token", "api_key")
]
for f in exposed:
    print(f"{f['protocol']:<8} {f['src']} -> {f['dst']}  {f.get('username', '')}")
sys.exit(1 if exposed else 0)
```

```bash
netcreds-ng -q -p test-run.pcapng --mask --strict --jsonl findings.jsonl && python gate.py findings.jsonl
```

`--strict` also fails the step (exit 3) if a plugin or capture error made the analysis incomplete. With `jq`:

```bash
jq -e -s 'map(select(.tags // [] | index("cleartext"))) | length == 0' findings.jsonl
```

## Send findings to a SIEM

=== "File + forwarder"

    ```bash
    netcreds-ng -i eth0 --no-tui -q --jsonl /var/log/netcreds-ng/findings.jsonl
    ```

    Ship the file with Splunk's universal forwarder, Filebeat or Elastic Agent. See the [Splunk](../reference/outputs.md#splunk) and [Elastic](../reference/outputs.md#elastic) examples.

=== "Syslog"

    ```bash
    netcreds-ng -i eth0 --no-tui -q --syslog udp://siem.example:514
    netcreds-ng -i eth0 --no-tui -q --syslog tcp://siem.example:6514 --option syslog.format=json
    ```

    RFC 5424 with a CEF (default) or JSON body; secrets masked. See [Syslog](../reference/outputs.md#syslog).

=== "CEF file"

    ```bash
    netcreds-ng -p captures/ --cef findings.cef
    ```

## Post alerts to Slack, Teams or Discord

```bash
netcreds-ng -i eth0 --no-tui -q \
  --webhook https://hooks.slack.com/services/T000/B000/XXXX \
  --webhook-format slack --option webhook.min_risk=high
```

Messages are batched (20 findings, or at the end of the run) and secrets are masked. See [Webhooks](../reference/outputs.md#webhooks).

## Hand evidence to the owner of a service

```bash
netcreds-ng -p big-capture.pcapng -f 192.0.2.5 --evidence evidence.pcapng
```

The evidence file holds only the packets behind each finding, plus a few after it, each annotated with a Wireshark packet comment such as `netcreds-ng: original frame 4; FTP credential for alice`. It contains the raw packets, secrets included. See [Evidence pcapng](../reference/outputs.md#evidence-pcapng).

## Audit rolling captures without repeats

Capture with rotation, then analyse each completed file and suppress anything already reported:

```bash
tcpdump -i eth0 -G 3600 -w 'cap-%Y%m%d-%H.pcap'          # one file per hour
netcreds-ng -q -p cap-20261008-14.pcap --dedup persistent --dedup-db /var/lib/netcreds-ng/seen.sqlite3 \
            --jsonl /var/log/netcreds-ng/findings.jsonl
```

Persistent dedup stores SHA-256 hashes of finding keys, never the findings themselves. Login results are always reported, so brute-force detection still works within each run.

## Keep a queryable history

```bash
netcreds-ng -p monday/ --sqlite audits.db
netcreds-ng -p tuesday/ --sqlite audits.db
```

Each run adds a row to `runs` and its findings to `findings` with that `run_id`:

```sql
-- Cleartext credentials per service, newest run
SELECT dst_ip, dst_port, protocol, COUNT(*) AS n FROM findings
WHERE run_id = (SELECT MAX(id) FROM runs)
  AND kind IN ('credential', 'password')
  AND ',' || tags || ',' LIKE '%,cleartext,%'
GROUP BY dst_ip, dst_port, protocol ORDER BY n DESC;
```

See the [SQLite schema](../reference/outputs.md#sqlite).

## Reduce noise

| Noise | Fix |
| --- | --- |
| URLs and searches | `--no-browsing`, or `--option http.urls=false` to stop collecting URLs |
| cookies | `--option http.cookies=off` |
| heuristic matches | `--strict-heuristics` |
| your own scanner or monitoring host | `-f 192.0.2.5` |
| findings already reviewed | `--dedup persistent` |
| a whole protocol | `--disable <plugin>` |

## Analyse many files faster

```bash
netcreds-ng -p archive/ -j 8 -q --jsonl findings.jsonl
```

See [parallel analysis](analysing-captures.md#parallel-analysis) for the trade-offs.

## Use netcreds-ng from Python

```python
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig

found = []
session = Session(load_registry(), SessionConfig(disable=["keyvalue"]), listeners=[found.append])
session.open()
session.run_files(["capture.pcapng"])
session.close()

for f in found:
    print(f.protocol, f.kind.value, f.src, f.dst, f.display)
print(session.stats.frames, "frames;", session.summary()["host_scores"])
```

`SessionConfig` takes the same settings as the command line (`enable`, `disable`, `plugin_options`, `outputs`, `mask_outputs`, `dedup`, `exclude_hosts`, `tls_keylog`, `jobs`). See the [Session API](../api/session.md).

## Build a test capture

The [testing SDK](../plugins/testing.md) writes deterministic captures without capture hardware or scapy, which is the quickest way to check how netcreds-ng reports a scenario. The [quickstart](../getting-started/quickstart.md#6-see-alerts-simulate-a-brute-force-attack) builds a brute-force capture this way.
