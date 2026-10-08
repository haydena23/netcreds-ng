# Writing netcreds-ng plugins

Plugin API version: **1** (`netcreds_ng.plugins.api.PLUGIN_API`). A plugin whose `api_version` differs is refused at load time, with a message in `--list-plugins`.

There are three kinds of plugin:

| Kind | Base class | Purpose |
| --- | --- | --- |
| Protocol | `ProtocolPlugin` | Inspect reassembled TCP streams / UDP datagrams and emit findings |
| Enricher | `EnricherPlugin` | Annotate findings (tags, risk) before they reach outputs |
| Sink | `SinkPlugin` | Write findings somewhere (files, databases, services) |

## Scope

netcreds-ng is a defensive exposure-auditing tool. A protocol plugin should:

- report cleartext credentials and secrets exactly as they crossed the wire, because that is the exposure;
- report challenge/response or encrypted authentication as an `AUTH_EVENT` with metadata only (user, mechanism, strength). Never put digests, nonces, responses or ciphertext in a finding.

## A protocol plugin in 30 lines

```python
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, text


@dataclass
class _State:
    lines: LineBuffer = field(default_factory=LineBuffer)


class AcmePlugin(ProtocolPlugin):
    name = "acme"                         # unique, lower-case
    description = "ACME login protocol"
    default_ports = frozenset({7777})     # hints only: traffic on any port is offered
    priority = 150                        # lower runs first

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        if direction is not Direction.CLIENT_TO_SERVER:
            return
        for line in ctx.state.lines.feed(data):
            if line.startswith(b"LOGIN "):
                user, _, password = line[6:].partition(b" ")
                ctx.emit(direction, Kind.CREDENTIAL, protocol="ACME", plugin=self.name,
                         username=text(user), secret=text(password), risk="high")
            elif not line.isascii():
                ctx.detach()              # not our protocol: stop receiving this flow
```

### Callbacks

| Callback | When |
| --- | --- |
| `new_state(flow)` | once per flow; the return value becomes `ctx.state` |
| `on_data(ctx, direction, data)` | in-order TCP bytes (already reassembled, de-duplicated, re-ordered) |
| `on_gap(ctx, direction, size)` | `size` bytes are missing before the next `on_data`; resynchronise |
| `on_datagram(ctx, direction, data)` | each UDP payload (set `transports = frozenset({Transport.UDP})`) |
| `on_close(ctx)` | flow ended or was evicted; emit anything still pending |

- `direction` is `Direction.CLIENT_TO_SERVER` or `SERVER_TO_CLIENT`. The client is the side that sent the SYN; without a handshake it is inferred from the ports.
- `ctx.flow` holds `client`, `server` (`Endpoint(ip, port)`), `transport` and `flow_id`.
- `ctx.emit(direction, kind, protocol=..., **fields)` builds a `Finding` and stamps it with the flow endpoints, the packet timestamp and the frame number. Pass `reverse=True` for a server reply that reports on the client's login (an `AUTH_RESULT`), so src/dst still read client → server.
- Finding fields: `username`, `secret`, `domain`, `value` (display text for events/URLs), `risk` (`info`/`low`/`medium`/`high`), `tags`, `extra` (JSON-serialisable dict), `confidence`.
- Kinds: `CREDENTIAL`, `USERNAME`, `PASSWORD`, `TOKEN`, `API_KEY`, `COOKIE`, `COMMUNITY`, `AUTH_EVENT`, `AUTH_RESULT`, `URL`, `POST`, `SEARCH`, `INFO`.
- Class attributes:
  - `ports_only = True` restricts the plugin to `default_ports`.
  - `opt_in = True` disables it unless the user passes `--enable <name>` or `--enable all`.

### Rules

- **Never raise on malformed input.** The engine does catch exceptions, counts them per plugin, shows them in the summary and detaches the plugin from that flow. That is a safety net, not a parsing strategy.
- **Bound all buffers and lengths.** Detach as soon as the traffic is clearly not yours, because every TCP plugin is offered every flow.
- **Keep wire data as `bytes`.** Decode only when building a finding (`_util.text()` gives UTF-8 with `\xNN` escapes).
- **Watch for look-alike protocols.** USER/PASS appears in FTP, POP3 and IRC. AUTH appears in SMTP, POP3, IMAP and Redis. Use greetings, command shapes and who-speaks-first to tell them apart.

## Testing

`netcreds_ng.testing` builds deterministic traffic without any capture hardware:

```python
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation, udp_frame, write_pcap

def test_acme_login():
    c = TCPConversation("192.0.2.10", 50000, "198.51.100.20", 7777).handshake()
    c.client(b"LOGIN alice Fake-Pass-1\r\n", segment=3)   # 3-byte segments
    c.close()
    (finding,) = analyze(c.frames, plugins=[AcmePlugin()], enrichers=[])
    assert (finding.username, finding.secret) == ("alice", "Fake-Pass-1")
```

- `analyze()` raises if any plugin errored, so silent failures cannot pass.
- `TCPConversation` also offers `raw_segment()` and `advance()`, for out-of-order and retransmission scenarios.
- `udp_frame()` builds UDP frames, and `write_pcap()` saves a fixture for use with the CLI.

## Distributing a plugin

Expose the class through the `netcreds_ng.plugins` entry-point group:

```toml
[project.entry-points."netcreds_ng.plugins"]
acme = "netcreds_acme.plugin:AcmePlugin"
```

After `pip install`, the plugin appears in `netcreds-ng --list-plugins`. For quick experiments, drop a `.py` file into a directory and pass `--plugin-dir DIR`, or use the user plugin directory: `%APPDATA%\netcreds-ng\plugins` on Windows, `~/.config/netcreds-ng/plugins` elsewhere.

## Enrichers and sinks

```python
from netcreds_ng.plugins.api import EnricherPlugin, SinkPlugin

class CorporateDomainTagger(EnricherPlugin):
    name = "corp-tagger"
    def enrich(self, finding):
        if finding.username and finding.username.endswith("@corp.example"):
            finding.tags.append("corporate-account")
        return iter(())          # may also yield extra findings

class StdoutCount(SinkPlugin):
    name = "count"               # usable as: -o count:-
    def open(self, ctx): self.n = 0
    def write(self, finding): self.n += 1
    def close(self, stats): print(f"{self.n} findings")
```

Enrichers run after de-duplication. Sinks receive `target` (the part after `FORMAT:`) and `options` (from `--option <name>.key=value` or the config file; `mask` is set when `--mask` is used).
