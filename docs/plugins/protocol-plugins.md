# Protocol plugins

A protocol plugin receives the bytes of every connection and reports what it finds. This page builds a complete plugin for a small, invented line protocol, *ACME*, in which the client sends `LOGIN <user> <password>` and the server answers `OK ...` or `ERR ...`.

## A first plugin

```python title="acme.py"
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, text


@dataclass
class _State:
    lines: LineBuffer = field(default_factory=LineBuffer)


class AcmePlugin(ProtocolPlugin):
    name = "acme"                         # unique, lower case; used by --enable/--disable/--option
    description = "ACME LOGIN credentials"
    default_ports = frozenset({7777})     # a hint only: traffic on any port is offered
    priority = 150                        # lower runs first

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()                   # becomes ctx.state for this connection

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        if direction is not Direction.CLIENT_TO_SERVER:
            return
        for line in ctx.state.lines.feed(data):
            if line.startswith(b"LOGIN "):
                user, _, password = line[6:].partition(b" ")
                ctx.emit(direction, Kind.CREDENTIAL, protocol="ACME", plugin=self.name,
                         username=text(user), secret=text(password), risk="high")
```

Save it in a directory and run:

```console
$ netcreds-ng -p acme.pcap --plugin-dir ./my-plugins
16:13:20 HIGH   ACME      credential 192.0.2.10:50000 > 198.51.100.20:7777 alice:Fake-Pass-1
```

That is already a working plugin: the engine reassembles the TCP stream, so `LOGIN` lines split across packets, retransmitted or reordered are handled for you. The rest of this page makes it robust.

## The lifecycle

One plugin **instance** serves every connection. Per-connection state lives in `ctx.state`.

| Callback | When |
| --- | --- |
| `new_state(flow)` | once per connection; the return value becomes `ctx.state` |
| `on_data(ctx, direction, data)` | in-order TCP bytes for one direction: reassembled, de-duplicated, re-ordered |
| `on_gap(ctx, direction, size)` | `size` bytes are missing before the next `on_data`. Default: detach |
| `on_datagram(ctx, direction, data)` | each UDP payload (set `transports = frozenset({Transport.UDP})`) |
| `on_close(ctx)` | the connection ended or was evicted; emit anything still pending |

`data` is whatever the stream delivered: it can hold part of a message or several messages. Always buffer and frame it yourself; `LineBuffer` does that for line protocols.

### The context

| Attribute | Meaning |
| --- | --- |
| `ctx.flow` | `FlowInfo`: `flow_id`, `transport`, `client` and `server` (`Endpoint(ip, port)`) |
| `ctx.state` | your per-connection state |
| `ctx.frame`, `ctx.timestamp` | frame number and capture time of the packet that carried the current bytes |
| `ctx.tls_decryption` | true when a TLS key log is loaded (see [TLS](#tls-and-starttls)) |
| `ctx.emit(direction, kind, protocol=..., **fields)` | build and publish a `Finding`; returns it |
| `ctx.detach()` | stop receiving this connection |
| `ctx.detached` | whether the plugin has detached |

Your plugin's options are on `self.options` (a dict from `--option acme.key=value` or `[plugins.acme]`).

### Class attributes

| Attribute | Default | Meaning |
| --- | --- | --- |
| `name` | (required) | unique plugin name |
| `description` | `""` | shown in `--list-plugins` |
| `version` | `"1.0"` | your plugin's version |
| `api_version` | `PLUGIN_API` | leave as is |
| `transports` | `{Transport.TCP}` | `TCP`, `UDP` or both |
| `default_ports` | empty | port hints: help the engine decide which side is the server |
| `ports_only` | `False` | only offer connections that use one of `default_ports` |
| `opt_in` | `False` | disabled unless `--enable <name>` or `--enable all` |
| `priority` | 100 | order among plugins on a connection; lower runs first. Built-ins use 10–210 |

## Emitting findings

`ctx.emit()` stamps the finding with the connection's endpoints, the current frame number and timestamp. `direction` says who sent the data: for `CLIENT_TO_SERVER`, `src` is the client and `dst` the server.

| Field | Use |
| --- | --- |
| `protocol` (required) | protocol label shown to users, e.g. `"ACME"` |
| `plugin` | your plugin name (set it: outputs and filters use it) |
| `username`, `secret`, `domain` | the account and the cleartext secret |
| `value` | description for events, results, URLs |
| `risk` | `"info"`, `"low"`, `"medium"`, `"high"` |
| `tags` | list of strings |
| `extra` | JSON-serialisable dict with protocol details |
| `confidence` | below 1.0 for heuristics |
| `reverse=True` | swap `src`/`dst`: for a server reply that reports on the client's login |

Kinds: `CREDENTIAL`, `USERNAME`, `PASSWORD`, `TOKEN`, `API_KEY`, `COOKIE`, `COMMUNITY`, `AUTH_EVENT`, `AUTH_RESULT`, `URL`, `POST`, `SEARCH`, `INFO`. `ALERT` is reserved for enrichers. See [kinds](../reference/findings.md#kinds).

Conventions worth following:

- Tag `nonstandard-port` when the server does not use your standard port.
- The `analytics` enricher adds the `cleartext` tag only for the built-in cleartext protocols. If your protocol sends secrets in cleartext, add `"cleartext"` to `tags` yourself so your findings count as cleartext exposure.
- Cap the length of values you copy from the wire (the built-ins use 256 characters for secrets and 120 for reply lines).

## Reporting login results

When the server answers a login, emit an `AUTH_RESULT` from the server's direction with `reverse=True`, so `src`/`dst` still read client → server:

```python
ctx.emit(Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="ACME", plugin=self.name,
         reverse=True, username=st.user, value="login succeeded" if ok else "login failed")
```

Use the wording `login succeeded` / `login failed`, or set `extra["outcome"] = "success" | "failure"`. `Finding.outcome` reads either, and the brute-force, spraying and login-after-failures alerts work for your protocol with no further effort.

## Capture gaps

When the capture lost bytes, the engine calls `on_gap()` before the next `on_data()`. The default implementation **detaches** your plugin from the connection, because continuing would join bytes from both sides of the hole and could report a wrong credential as fact.

If your protocol has resynchronisation points, override it. For a line protocol, drop the damaged line and continue at the next one:

```python
def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
    ctx.state.lines[direction].gap()
```

`LineBuffer.gap()` discards the partial line before the hole and the rest of the line after it.

## Detaching early

Every TCP plugin is offered every TCP connection, on any port. Detach as soon as the traffic is clearly not yours, both for speed and to avoid false positives:

- after a bounded amount of data without anything recognisable;
- when a greeting or first message identifies another protocol;
- when a length field or structure is impossible.

Watch for look-alike protocols. `USER`/`PASS` appear in FTP, POP3 and IRC; `AUTH` in SMTP, POP3, IMAP and Redis. Use greetings, command shapes and who speaks first to tell them apart, as the built-in plugins do.

## The complete plugin

```python title="acme.py"
"""ACME login protocol: a toy line protocol used in the plugin tutorial."""

from __future__ import annotations

from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, text

_GIVE_UP = 4096  # client bytes without a LOGIN before we decide this is not ACME


@dataclass
class _State:
    lines: tuple[LineBuffer, LineBuffer] = field(default_factory=lambda: (LineBuffer(), LineBuffer()))
    user: str | None = None
    awaiting_result: bool = False
    client_bytes: int = 0


class AcmePlugin(ProtocolPlugin):
    name = "acme"
    description = "ACME LOGIN credentials and results (any port)"
    default_ports = frozenset({7777})
    priority = 150

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        ctx.state.lines[direction].gap()  # drop the damaged line, continue at the next one

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        for line in st.lines[direction].feed(data):
            if direction is Direction.CLIENT_TO_SERVER:
                self._client(ctx, st, line)
            else:
                self._server(ctx, st, line)
            if ctx.detached:
                return
        if direction is Direction.CLIENT_TO_SERVER:
            st.client_bytes += len(data)
            if st.user is None and st.client_bytes > _GIVE_UP:
                ctx.detach()

    def _client(self, ctx: Context, st: _State, line: bytes) -> None:
        if not line.startswith(b"LOGIN "):
            return
        user, _, password = line[6:].partition(b" ")
        st.user, st.awaiting_result = text(user), True
        tags = [] if ctx.flow.server.port in self.default_ports else ["nonstandard-port"]
        ctx.emit(Direction.CLIENT_TO_SERVER, Kind.CREDENTIAL, protocol="ACME", plugin=self.name,
                 username=st.user, secret=text(password), risk="high", tags=tags)

    def _server(self, ctx: Context, st: _State, line: bytes) -> None:
        if st.awaiting_result and line[:3] in (b"OK ", b"ERR"):
            st.awaiting_result = False
            ok = line.startswith(b"OK ")
            ctx.emit(Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="ACME", plugin=self.name,
                     reverse=True, username=st.user, value="login succeeded" if ok else "login failed")
```

Its tests are on the [testing page](testing.md#testing-the-acme-plugin).

## Client and server direction

`direction` is `Direction.CLIENT_TO_SERVER` or `Direction.SERVER_TO_CLIENT`. The client is the side that sent the SYN; without a handshake it is inferred from the ports. When the ports cannot decide (both ephemeral, or both well-known), the engine gives your plugin **two** contexts, one per orientation. The first one to emit a finding wins, and the other is detached and gets no `on_close`. A plugin that emits nothing for traffic in the wrong direction therefore needs no special handling. See [client and server roles](../architecture/engine.md#client-and-server-roles).

## UDP plugins

```python
from netcreds_ng.plugins.api import Transport

class AcmeUdpPlugin(ProtocolPlugin):
    name = "acme-udp"
    transports = frozenset({Transport.UDP})
    default_ports = frozenset({7777})

    def on_datagram(self, ctx: Context, direction: Direction, data: bytes) -> None:
        ...  # one call per datagram; IP fragments are already reassembled
```

A plugin can support both transports, like `kerberos` and `sip`. UDP conversations idle for 2 minutes are closed.

## TLS and STARTTLS

`ctx.tls_decryption` is true when the user supplied a key log. After STARTTLS (or a similar upgrade) your plugin then receives the decrypted plaintext, or nothing at all, but never ciphertext. So:

- without a key log, stop parsing when the session upgrades to TLS (detach, or ignore further data);
- with a key log, keep parsing after the upgrade.

The engine tags findings from decrypted data `tls-decrypted`; you do not need to.

## Rules

- **Never raise on malformed input.** The engine does catch exceptions, counts them per plugin, shows them in the summary and detaches the plugin from that connection. That is a safety net, not a parsing strategy.
- **Bound every buffer and length.** Assume hostile input.
- **Keep wire data as `bytes`.** Decode only when building a finding; `_util.text()` gives UTF-8 with `\xNN` escapes.
- **Stay in scope.** Challenge/response material never goes into a finding (see [scope](index.md#scope-for-plugins)).

## Helpers

`netcreds_ng.plugins.protocols._util` contains what the built-ins share:

| Helper | Purpose |
| --- | --- |
| `text(raw)` | bytes → display string (UTF-8, `\xNN` for undecodable bytes) |
| `b64decode(value)` | lenient base64; `None` on invalid input |
| `sasl_plain(decoded)` | split a SASL PLAIN message into (authzid, authcid, password) |
| `LineBuffer` | yields complete lines (LF or CRLF), caps line length, supports `gap()` |
| `TelnetDecoder` | strips Telnet option negotiation statefully |
| `printable_ascii(data)` | whether bytes are printable ASCII |

`netcreds_ng.proto` has strict parsers for BER/DER (`der`), HPACK (`hpack`) and NTLMSSP (`ntlm`). See [Protocol parsers](../api/proto.md).

## Adding a built-in plugin

To contribute a plugin to netcreds-ng itself:

1. add message builders to `netcreds_ng/testing/<area>_msgs.py` if needed;
2. add the plugin under `src/netcreds_ng/plugins/protocols/`;
3. register its module in `BUILTIN_MODULES` in `plugins/registry.py`;
4. add `tests/test_proto_<name>.py` with positive tests, negative tests (other protocols on the port, random bytes, truncation) and segmentation tests;
5. add a case to `tests/test_cross_protocol_ng.py`, on its standard and a non-standard port, so it is checked against every other plugin for misfires;
6. if it can run inside TLS, add a `testing.tls_lab` test;
7. document it in the [protocol reference](../reference/protocols.md), `README.md` and `CHANGELOG.md`.
