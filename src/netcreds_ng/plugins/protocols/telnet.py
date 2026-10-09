"""Telnet logins: prompt-driven capture of usernames and passwords typed by the client.

Improvements over the original: Telnet option negotiation is stripped instead
of dropping whole packets, backspace/delete editing is applied, the username
and password are paired into one credential, and a following failure message
is reported.

Option ``strict`` (``--option telnet.strict=true`` or ``--strict-heuristics``): honour
login prompts only on a Telnet port or after real Telnet option negotiation. Without
it, such matches are still reported but tagged ``heuristic`` with lower confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import TelnetDecoder, text

_USER_PROMPT = re.compile(rb"(user ?name|login)\s*:\s*$", re.IGNORECASE)
_PASS_PROMPT = re.compile(rb"pass(word|code)?( for [^:\r\n]{1,64})?\s*:\s*$", re.IGNORECASE)
# Text protocols whose messages may legitimately end in "Password:" but are not Telnet logins.
_OTHER_PROTOCOL = re.compile(rb"^(HTTP/1\.|GET |POST |PUT |HEAD |SIP/2\.0|RTSP/|\+OK|\* OK|220[ -])")
_FAIL = re.compile(rb"(login incorrect|authentication failed|access denied|% bad passwords?|login failed)", re.IGNORECASE)
_GIVE_UP_BYTES = 64 * 1024


@dataclass
class _State:
    decoders: tuple[TelnetDecoder, TelnetDecoder] = field(default_factory=lambda: (TelnetDecoder(), TelnetDecoder()))
    server_tail: bytes = b""
    expecting: str | None = None  # "username" / "password"
    typed: bytearray = field(default_factory=bytearray)
    user: str | None = None
    prompts_seen: bool = False
    server_bytes: int = 0
    last_was_password: bool = False
    first_seen: list[bool] = field(default_factory=lambda: [False, False])


class TelnetPlugin(ProtocolPlugin):
    name = "telnet"
    description = "Telnet usernames/passwords typed after login prompts (any port)"
    default_ports = frozenset({23, 2323})
    priority = 30

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    @property
    def _strict(self) -> bool:
        return bool(self.options.get("strict", False))

    def _trusted(self, ctx: Context, st: _State) -> bool:
        """Strong evidence this is Telnet: a Telnet port, or option negotiation in either direction."""
        flow = ctx.flow
        return (
            flow.server.port in self.default_ports
            or st.decoders[0].negotiated
            or st.decoders[1].negotiated
        )

    def _evidence(self, ctx: Context, st: _State) -> dict[str, Any]:
        return {} if self._trusted(ctx, st) else {"tags": ["heuristic"], "confidence": 0.6}

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        st: _State = ctx.state
        if direction is Direction.CLIENT_TO_SERVER:
            st.typed.clear()  # lost keystrokes: the value being typed is unknowable
            st.expecting = None
        else:
            st.server_tail = b""

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        if not st.first_seen[direction] and data.strip():
            st.first_seen[direction] = True
            if _OTHER_PROTOCOL.match(data.lstrip()):
                ctx.detach()
                return
        clean = st.decoders[direction].feed(data)
        if direction is Direction.SERVER_TO_CLIENT:
            self._server(ctx, st, clean)
        else:
            self._client(ctx, st, clean)

    def _server(self, ctx: Context, st: _State, data: bytes) -> None:
        st.server_bytes += len(data)
        if st.last_was_password and _FAIL.search(data):
            st.last_was_password = False
            ctx.emit(
                Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="Telnet", reverse=True,
                username=st.user, value="login failed", plugin=self.name, **self._evidence(ctx, st),
            )  # fmt: skip
        tail = (st.server_tail + data)[-256:].rstrip(b"\x00")
        st.server_tail = tail
        stripped = tail.rstrip()
        if self._strict and not self._trusted(ctx, st):
            if st.server_bytes > _GIVE_UP_BYTES:
                ctx.detach()
            return  # strict mode: a prompt alone is not enough evidence on a non-Telnet port
        if _PASS_PROMPT.search(stripped):
            st.expecting, st.prompts_seen = "password", True
            st.typed.clear()
        elif _USER_PROMPT.search(stripped):
            st.expecting, st.prompts_seen = "username", True
            st.typed.clear()
        elif not st.prompts_seen and st.server_bytes > _GIVE_UP_BYTES:
            ctx.detach()

    def _client(self, ctx: Context, st: _State, data: bytes) -> None:
        if st.expecting is None:
            return
        for b in data:
            if b in (0x0D, 0x0A):
                if st.typed or b == 0x0D:
                    self._submit(ctx, st)
                continue
            if b in (0x08, 0x7F):
                if st.typed:
                    st.typed.pop()
                continue
            if b == 0x00:
                continue
            st.typed.append(b)
            if len(st.typed) > 512:
                st.typed.clear()
                st.expecting = None
                return

    def _submit(self, ctx: Context, st: _State) -> None:
        value = text(bytes(st.typed))
        st.typed.clear()
        what, st.expecting = st.expecting, None
        st.server_tail = b""
        if what == "username":
            if value:
                if st.user is not None:
                    self._emit_user(ctx, st)
                st.user = value
        elif what == "password":
            kind = Kind.CREDENTIAL if st.user is not None else Kind.PASSWORD
            ctx.emit(
                Direction.CLIENT_TO_SERVER, kind, protocol="Telnet", username=st.user, secret=value,
                plugin=self.name, risk="high", **self._evidence(ctx, st),
            )  # fmt: skip
            st.last_was_password = True
            st.user = None

    def _emit_user(self, ctx: Context, st: _State) -> None:
        ctx.emit(Direction.CLIENT_TO_SERVER, Kind.USERNAME, protocol="Telnet", username=st.user, plugin=self.name,
                 **self._evidence(ctx, st))  # fmt: skip

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        if st.expecting == "password" and st.typed:
            self._submit(ctx, st)
        elif st.expecting == "username" and st.typed:
            self._submit(ctx, st)
        if st.user is not None:
            self._emit_user(ctx, st)
