"""SIP (UDP and TCP): Digest authentication metadata and Basic credentials.

Scope: cleartext credentials (``Authorization: Basic``) are reported in full.
Digest challenge/response authentication is reported as metadata only (user,
realm, method, uri, algorithm); nonces, cnonces and responses are never read
into a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin, Transport
from netcreds_ng.plugins.protocols._util import b64decode, text

_METHODS = frozenset({
    b"REGISTER", b"INVITE", b"ACK", b"BYE", b"CANCEL", b"OPTIONS", b"SUBSCRIBE", b"NOTIFY",
    b"MESSAGE", b"REFER", b"INFO", b"PRACK", b"UPDATE", b"PUBLISH",
})  # fmt: skip
_REQUEST_LINE = re.compile(rb"^([A-Z]+) (\S+) SIP/2\.0$")
_STATUS_LINE = re.compile(rb"^SIP/2\.0 (\d{3})(?: .*)?$")
_COMPACT = {b"f": b"from", b"t": b"to", b"i": b"call-id", b"l": b"content-length"}
_PARAM = re.compile(rb'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*("(?:[^"\\]|\\.)*"|[^,\s]*)')
_URI_USER = re.compile(rb"sips?:([^@;>\s:]+)(?::[^@;>\s]*)?@", re.I)
_MAX_HEADER = 64 * 1024
_MAX_BODY = 1024 * 1024
_MAX_PENDING = 64
_MAX_FIELD = 256


@dataclass
class _Msg:
    start: bytes
    headers: dict[bytes, list[bytes]]
    header_len: int  # bytes up to and including the blank line


@dataclass
class _State:
    buffers: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    reported: set[tuple[str, ...]] = field(default_factory=set)
    #: (call-id, cseq) -> (user, realm) for requests that carried credentials.
    pending: dict[tuple[bytes, bytes], tuple[str | None, str | None]] = field(default_factory=dict)
    started: bool = False  # a complete SIP message was seen on this TCP connection
    resync: list[bool] = field(default_factory=lambda: [False, False])  # after a gap, per direction (E-5)


def _parse_head(data: bytes) -> _Msg | None:
    end = data.find(b"\r\n\r\n")
    if end < 0:
        return None
    lines = data[:end].split(b"\r\n")
    headers: dict[bytes, list[bytes]] = {}
    last: bytes | None = None
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t") and last is not None:  # folded continuation
            headers[last][-1] += b" " + line.strip()
            continue
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        key = name.strip().lower()
        key = _COMPACT.get(key, key)
        headers.setdefault(key, []).append(value.strip())
        last = key
    return _Msg(lines[0], headers, end + 4)


def _first(msg: _Msg, name: bytes) -> bytes | None:
    values = msg.headers.get(name)
    return values[0] if values else None


def _uri_user(value: bytes | None) -> str | None:
    if not value:
        return None
    m = _URI_USER.search(value)
    return text(m.group(1))[:_MAX_FIELD] if m else None


def _digest_params(value: bytes) -> dict[str, str]:
    """Extract only the non-secret Digest parameters (never nonce/cnonce/response)."""
    wanted = {b"username", b"realm", b"uri", b"algorithm"}
    out: dict[str, str] = {}
    for m in _PARAM.finditer(value):
        key = m.group(1).lower()
        if key not in wanted:
            continue
        raw = m.group(2)
        if len(raw) >= 2 and raw.startswith(b'"') and raw.endswith(b'"'):
            raw = re.sub(rb"\\(.)", rb"\1", raw[1:-1])
        out[key.decode("ascii")] = text(raw)[:_MAX_FIELD]
    return out


class SIPPlugin(ProtocolPlugin):
    name = "sip"
    sets = ("voip",)
    description = "SIP over UDP/TCP: Basic credentials, Digest authentication metadata, auth results"
    transports = frozenset({Transport.UDP, Transport.TCP})
    default_ports = frozenset({5060})
    priority = 92

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    # -- transports -------------------------------------------------------

    def on_datagram(self, ctx: Context, direction: Direction, data: bytes) -> None:
        msg = _parse_head(data.lstrip(b"\r\n"))
        if msg is not None:
            self._message(ctx, direction, msg)

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        st: _State = ctx.state
        if not st.started:
            ctx.detach()  # not yet known to be SIP: nothing to resynchronise to
            return
        # E-5: long-lived SIP-over-TCP connections (trunks, phones) resume at the next start line.
        st.buffers[direction].clear()
        st.resync[direction] = True

    def _resync(self, buf: bytearray) -> bool:
        """Drop bytes up to the first complete line that starts a SIP message; False if none yet."""
        pos = 0
        while True:
            eol = buf.find(b"\r\n", pos)
            if eol < 0:
                del buf[:pos]  # keep the incomplete last line
                if len(buf) > _MAX_HEADER:
                    buf.clear()
                return False
            if self._looks_sip(bytes(buf[pos:eol])):
                del buf[:pos]
                return True
            pos = eol + 2

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        buf = st.buffers[direction]
        buf += data
        if st.resync[direction]:
            if not self._resync(buf):
                return
            st.resync[direction] = False
        while buf and not ctx.detached:
            if buf[:1] in (b"\r", b"\n"):  # keep-alive CRLFs between messages
                del buf[0]
                continue
            eol = buf.find(b"\r\n")
            if eol < 0:  # no complete line, so no complete head: skip copying and parsing the buffer
                if len(buf) >= _MAX_HEADER:
                    ctx.detach()
                return
            if not self._looks_sip(bytes(buf[:eol])):
                ctx.detach()
                return
            msg = _parse_head(bytes(buf[:_MAX_HEADER]))
            if msg is None:
                if len(buf) >= _MAX_HEADER:
                    ctx.detach()
                return
            length = 0
            raw_len = _first(msg, b"content-length")
            if raw_len is not None:
                if not raw_len.isdigit() or int(raw_len) > _MAX_BODY:
                    ctx.detach()
                    return
                length = int(raw_len)
            total = msg.header_len + length
            if len(buf) < total:
                return
            del buf[:total]
            st.started = True
            self._message(ctx, direction, msg)

    @staticmethod
    def _looks_sip(line: bytes) -> bool:
        m = _REQUEST_LINE.match(line)
        if m:
            return m.group(1) in _METHODS
        return bool(_STATUS_LINE.match(line))

    # -- message handling ---------------------------------------------------

    def _message(self, ctx: Context, direction: Direction, msg: _Msg) -> None:
        req = _REQUEST_LINE.match(msg.start)
        if req and req.group(1) in _METHODS:
            self._request(ctx, direction, msg, req.group(1), req.group(2))
            return
        status = _STATUS_LINE.match(msg.start)
        if status:
            self._response(ctx, direction, msg, int(status.group(1)))

    def _request(self, ctx: Context, direction: Direction, msg: _Msg, method: bytes, req_uri: bytes) -> None:
        auth_values = msg.headers.get(b"authorization", []) + msg.headers.get(b"proxy-authorization", [])
        if not auth_values:
            return
        st: _State = ctx.state
        method_s = method.decode("ascii")
        from_user = _uri_user(_first(msg, b"from"))
        to_user = _uri_user(_first(msg, b"to"))
        agent = _first(msg, b"user-agent")
        base: dict[str, str] = {"method": method_s}
        if from_user:
            base["from_user"] = from_user
        if to_user:
            base["to_user"] = to_user
        if agent:
            base["user_agent"] = text(agent)[:_MAX_FIELD]
        tags = [] if ctx.flow.server.port in self.default_ports else ["nonstandard-port"]
        for value in auth_values:
            scheme, _, rest = value.strip().partition(b" ")
            scheme = scheme.lower()
            if scheme == b"digest":
                p = _digest_params(rest)
                user, realm = p.get("username"), p.get("realm")
                if not user:
                    continue
                self._track(st, msg, user, realm)
                key = ("digest", user or "", realm or "")
                if key in st.reported:
                    continue
                st.reported.add(key)
                extra = dict(base)
                extra["realm"] = realm or ""
                extra["uri"] = p.get("uri") or text(req_uri)[:_MAX_FIELD]
                extra["algorithm"] = p.get("algorithm") or "MD5"
                ctx.emit(
                    direction, Kind.AUTH_EVENT, protocol="SIP", username=user,
                    value=f"SIP Digest authentication ({method_s})", risk="medium",
                    plugin=self.name, tags=["digest", *tags], extra=extra,
                )  # fmt: skip
            elif scheme == b"basic":
                decoded = b64decode(rest)
                if decoded is None or b":" not in decoded:
                    continue
                user_b, _, pw_b = decoded.partition(b":")
                user, secret = text(user_b), text(pw_b)
                self._track(st, msg, user, None)
                key = ("basic", user, secret)
                if key in st.reported:
                    continue
                st.reported.add(key)
                ctx.emit(
                    direction, Kind.CREDENTIAL, protocol="SIP", username=user, secret=secret,
                    plugin=self.name, risk="high", tags=["basic-auth", *tags], extra=base,
                )  # fmt: skip

    @staticmethod
    def _track(st: _State, msg: _Msg, user: str | None, realm: str | None) -> None:
        call_id, cseq = _first(msg, b"call-id"), _first(msg, b"cseq")
        if call_id is None or cseq is None:
            return
        if len(st.pending) >= _MAX_PENDING:
            st.pending.pop(next(iter(st.pending)))
        st.pending[(call_id, b" ".join(cseq.split()))] = (user, realm)

    def _response(self, ctx: Context, direction: Direction, msg: _Msg, code: int) -> None:
        if code < 200:
            return  # provisional
        call_id, cseq = _first(msg, b"call-id"), _first(msg, b"cseq")
        if call_id is None or cseq is None:
            return
        st: _State = ctx.state
        entry = st.pending.pop((call_id, b" ".join(cseq.split())), None)
        if entry is None:
            return
        if code // 100 == 2:
            outcome = "succeeded"
        elif code == 403:
            outcome = "failed"
        else:
            return
        user, realm = entry
        extra = {"status": str(code)}
        if realm:
            extra["realm"] = realm
        ctx.emit(
            direction, Kind.AUTH_RESULT, protocol="SIP", reverse=True, username=user,
            value=f"SIP authentication {outcome}", plugin=self.name, extra=extra,
        )  # fmt: skip
