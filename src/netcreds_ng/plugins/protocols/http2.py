"""HTTP/2 (RFC 9113): the HTTP/1 plugin's findings for h2c and decrypted h2 (any port).

Only connections that start with the client connection preface are followed
(prior-knowledge h2c, or HTTP/2 inside TLS once the engine decrypts it). Frames
are parsed per direction, header blocks are decompressed with one HPACK context
per direction, and each request stream is analysed like an HTTP/1 request when
it ends: URLs, searches, form/JSON/query credentials, Authorization schemes,
API keys, session cookies and JWTs. A ``:status`` of 401/403/407 on a stream that
carried credentials becomes a failed AUTH_RESULT, as in the HTTP/1 plugin.

Limitations: h2c reached through an HTTP/1.1 ``Upgrade: h2c`` exchange is not
followed (the request before the upgrade is still seen by the ``http`` plugin);
connections captured mid-stream are ignored because the HPACK state is unknown.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import b64decode, printable_ascii, text
from netcreds_ng.plugins.protocols.http import (
    _JWT,
    _SESSION_COOKIE,
    _STATIC,
    API_KEY_HEADERS,
    API_KEY_PARAMS,
    PASS_FIELDS,
    SEARCH_FIELDS,
    USER_FIELDS,
    _flatten_json,
)
from netcreds_ng.proto import hpack, ntlm

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
PROTOCOL = "HTTP/2"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = range(10)
F_END_STREAM, F_ACK, F_END_HEADERS, F_PADDED, F_PRIORITY = 0x1, 0x1, 0x4, 0x8, 0x20
SETTINGS_HEADER_TABLE_SIZE = 0x1

FRAME_HEADER = 9
#: Non-DATA frames are buffered whole; anything larger is not a sane HTTP/2 peer
#: (the protocol maximum is 2**24-1, but SETTINGS_MAX_FRAME_SIZE defaults to 16 KiB).
MAX_CONTROL_FRAME = 256 * 1024
MAX_HEADER_BLOCK = 256 * 1024
MAX_BODY = 64 * 1024
MAX_STREAMS = 256
#: server bytes buffered while the client preface is still incomplete
MAX_EARLY_SERVER = 64 * 1024


@dataclass
class _Stream:
    headers: list[tuple[str, str]] = field(default_factory=list)  # regular headers, in order
    pseudo: dict[str, str] = field(default_factory=dict)
    body: bytearray = field(default_factory=bytearray)
    analysed: bool = False
    auth_scheme: str = ""
    auth_user: str | None = None
    status: str | None = None  # final response status seen before the request was analysed
    result_done: bool = False


@dataclass
class _Dir:
    """Framing state for one direction."""

    buf: bytearray = field(default_factory=bytearray)
    # header block being assembled across HEADERS/PUSH_PROMISE + CONTINUATION
    block: bytearray = field(default_factory=bytearray)
    block_stream: int = 0  # 0 = no block in progress
    block_end_stream: bool = False
    block_push: bool = False
    # DATA frame being streamed
    data_stream: int = 0
    data_left: int = 0
    pad_left: int = 0
    data_end_stream: bool = False
    data_header_pending: bool = False  # PADDED DATA frame whose pad-length byte has not arrived
    data_frame_len: int = 0


@dataclass
class _State:
    dirs: tuple[_Dir, _Dir] = field(default_factory=lambda: (_Dir(), _Dir()))
    # decoders[d] decodes header blocks *sent* in direction d
    decoders: tuple[hpack.Decoder, hpack.Decoder] = field(default_factory=lambda: (hpack.Decoder(), hpack.Decoder()))
    streams: OrderedDict[int, _Stream] = field(default_factory=OrderedDict)
    preface_seen: bool = False
    preface_buf: bytearray = field(default_factory=bytearray)
    server_checked: bool = False


class HTTP2Plugin(ProtocolPlugin):
    name = "http2"
    description = "HTTP/2 URLs, credentials, auth headers, API keys, cookies, JWTs (h2c / decrypted h2)"
    default_ports = frozenset({80, 443, 8080, 8443})
    priority = 51

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    @property
    def cookie_mode(self) -> str:
        return str(self.options.get("cookies", "session"))  # session / all / off

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        # Unlike HTTP/1 there is no resynchronisation point: frame boundaries are only
        # known by counting lengths from the start, and every header block mutates the
        # HPACK dynamic table. After lost bytes, later indexed header references could
        # resolve to the wrong (name, value), so we would risk reporting a wrong
        # credential as fact. Stop following the connection instead.
        ctx.detach()

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        if st is None or not st.preface_seen:
            return
        # The request headers crossed the wire even if the stream never completed.
        for stream in list(st.streams.values()):
            if not stream.analysed and stream.pseudo:
                self._analyse(ctx, stream)

    # ------------------------------------------------------------------ framing

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        if direction is Direction.CLIENT_TO_SERVER:
            if not st.preface_seen:
                st.preface_buf += data
                head = bytes(st.preface_buf[: len(PREFACE)])
                if not PREFACE.startswith(head):
                    ctx.detach()
                    return
                if len(head) < len(PREFACE):
                    return
                st.preface_seen = True
                st.dirs[0].buf += st.preface_buf[len(PREFACE) :]
                st.preface_buf = bytearray()
                if not self._check_server(ctx, st) or not self._pump(ctx, st, Direction.SERVER_TO_CLIENT):
                    return
            else:
                st.dirs[0].buf += data
            self._pump(ctx, st, Direction.CLIENT_TO_SERVER)
        else:
            st.dirs[1].buf += data
            if not self._check_server(ctx, st):
                return
            if not st.preface_seen:
                if len(st.dirs[1].buf) > MAX_EARLY_SERVER:
                    ctx.detach()
                return
            self._pump(ctx, st, Direction.SERVER_TO_CLIENT)

    def _check_server(self, ctx: Context, st: _State) -> bool:
        """The server's first frame must be SETTINGS; an HTTP/1 response means this is not HTTP/2."""
        if st.server_checked:
            return True
        buf = st.dirs[1].buf
        if len(buf) < FRAME_HEADER:
            if len(buf) >= 5 and buf.startswith(b"HTTP/"):
                ctx.detach()
                return False
            return True
        if buf[3] != SETTINGS or buf[4] & F_ACK or int.from_bytes(buf[0:3], "big") % 6:
            ctx.detach()
            return False
        st.server_checked = True
        return True

    def _pump(self, ctx: Context, st: _State, direction: Direction) -> bool:
        """Consume complete frames from ``direction``'s buffer. Returns False if detached."""
        d = st.dirs[direction]
        buf = d.buf
        while True:
            if d.data_stream:
                if not self._stream_data(ctx, st, direction, d):
                    return not ctx.detached
                continue
            if len(buf) < FRAME_HEADER:
                return True
            length = int.from_bytes(buf[0:3], "big")
            ftype, flags = buf[3], buf[4]
            sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            if d.block_stream and (ftype != CONTINUATION or sid != d.block_stream):
                ctx.detach()  # a header block must be finished by CONTINUATION frames on its stream
                return False
            if ftype == DATA:
                if sid == 0:
                    ctx.detach()
                    return False
                if flags & F_PADDED and length == 0:
                    ctx.detach()  # no room for the pad-length byte
                    return False
                del buf[:FRAME_HEADER]
                d.data_stream, d.data_frame_len = sid, length
                d.data_end_stream = bool(flags & F_END_STREAM)
                d.data_header_pending = bool(flags & F_PADDED)
                d.data_left, d.pad_left = (0 if d.data_header_pending else length), 0
                continue
            if length > MAX_CONTROL_FRAME:
                ctx.detach()
                return False
            if len(buf) < FRAME_HEADER + length:
                return True
            payload = bytes(buf[FRAME_HEADER : FRAME_HEADER + length])
            del buf[: FRAME_HEADER + length]
            if not self._frame(ctx, st, direction, ftype, flags, sid, payload):
                ctx.detach()
                return False

    def _stream_data(self, ctx: Context, st: _State, direction: Direction, d: _Dir) -> bool:
        """Advance the DATA frame in progress. Returns False when more bytes are needed."""
        buf = d.buf
        if d.data_header_pending:
            if not buf:
                return False
            pad = buf[0]
            del buf[:1]
            if pad >= d.data_frame_len:  # padding must leave room for the pad-length byte
                ctx.detach()
                return False
            d.data_header_pending = False
            d.data_left, d.pad_left = d.data_frame_len - 1 - pad, pad
        if d.data_left:
            take = min(d.data_left, len(buf))
            if direction is Direction.CLIENT_TO_SERVER:
                stream = st.streams.get(d.data_stream)
                if stream is not None and not stream.analysed and len(stream.body) < MAX_BODY:
                    stream.body += buf[: min(take, MAX_BODY - len(stream.body))]
            del buf[:take]
            d.data_left -= take
            if d.data_left:
                return False
        if d.pad_left:
            take = min(d.pad_left, len(buf))
            del buf[:take]
            d.pad_left -= take
            if d.pad_left:
                return False
        sid, end = d.data_stream, d.data_end_stream
        d.data_stream = 0
        if end and direction is Direction.CLIENT_TO_SERVER:
            stream = st.streams.get(sid)
            if stream is not None and not stream.analysed and stream.pseudo:
                self._analyse(ctx, stream)
        return True

    def _frame(self, ctx: Context, st: _State, direction: Direction, ftype: int, flags: int, sid: int,
               payload: bytes) -> bool:  # fmt: skip
        """Handle one complete non-DATA frame. Returns False on a protocol error."""
        d = st.dirs[direction]
        if ftype in (HEADERS, PUSH_PROMISE):
            if sid == 0:
                return False
            pos, end = 0, len(payload)
            if flags & F_PADDED:
                if not payload:
                    return False
                pad = payload[0]
                pos, end = 1, end - pad
            if ftype == HEADERS and flags & F_PRIORITY:
                pos += 5
            elif ftype == PUSH_PROMISE:
                pos += 4
            if pos > end:
                return False
            d.block = bytearray(payload[pos:end])
            d.block_end_stream = ftype == HEADERS and bool(flags & F_END_STREAM)
            d.block_push = ftype == PUSH_PROMISE
            d.block_stream = sid
            if flags & F_END_HEADERS:
                return self._block_done(ctx, st, direction)
            return True
        if ftype == CONTINUATION:
            if not d.block_stream:
                return False
            d.block += payload
            if len(d.block) > MAX_HEADER_BLOCK:
                return False
            if flags & F_END_HEADERS:
                return self._block_done(ctx, st, direction)
            return True
        if ftype == SETTINGS:
            if sid != 0 or len(payload) % 6 or (flags & F_ACK and payload):
                return False
            for i in range(0, len(payload), 6):
                ident = int.from_bytes(payload[i : i + 2], "big")
                if ident == SETTINGS_HEADER_TABLE_SIZE:
                    # The sender's decoder accepts tables up to this size: it bounds the
                    # header blocks travelling in the opposite direction.
                    st.decoders[direction.other].allow_table_size(int.from_bytes(payload[i + 2 : i + 6], "big"))
            return True
        if ftype == RST_STREAM:
            stream = st.streams.get(sid)
            if stream is not None:
                if not stream.analysed and stream.pseudo:
                    self._analyse(ctx, stream)
                del st.streams[sid]
            return True
        return True  # PRIORITY, PING, GOAWAY, WINDOW_UPDATE and unknown types carry nothing we report

    def _block_done(self, ctx: Context, st: _State, direction: Direction) -> bool:
        d = st.dirs[direction]
        sid, end_stream, push = d.block_stream, d.block_end_stream, d.block_push
        block = bytes(d.block)
        d.block, d.block_stream = bytearray(), 0
        try:
            headers = st.decoders[direction].decode(block)
        except hpack.HpackError:
            return False
        if push:
            return True  # decoded only to keep the HPACK context in sync
        if direction is Direction.CLIENT_TO_SERVER:
            self._request_headers(ctx, st, sid, headers, end_stream)
        else:
            self._response_headers(ctx, st, sid, headers)
        return True

    # ------------------------------------------------------------------ streams

    def _request_headers(self, ctx: Context, st: _State, sid: int, headers: list[hpack.Header],
                         end_stream: bool) -> None:  # fmt: skip
        stream = st.streams.get(sid)
        if stream is None:
            if len(st.streams) >= MAX_STREAMS:
                _, old = st.streams.popitem(last=False)
                if not old.analysed and old.pseudo:
                    self._analyse(ctx, old)
            stream = st.streams[sid] = _Stream()
        if stream.analysed:
            return
        for hdr in headers:
            name, value = text(hdr.name), text(hdr.value)
            if name.startswith(":"):
                stream.pseudo.setdefault(name, value)
            else:
                stream.headers.append((name, value))
        if end_stream and stream.pseudo:
            self._analyse(ctx, stream)

    def _response_headers(self, ctx: Context, st: _State, sid: int, headers: list[hpack.Header]) -> None:
        status = next((text(h.value) for h in headers if h.name == b":status"), None)
        stream = st.streams.get(sid)
        if status is None or stream is None or status.startswith("1") or stream.result_done:
            return  # trailers, interim responses (100 Continue) and unknown streams are not verdicts
        if stream.analysed:
            self._result(ctx, stream, status)
            del st.streams[sid]  # request analysed and answered: nothing more to track
        else:
            stream.status = status  # early response: decide once the request has been analysed

    def _result(self, ctx: Context, stream: _Stream, status: str) -> None:
        stream.result_done = True
        if not stream.auth_scheme:
            return
        failed = status.startswith(("401", "403", "407"))
        if stream.auth_scheme == "form" and not failed:
            return  # most sites answer failed form logins with 200/302: no reliable success signal
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol=PROTOCOL, reverse=True, plugin=self.name,
            username=stream.auth_user,
            value=f"{stream.auth_scheme} login {'failed' if failed else 'succeeded'} (HTTP/2 {status})",
        )  # fmt: skip

    # ------------------------------------------------------------------ request analysis
    # Mirrors HTTPPlugin._request so HTTP/2 yields the same finding shapes as HTTP/1.

    def _emit(self, ctx: Context, kind: Kind, **kw: Any) -> None:
        ctx.emit(Direction.CLIENT_TO_SERVER, kind, protocol=PROTOCOL, plugin=self.name, **kw)

    def _analyse(self, ctx: Context, stream: _Stream) -> None:
        stream.analysed = True
        body = bytes(stream.body)
        stream.body = bytearray()
        method = stream.pseudo.get(":method", "")
        target = stream.pseudo.get(":path", "")
        headers = stream.headers

        def header(name: str) -> str | None:
            return next((v for k, v in headers if k.lower() == name), None)

        authority = stream.pseudo.get(":authority") or header("host") or ""
        parts = urlsplit(target)
        path = parts.path or target
        url_host = parts.netloc or authority
        url = f"{method} {url_host}{path}" + (f"?{parts.query}" if parts.query else "")

        if self.options.get("urls", True) and not path.lower().endswith(_STATIC):
            self._emit(ctx, Kind.URL, value=url, extra={"host": url_host})

        params = parse_qsl(parts.query, keep_blank_values=True)
        body_params: list[tuple[str, str]] = []
        ctype = (header("content-type") or "").lower()
        if body:
            if "application/x-www-form-urlencoded" in ctype or (not ctype and b"=" in body and printable_ascii(body)):
                body_params = parse_qsl(text(body), keep_blank_values=True)
            elif "json" in ctype or body.lstrip()[:1] in (b"{", b"["):
                try:
                    _flatten_json(json.loads(body), body_params)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    pass
        all_params = params + body_params

        if "ocsp" not in url_host:
            for k, v in all_params:
                if k.lower() in SEARCH_FIELDS and v and not (len(v) == 1 and v.isdigit()) and len(v) <= 100:
                    self._emit(ctx, Kind.SEARCH, value=v.replace("+", " "), extra={"host": url_host, "param": k})
                    break

        user = next((v for k, v in all_params if k.lower() in USER_FIELDS and v), None)
        password = next((v for k, v in all_params if k.lower() in PASS_FIELDS and v), None)
        if password is not None and len(password) <= 256:
            self._emit(ctx, Kind.CREDENTIAL if user else Kind.PASSWORD, username=user, secret=password,
                       risk="high", extra={"mechanism": "form" if body_params else "query string", "url": url})  # fmt: skip
            stream.auth_scheme, stream.auth_user = "form", user

        for k, v in all_params:
            if k.lower() in API_KEY_PARAMS and v and len(v) >= 8:
                kind = Kind.TOKEN if "token" in k.lower() else Kind.API_KEY
                self._emit(ctx, kind, secret=v, risk="high", extra={"param": k, "url": url})

        if method == "POST" and body and "ocsp" not in url_host and printable_ascii(body):
            self._emit(ctx, Kind.POST, value=text(body), extra={"url": url})

        for name, value in headers:
            lname = name.lower()
            if lname in ("authorization", "proxy-authorization"):
                scheme, auth_user = self._authorization(ctx, value, lname, url)
                if scheme:
                    stream.auth_scheme, stream.auth_user = scheme, auth_user
            elif lname in API_KEY_HEADERS and value:
                self._emit(ctx, Kind.API_KEY, secret=value, risk="high", extra={"header": name, "url": url})
            elif lname == "cookie" and self.cookie_mode != "off":
                # HTTP/2 may split the Cookie header into several fields (RFC 9113 §8.2.3).
                for item in value.split(";"):
                    cname, _, cval = item.strip().partition("=")
                    if cname and cval and (self.cookie_mode == "all" or _SESSION_COOKIE.search(cname)):
                        self._emit(ctx, Kind.COOKIE, secret=f"{cname}={cval}", risk="medium",
                                   extra={"cookie": cname, "host": url_host})  # fmt: skip

        blob = "\n".join(v for k, v in headers if k.lower() not in ("authorization", "proxy-authorization", "cookie"))
        for m in _JWT.finditer(blob.encode("utf-8", "surrogateescape") + b"\n" + body):
            self._emit(ctx, Kind.TOKEN, secret=text(m.group()), risk="high", extra={"token_type": "JWT", "url": url})

        if stream.status is not None:
            self._result(ctx, stream, stream.status)

    def _authorization(self, ctx: Context, value: str, header: str, url: str) -> tuple[str, str | None]:
        scheme, _, param = value.partition(" ")
        s = scheme.lower()
        extra = {"header": header, "url": url}
        if s == "basic":
            decoded = b64decode(param)
            if decoded is None:
                return "", None
            user, _, password = text(decoded).partition(":")
            self._emit(ctx, Kind.CREDENTIAL, username=user, secret=password, risk="high",
                       extra={**extra, "mechanism": "Basic"})  # fmt: skip
            return "Basic", user
        if s == "bearer":
            kind_extra = {"token_type": "JWT"} if _JWT.match(param.encode("utf-8", "surrogateescape")) else {}
            self._emit(ctx, Kind.TOKEN, secret=param.strip(), risk="high",
                       extra={**extra, "mechanism": "Bearer", **kind_extra})  # fmt: skip
            return "Bearer", None
        if s == "digest":
            # metadata only: never the response digest or nonce
            fields = dict(re.findall(r'(\w+)="?([^",]*)"?', param))
            digest_user = fields.get("username")
            self._emit(ctx, Kind.AUTH_EVENT, username=digest_user,
                       value=f"HTTP Digest ({fields.get('algorithm', 'MD5')})", risk="medium",
                       extra={**extra, "mechanism": "Digest", "realm": fields.get("realm")})  # fmt: skip
            return "Digest", digest_user
        if s in ("ntlm", "negotiate"):
            decoded = b64decode(param)
            if not decoded:
                return "", None
            msg = ntlm.parse_authenticate(decoded) if decoded.startswith(ntlm.SIGNATURE) else None
            if msg is not None:
                self._emit(ctx, Kind.AUTH_EVENT, username=msg.user, domain=msg.domain or None,
                           value=f"{msg.version} authentication over HTTP/2",
                           risk="high" if msg.version == "NTLMv1" else "medium",
                           extra={**extra, "mechanism": scheme, "workstation": msg.workstation,
                                  "ntlm_version": msg.version})  # fmt: skip
                return scheme, msg.user
            if not decoded.startswith(ntlm.SIGNATURE):
                self._emit(ctx, Kind.AUTH_EVENT, value="Kerberos (SPNEGO) authentication over HTTP/2", risk="low",
                           extra={**extra, "mechanism": scheme})  # fmt: skip
            return "", None
        return "", None
