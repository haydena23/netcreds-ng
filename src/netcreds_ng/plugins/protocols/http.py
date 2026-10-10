"""HTTP/1.x: URLs, searches, POST bodies, form/JSON credentials, Authorization schemes,
API keys, session cookies and JWTs (any port).

Requests are parsed as real HTTP messages (Content-Length and chunked bodies,
pipelining, resynchronisation after gaps).
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import b64decode, printable_ascii, text
from netcreds_ng.proto import ntlm

METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"TRACK", b"PROPFIND")
_REQ_START = re.compile(rb"(?:^|\r?\n)((?:" + b"|".join(METHODS) + rb") \S+ HTTP/1\.[01])\r?\n")
_STATIC = (".jpg", ".jpeg", ".gif", ".png", ".css", ".ico", ".js", ".svg", ".woff", ".woff2", ".webp", ".map")
_JWT = re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_SESSION_COOKIE = re.compile(r"sess|sid$|^sid|token|auth|jwt|login|remember|phpsessid|jsessionid|asp\.net", re.I)

# Field names from the original (Pcredz-derived), matched exactly (case-insensitive) instead of by substring.
USER_FIELDS = {
    "log", "login", "wpname", "ahd_username", "unickname", "nickname", "user", "user_name", "alias", "pseudo",
    "email", "username", "_username", "userid", "form_loginname", "loginname", "login_id", "loginid",
    "session_key", "sessionkey", "pop_login", "uid", "id", "user_id", "screename", "uname", "ulogin",
    "acctname", "account", "member", "mailaddress", "membername", "login_username", "login_email",
    "loginusername", "loginemail", "uin", "sign-in", "usuario", "j_username", "user[login]", "user[email]",
}  # fmt: skip
PASS_FIELDS = {
    "ahd_password", "pass", "password", "_password", "passwd", "session_password", "sessionpassword",
    "login_password", "loginpassword", "form_pw", "pw", "userpassword", "pwd", "upassword", "passwort",
    "passwrd", "wppassword", "upasswd", "senha", "contrasena", "j_password", "user[password]", "secret",
}  # fmt: skip
SEARCH_FIELDS = {"search", "query", "q", "p", "searchterm", "keywords", "keyword", "command", "terms", "keys",
                 "question", "kwd", "searchphrase", "s"}  # fmt: skip
API_KEY_HEADERS = {"x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "private-token", "x-apikey"}
API_KEY_PARAMS = {"api_key", "apikey", "api-key", "access_token", "auth_token", "token", "key"}

CRLF = b"\r\n"
MAX_BODY = 256 * 1024
MAX_HEADER = 64 * 1024


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes = b""

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None


@dataclass
class _Parser:
    """Incremental HTTP/1.x message framer for one direction."""

    is_request: bool
    buf: bytearray = field(default_factory=bytearray)
    head: Any = None  # parsed start-line/headers awaiting body
    remaining: int = 0
    chunked: bool = False
    body: bytearray = field(default_factory=bytearray)
    dead: bool = False  # unframeable (e.g. response read-until-close)
    chunk_state: str = "size"
    #: response parser only: methods of requests still awaiting a final response (HEAD has no body)
    methods: deque[str] = field(default_factory=lambda: deque(maxlen=64))
    #: response parser only: no "HTTP/1." starts before this offset of ``buf`` (it was only appended to since)
    searched: int = 0

    def feed(self, data: bytes) -> list[tuple[Any, bytes]]:
        if self.dead:
            return []
        self.buf += data
        out: list[tuple[Any, bytes]] = []
        while not self.dead:
            if self.head is None:
                if not self._read_head():
                    break
            if self.chunked:
                if not self._read_chunks():
                    break
            else:
                take = min(self.remaining, len(self.buf))
                if len(self.body) < MAX_BODY:
                    self.body += self.buf[: min(take, MAX_BODY - len(self.body))]
                del self.buf[:take]
                self.remaining -= take
                if self.remaining > 0:
                    break
            out.append((self.head, bytes(self.body)))
            self.head, self.body, self.chunked, self.remaining = None, bytearray(), False, 0
        return out

    def resync(self) -> None:
        self.buf.clear()
        self.searched = 0
        self.head, self.body, self.chunked, self.remaining = None, bytearray(), False, 0
        self.chunk_state = "size"

    def _read_head(self) -> bool:
        if self.is_request:
            m = _REQ_START.search(self.buf)
            if m is None:
                if len(self.buf) > MAX_HEADER:
                    del self.buf[: len(self.buf) - 64]
                return False
            if m.start(1) > 0:
                del self.buf[: m.start(1)]
        elif not self.buf.startswith(b"HTTP/"):
            idx = self.buf.find(b"HTTP/1.", self.searched)
            if idx < 0:
                if len(self.buf) > MAX_HEADER:
                    self.buf.clear()
                    self.searched = 0
                else:  # nothing before here can start a match: only appended bytes are searched next time
                    self.searched = max(0, len(self.buf) - 6)
                return False
            del self.buf[:idx]
        self.searched = 0  # the buffer may now change other than by appending
        end = self.buf.find(b"\r\n\r\n")
        sep = 4
        if end < 0:
            end, sep = self.buf.find(b"\n\n"), 2
        if end < 0:
            if len(self.buf) > MAX_HEADER:
                self.resync()
            return False
        raw = bytes(self.buf[:end])
        del self.buf[: end + sep]
        lines = raw.replace(b"\r\n", b"\n").split(b"\n")
        start = lines[0].split(b" ", 2)
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            k, sepc, v = line.partition(b":")
            if sepc:
                headers.append((text(k.strip()), text(v.strip())))
        hmap = {k.lower(): v for k, v in headers}
        te = hmap.get("transfer-encoding", "").lower()
        code = start[1] if len(start) > 1 else b""
        no_body = False
        if not self.is_request:
            if code.startswith(b"1"):
                no_body = True  # interim response; the request still awaits its final response
            else:
                method = self.methods.popleft() if self.methods else ""
                no_body = method == "HEAD" or code in (b"204", b"304")
        if no_body:
            self.chunked, self.remaining = False, 0
        elif "chunked" in te:
            self.chunked = True
        else:
            try:
                self.remaining = max(0, int(hmap.get("content-length", "0") or 0))
            except ValueError:
                self.remaining = 0
            if not self.is_request and "content-length" not in hmap:
                self.dead = True  # body runs until close; we only need response headers
        if self.is_request:
            if len(start) < 3:
                self.chunked, self.remaining = False, 0
                return False
            self.head = Request(text(start[0]), text(start[1]), text(start[2]), headers)
        else:
            self.head = (text(start[1]) if len(start) > 1 else "", headers)
        return True

    def _read_chunks(self) -> bool:
        """Chunked body state machine. ``chunk_state``: size -> data -> crlf -> size ... -> trailer."""
        while True:
            if self.chunk_state == "size":
                idx = self.buf.find(CRLF)
                if idx < 0:
                    return False
                size_s = bytes(self.buf[:idx]).split(b";")[0].strip()
                del self.buf[: idx + 2]
                try:
                    self.remaining = int(size_s, 16)
                except ValueError:
                    self.resync()
                    return False
                self.chunk_state = "data" if self.remaining else "trailer"
            elif self.chunk_state == "data":
                take = min(self.remaining, len(self.buf))
                if len(self.body) < MAX_BODY:
                    self.body += self.buf[: min(take, MAX_BODY - len(self.body))]
                del self.buf[:take]
                self.remaining -= take
                if self.remaining:
                    return False
                self.chunk_state = "crlf"
            elif self.chunk_state == "crlf":
                if len(self.buf) < 2:
                    return False
                del self.buf[:2]
                self.chunk_state = "size"
            else:  # trailer: header lines until an empty line
                idx = self.buf.find(CRLF)
                if idx < 0:
                    return False
                del self.buf[: idx + 2]
                if idx == 0:
                    self.chunk_state = "size"
                    return True


@dataclass
class _State:
    parsers: tuple[_Parser, _Parser] = field(default_factory=lambda: (_Parser(True), _Parser(False)))
    # (username, scheme) for each request awaiting its final response
    pending: deque[tuple[str | None, str]] = field(default_factory=lambda: deque(maxlen=64))
    http_seen: bool = False
    client_bytes: int = 0


def _flatten_json(obj: Any, out: list[tuple[str, str]], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                out.append((str(k), str(v)))
            else:
                _flatten_json(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:100]:
            _flatten_json(v, out, depth + 1)


class HTTPPlugin(ProtocolPlugin):
    name = "http"
    sets = ("web", "legacy")
    description = "HTTP URLs, searches, POST bodies, credentials, auth headers, API keys, cookies, JWTs"
    default_ports = frozenset({80, 8000, 8008, 8080, 8081, 8888, 3128})
    priority = 50

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    @property
    def cookie_mode(self) -> str:
        return str(self.options.get("cookies", "session"))  # session / all / off

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        ctx.state.parsers[direction].resync()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        if direction is Direction.CLIENT_TO_SERVER:
            st.client_bytes += len(data)
            for req, body in st.parsers[0].feed(data):
                st.http_seen = True
                req.body = body
                st.parsers[1].methods.append(req.method.upper())
                self._request(ctx, st, req)
            if not st.http_seen and st.client_bytes > MAX_HEADER:
                ctx.detach()
        else:
            for (status, _headers), _body in st.parsers[1].feed(data):
                if status.startswith("1") or not st.pending:
                    continue  # interim responses (100 Continue) are not verdicts
                user, scheme = st.pending.popleft()
                if not scheme:
                    continue
                failed = status.startswith(("401", "403", "407"))
                if scheme == "form" and not failed:
                    continue  # most sites answer failed form logins with 200/302: no reliable success signal
                ctx.emit(
                    Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="HTTP", reverse=True,
                    username=user, value=f"{scheme} login {'failed' if failed else 'succeeded'} (HTTP {status})",
                    plugin=self.name,
                )  # fmt: skip

    # request analysis ------------------------------------------------------

    def _emit(self, ctx: Context, kind: Kind, **kw: Any) -> None:
        ctx.emit(Direction.CLIENT_TO_SERVER, kind, protocol="HTTP", plugin=self.name, **kw)

    def _request(self, ctx: Context, st: _State, req: Request) -> None:
        host = req.header("host") or ""
        target = req.target
        parts = urlsplit(target)
        path = parts.path or target
        url_host = parts.netloc or host
        url = f"{req.method} {url_host}{path}" + (f"?{parts.query}" if parts.query else "")
        auth_scheme = ""
        auth_user: str | None = None

        if self.options.get("urls", True) and not path.lower().endswith(_STATIC):
            self._emit(ctx, Kind.URL, value=url, extra={"host": url_host})

        params = parse_qsl(parts.query, keep_blank_values=True)
        body_params: list[tuple[str, str]] = []
        ctype = (req.header("content-type") or "").lower()
        if req.body:
            if "application/x-www-form-urlencoded" in ctype or (not ctype and b"=" in req.body and printable_ascii(req.body)):
                body_params = parse_qsl(text(req.body), keep_blank_values=True)
            elif "json" in ctype or req.body.lstrip()[:1] in (b"{", b"["):
                try:
                    _flatten_json(json.loads(req.body), body_params)
                except (ValueError, UnicodeDecodeError):
                    pass
        all_params = params + body_params

        # searches
        if "ocsp" not in url_host:
            for k, v in params + body_params:
                if k.lower() in SEARCH_FIELDS and v and not (len(v) == 1 and v.isdigit()) and len(v) <= 100:
                    self._emit(ctx, Kind.SEARCH, value=v.replace("+", " "), extra={"host": url_host, "param": k})
                    break

        # form / JSON credentials
        user = next((v for k, v in all_params if k.lower() in USER_FIELDS and v), None)
        password = next((v for k, v in all_params if k.lower() in PASS_FIELDS and v), None)
        if password is not None and len(password) <= 256:
            self._emit(ctx, Kind.CREDENTIAL if user else Kind.PASSWORD, username=user, secret=password,
                       risk="high", extra={"mechanism": "form" if body_params else "query string", "url": url})  # fmt: skip
            auth_scheme, auth_user = "form", user

        # API keys / tokens in parameters
        for k, v in all_params:
            if k.lower() in API_KEY_PARAMS and v and len(v) >= 8:
                kind = Kind.TOKEN if "token" in k.lower() else Kind.API_KEY
                self._emit(ctx, kind, secret=v, risk="high", extra={"param": k, "url": url})

        # POST bodies (printable only, as the original)
        if req.method == "POST" and req.body and "ocsp" not in url_host and printable_ascii(req.body):
            self._emit(ctx, Kind.POST, value=text(req.body), extra={"url": url})

        # headers
        for name, value in req.headers:
            lname = name.lower()
            if lname in ("authorization", "proxy-authorization"):
                scheme, user_from_auth = self._authorization(ctx, value, lname, url)
                if scheme:
                    auth_scheme, auth_user = scheme, user_from_auth
            elif lname in API_KEY_HEADERS and value:
                self._emit(ctx, Kind.API_KEY, secret=value, risk="high", extra={"header": name, "url": url})
            elif lname == "cookie" and self.cookie_mode != "off":
                for item in value.split(";"):
                    cname, _, cval = item.strip().partition("=")
                    if cname and cval and (self.cookie_mode == "all" or _SESSION_COOKIE.search(cname)):
                        self._emit(ctx, Kind.COOKIE, secret=f"{cname}={cval}", risk="medium",
                                   extra={"cookie": cname, "host": url_host})  # fmt: skip

        # JWTs anywhere else in the request
        blob = "\n".join(v for k, v in req.headers if k.lower() not in ("authorization", "proxy-authorization", "cookie"))
        for m in _JWT.finditer(blob.encode("utf-8", "surrogateescape") + b"\n" + req.body[:MAX_BODY]):
            self._emit(ctx, Kind.TOKEN, secret=text(m.group()), risk="high", extra={"token_type": "JWT", "url": url})

        st.pending.append((auth_user, auth_scheme))

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
            kind_extra = {"token_type": "JWT"} if _JWT.match(param.encode()) else {}
            self._emit(ctx, Kind.TOKEN, secret=param.strip(), risk="high", extra={**extra, "mechanism": "Bearer", **kind_extra})
            return "Bearer", None
        if s == "digest":
            fields = dict(re.findall(r'(\w+)="?([^",]*)"?', param))
            digest_user = fields.get("username")
            self._emit(ctx, Kind.AUTH_EVENT, username=digest_user, value=f"HTTP Digest ({fields.get('algorithm', 'MD5')})",
                       risk="medium", extra={**extra, "mechanism": "Digest", "realm": fields.get("realm")})  # fmt: skip
            return "Digest", digest_user
        if s in ("ntlm", "negotiate"):
            decoded = b64decode(param)
            if not decoded:
                return "", None
            msg = ntlm.parse_authenticate(decoded) if decoded.startswith(ntlm.SIGNATURE) else None
            if msg is not None:
                self._emit(ctx, Kind.AUTH_EVENT, username=msg.user, domain=msg.domain or None,
                           value=f"{msg.version} authentication over HTTP",
                           risk="high" if msg.version == "NTLMv1" else "medium",
                           extra={**extra, "mechanism": scheme, "workstation": msg.workstation,
                                  "ntlm_version": msg.version})  # fmt: skip
                return scheme, msg.user
            if not decoded.startswith(ntlm.SIGNATURE):
                self._emit(ctx, Kind.AUTH_EVENT, value="Kerberos (SPNEGO) authentication over HTTP", risk="low",
                           extra={**extra, "mechanism": scheme})  # fmt: skip
            return "", None
        return "", None

