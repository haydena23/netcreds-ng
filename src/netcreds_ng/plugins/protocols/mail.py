"""SMTP / POP3 / IMAP authentication (any port).

Covers SMTP/POP3 ``AUTH PLAIN|LOGIN|CRAM-MD5|NTLM|XOAUTH2`` (with initial
responses and continuations), POP3 ``USER/PASS`` and ``APOP``, IMAP ``LOGIN``
(quoted strings, atoms and literals) and ``AUTHENTICATE``, login results, and
STARTTLS (parsing stops once the session is encrypted, unless the engine decrypts TLS with a key log).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, b64decode, sasl_plain, text
from netcreds_ng.proto import ntlm

_GIVE_UP_BYTES = 16 * 1024
_LITERAL = re.compile(rb"\{(\d+)\+?\}$")
_IMAP_TAG = re.compile(rb"^([A-Za-z0-9.]+) ")
_B64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}")


def _is_text(raw: bytes) -> bool:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return decoded.isprintable()


@dataclass
class _Auth:
    mech: str
    step: int = 0
    user: str | None = None
    tag: bytes | None = None  # IMAP tag


@dataclass
class _State:
    lines: tuple[LineBuffer, LineBuffer] = field(default_factory=lambda: (LineBuffer(), LineBuffer()))
    proto: str | None = None
    auth: _Auth | None = None
    pop_user: str | None = None
    result_for: str | None = None  # username awaiting a server verdict
    result_tag: bytes | None = None
    awaiting_result: bool = False
    tls_pending: bool = False
    literal_buf: bytes | None = None
    mail_seen: bool = False
    client_bytes: int = 0


def _imap_args(data: bytes) -> list[bytes]:
    """Tokenise IMAP arguments: atoms, "quoted strings" and {n} literals (already joined with CRLF)."""
    out: list[bytes] = []
    i, n = 0, len(data)
    while i < n:
        c = data[i : i + 1]
        if c in (b" ", b"\r", b"\n"):
            i += 1
        elif c == b'"':
            j, buf = i + 1, bytearray()
            while j < n and data[j : j + 1] != b'"':
                if data[j : j + 1] == b"\\" and j + 1 < n:
                    j += 1
                buf += data[j : j + 1]
                j += 1
            out.append(bytes(buf))
            i = j + 1
        elif c == b"{":
            m = re.match(rb"\{(\d+)\+?\}\r\n", data[i:])
            if not m:
                out.append(data[i:].split()[0])
                break
            size = int(m.group(1))
            start = i + m.end()
            out.append(data[start : start + size])
            i = start + size
        else:
            j = i
            while j < n and data[j : j + 1] not in (b" ", b"\r", b"\n"):
                j += 1
            out.append(data[i:j])
            i = j
    return out


class MailPlugin(ProtocolPlugin):
    name = "mail"
    wants_encrypted = False
    sets = ("email", "legacy")
    description = "SMTP/POP3/IMAP logins, SASL mechanisms and results (any port)"
    default_ports = frozenset({25, 110, 143, 465, 587, 993, 995, 2525})
    priority = 20

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        st: _State = ctx.state
        st.lines[direction].gap()
        if direction is Direction.CLIENT_TO_SERVER:
            st.auth = None  # a lost continuation would mis-assign username/password
            st.literal_buf = None

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        for line in st.lines[direction].feed(data):
            if ctx.detached:
                return
            if direction is Direction.CLIENT_TO_SERVER:
                self._client(ctx, st, line)
            else:
                self._server(ctx, st, line)
        if direction is Direction.CLIENT_TO_SERVER:
            st.client_bytes += len(data)
            if not st.mail_seen and st.client_bytes > _GIVE_UP_BYTES:
                ctx.detach()

    # helpers ---------------------------------------------------------------

    def _emit(self, ctx: Context, kind: Kind, st: _State, **kw: object) -> None:
        ctx.emit(
            Direction.CLIENT_TO_SERVER, kind, protocol=st.proto or "Mail", plugin=self.name, **kw  # type: ignore[arg-type]
        )

    def _credential(self, ctx: Context, st: _State, user: str | None, password: str, mech: str) -> None:
        kind = Kind.CREDENTIAL if user else Kind.PASSWORD
        self._emit(ctx, kind, st, username=user, secret=password, risk="high", extra={"mechanism": mech})
        st.result_for = user
        st.awaiting_result = True

    @staticmethod
    def _is_pop3(ctx: Context, st: _State) -> bool:
        """USER/PASS is shared with FTP: only treat it as POP3 after a POP3 greeting or on a POP3 port."""
        return st.proto == "POP3" or (st.proto is None and ctx.flow.server.port in (110, 995))

    # server ------------------------------------------------------------------

    def _server(self, ctx: Context, st: _State, line: bytes) -> None:
        if st.proto is None:
            if line.startswith(b"+OK"):
                st.proto, st.mail_seen = "POP3", True
            elif line.startswith((b"* OK", b"* PREAUTH")):
                st.proto, st.mail_seen = "IMAP", True
            elif line.startswith(b"220") and (b"SMTP" in line.upper() or b"MAIL" in line.upper()):
                st.proto, st.mail_seen = "SMTP", True
        if st.tls_pending:
            if line.startswith((b"220", b"+OK")) or (st.result_tag and line.startswith(st.result_tag + b" OK")):
                if not ctx.tls_decryption:
                    ctx.detach()  # session switches to TLS
                    return
                st.tls_pending = False  # decrypted plaintext follows: keep parsing
                for buf in st.lines:
                    buf.reset()
                return
            if not line.startswith(b"250"):
                st.tls_pending = False
        if not st.awaiting_result:
            return
        verdict: bool | None = None
        if st.proto == "SMTP" or (st.proto is None and line[:3].isdigit()):
            if line.startswith(b"235"):
                verdict = True
            elif line[:1] in (b"4", b"5") and line[:3].isdigit():
                verdict = False
        elif st.proto == "POP3":
            if line.startswith(b"+OK"):
                verdict = True
            elif line.startswith(b"-ERR"):
                verdict = False
        elif st.proto == "IMAP" and st.result_tag is not None:
            if line.startswith(st.result_tag + b" OK"):
                verdict = True
            elif line.startswith((st.result_tag + b" NO", st.result_tag + b" BAD")):
                verdict = False
        if verdict is not None:
            st.awaiting_result = False
            ctx.emit(
                Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol=st.proto or "Mail", reverse=True,
                username=st.result_for, value="login succeeded" if verdict else "login failed", plugin=self.name,
            )  # fmt: skip

    # client ------------------------------------------------------------------

    def _client(self, ctx: Context, st: _State, line: bytes) -> None:
        if st.literal_buf is not None:
            line = st.literal_buf + b"\r\n" + line
            st.literal_buf = None
        if _LITERAL.search(line) and st.auth is None and b"LOGIN" in line[:40].upper():
            st.literal_buf = line
            return
        if st.auth is not None:
            if line.strip() == b"*" or _B64.fullmatch(line.strip()):
                self._auth_continuation(ctx, st, line)
                return
            st.auth = None  # client abandoned the exchange (e.g. RSET): parse the line as a command
        tag = b""
        body = line
        m = _IMAP_TAG.match(line)
        if m and (st.proto == "IMAP" or line[m.end() :].upper().startswith((b"LOGIN ", b"AUTHENTICATE ", b"STARTTLS"))):
            tag, body = m.group(1), line[m.end() :]
            if st.proto is None:
                st.proto = "IMAP"
        verb, _, rest = body.partition(b" ")
        verb = verb.upper()
        if verb in (b"EHLO", b"HELO") and not tag:
            st.proto, st.mail_seen = st.proto or "SMTP", True
        elif verb in (b"STARTTLS", b"STLS"):
            st.mail_seen = True
            st.tls_pending = True
            st.result_tag = tag or None
        elif verb == b"LOGIN" and tag:
            st.mail_seen = True
            args = _imap_args(rest)
            if len(args) >= 2:
                st.result_tag = tag
                self._credential(ctx, st, text(args[0]), text(args[1]), "IMAP LOGIN")
        elif verb in (b"AUTH", b"AUTHENTICATE"):
            st.mail_seen = True
            parts = rest.split()
            if not parts:
                return
            mech = text(parts[0]).upper()
            st.auth = _Auth(mech, tag=tag or None)
            st.result_tag = tag or None
            if st.proto is None and not tag:
                st.proto = "SMTP"
            if len(parts) > 1 and parts[1] != b"=":
                self._auth_continuation(ctx, st, parts[1])
        elif verb == b"USER" and not tag and rest.strip() and self._is_pop3(ctx, st):
            st.pop_user = text(rest.strip())
        elif verb == b"PASS" and not tag and st.pop_user is not None:
            st.mail_seen = True
            st.proto = "POP3"
            self._credential(ctx, st, st.pop_user, text(rest.strip()), "USER/PASS")
            st.pop_user = None
        elif verb == b"APOP" and not tag:
            st.mail_seen = True
            st.proto = st.proto or "POP3"
            args = rest.split()
            if args:
                self._emit(ctx, Kind.AUTH_EVENT, st, username=text(args[0]), value="APOP (MD5 challenge-response)",
                           risk="medium", extra={"mechanism": "APOP"})  # fmt: skip
                st.result_for, st.awaiting_result = text(args[0]), True

    def _auth_continuation(self, ctx: Context, st: _State, line: bytes) -> None:
        auth = st.auth
        assert auth is not None
        if line.strip() == b"*":
            st.auth = None
            return
        decoded = b64decode(line)
        if decoded is None:
            st.auth = None
            return
        mech = auth.mech
        if mech in ("PLAIN", "LOGIN") and not _is_text(decoded.replace(b"\x00", b"")):
            st.auth = None  # not a real username/password (binary after decoding): never guess
            return
        if mech == "PLAIN":
            parts = sasl_plain(decoded)
            st.auth = None
            if parts:
                self._credential(ctx, st, parts[1] or parts[0], parts[2], "AUTH PLAIN")
        elif mech == "LOGIN":
            if auth.step == 0:
                auth.user = text(decoded)
                auth.step = 1
            else:
                st.auth = None
                self._credential(ctx, st, auth.user, text(decoded), "AUTH LOGIN")
        elif mech == "CRAM-MD5":
            st.auth = None
            # "<user> <hex digest>": without the separator there is no safe username to report
            user = text(decoded.rsplit(b" ", 1)[0]) if b" " in decoded else None
            self._emit(ctx, Kind.AUTH_EVENT, st, username=user, value="CRAM-MD5 (challenge-response)",
                       risk="medium", extra={"mechanism": mech})  # fmt: skip
            st.result_for, st.awaiting_result = user, True
        elif mech == "NTLM":
            msg = ntlm.parse_authenticate(decoded)
            if msg is not None:
                st.auth = None
                self._emit(ctx, Kind.AUTH_EVENT, st, username=msg.user, domain=msg.domain or None,
                           value=f"{msg.version} authentication", risk="high" if msg.version == "NTLMv1" else "medium",
                           extra={"mechanism": "NTLM", "workstation": msg.workstation, "ntlm_version": msg.version})  # fmt: skip
                st.result_for, st.awaiting_result = msg.user, True
        elif mech in ("XOAUTH2", "OAUTHBEARER"):
            st.auth = None
            raw = text(decoded)
            user_m = re.search(r"user=([^\x01,]+)", raw) or re.search(r"a=([^,\x01]+)", raw)
            tok_m = re.search(r"auth=Bearer ([^\x01]+)", raw)
            if tok_m:
                self._emit(ctx, Kind.TOKEN, st, username=user_m.group(1) if user_m else None, secret=tok_m.group(1),
                           risk="high", extra={"mechanism": mech})  # fmt: skip
        else:
            st.auth = None  # GSSAPI, SCRAM, ...: no cleartext exposure to report
