"""TACACS+ (RFC 8907): cleartext logins, authorization/accounting commands, results.

Scope: bodies are only parsed when the header carries ``TAC_PLUS_UNENCRYPTED_FLAG``; in that
mode ASCII and PAP passwords cross the wire in cleartext and are reported in full. CHAP and
MS-CHAP logins are reported as metadata only (no challenge or response bytes). Obfuscated
bodies are reported once per flow as an ``AUTH_EVENT``; they are never decrypted and the
shared key is never guessed or derived.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

HEADER_LEN = 12
UNENCRYPTED_FLAG, SINGLE_CONNECT_FLAG = 0x01, 0x04
AUTHEN, AUTHOR, ACCT = 1, 2, 3
_MAX_BODY = 64 * 1024
_MAX_BUFFER = 256 * 1024
_MAX_SESSIONS = 64

ACTIONS = {1: "login", 2: "chpass", 4: "sendauth"}
AUTHEN_TYPES = {1: "ASCII", 2: "PAP", 3: "CHAP", 4: "ARAP", 5: "MSCHAP", 6: "MSCHAPv2"}
SERVICES = {0: "none", 1: "login", 2: "enable", 3: "ppp", 4: "arap", 5: "pt", 6: "rcmd",
            7: "x25", 8: "nasi", 9: "fwproxy"}  # fmt: skip
AUTHEN_STATUS = {1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER", 5: "GETPASS", 6: "RESTART",
                 7: "ERROR", 0x21: "FOLLOW"}  # fmt: skip
TYPE_NAMES = {AUTHEN: "authentication", AUTHOR: "authorization", ACCT: "accounting"}
ACCT_FLAGS = ((0x02, "start"), (0x04, "stop"), (0x08, "watchdog"))
ASCII, PAP = 1, 2
GETDATA, GETUSER, GETPASS = 3, 4, 5
REPLY_NOECHO, CONTINUE_ABORT = 0x01, 0x01
_SENSITIVE_WORDS = (b"password", b"secret", b"key ", b"community")


@dataclass
class _Session:
    action: str = "login"
    authen_type: str = "ASCII"
    service: str = "login"
    priv_lvl: int = 0
    user: str | None = None
    port: str | None = None
    rem_addr: str | None = None
    asking: int = 0  # last REPLY status asking the client for input
    noecho: bool = False
    passwords: int = 0


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    sessions: OrderedDict[int, _Session] = field(default_factory=OrderedDict)
    started: bool = False
    encrypted_reported: bool = False


def _fields(body: bytes, pos: int, lengths: list[int]) -> list[bytes] | None:
    """Consecutive fields of the given lengths; None unless they exactly fill ``body``."""
    out: list[bytes] = []
    for n in lengths:
        out.append(body[pos : pos + n])
        pos += n
    return out if pos == len(body) else None


def _args(raw: list[bytes]) -> list[str]:
    return [text(a[:256]) for a in raw]


def _command(args: list[str]) -> str | None:
    cmd: str | None = None
    rest: list[str] = []
    for a in args:
        # Mandatory "key=value" or optional "key*value": split on whichever separator comes first.
        positions = [i for i in (a.find("="), a.find("*")) if i >= 0]
        if not positions:
            continue
        cut = min(positions)
        key, sep, val = a[:cut], a[cut], a[cut + 1 :]
        if not sep:
            continue
        if key == "cmd":
            cmd = val
        elif key == "cmd-arg" and val != "<cr>":
            rest.append(val)
    if cmd is None:
        return None
    return " ".join([cmd, *rest]).strip()


class TacacsPlugin(ProtocolPlugin):
    name = "tacacs"
    description = "TACACS+: cleartext ASCII/PAP logins, command authorization/accounting, results"
    default_ports = frozenset({49})
    priority = 90

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    # -- stream plumbing ---------------------------------------------------------------
    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        buf = st.bufs[direction]
        buf += data
        while not ctx.detached and len(buf) >= HEADER_LEN:
            version, ptype, seq, flags = buf[0], buf[1], buf[2], buf[3]
            session_id = int.from_bytes(buf[4:8], "big")
            length = int.from_bytes(buf[8:12], "big")
            client = direction is Direction.CLIENT_TO_SERVER
            if (
                version not in (0xC0, 0xC1)
                or ptype not in TYPE_NAMES
                or seq == 0
                or (seq % 2 == 1) != client
                or flags & ~(UNENCRYPTED_FLAG | SINGLE_CONNECT_FLAG)
                or length > _MAX_BODY
                or (not st.started and (not client or seq != 1))
            ):
                ctx.detach()
                return
            if len(buf) < HEADER_LEN + length:
                break
            body = bytes(buf[HEADER_LEN : HEADER_LEN + length])
            del buf[: HEADER_LEN + length]
            st.started = True
            if not flags & UNENCRYPTED_FLAG:
                self._encrypted(ctx, st, ptype, version, session_id)
                continue
            if not self._packet(ctx, st, direction, ptype, seq, session_id, body):
                ctx.detach()
                return
        if len(buf) > _MAX_BUFFER:
            ctx.detach()

    def _session(self, st: _State, session_id: int, create: bool) -> _Session | None:
        sess = st.sessions.get(session_id)
        if sess is None and create:
            if len(st.sessions) >= _MAX_SESSIONS:
                st.sessions.popitem(last=False)
            sess = st.sessions[session_id] = _Session()
        return sess

    def _encrypted(self, ctx: Context, st: _State, ptype: int, version: int, session_id: int) -> None:
        if st.encrypted_reported:
            return
        st.encrypted_reported = True
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="TACACS+",
            value="TACACS+ session (encrypted body)", plugin=self.name, risk="info",
            tags=self._tags(ctx, "obfuscated-body"),
            extra={"session_id": f"{session_id:08x}", "packet_type": TYPE_NAMES[ptype],
                   "minor_version": version & 0x0F},
        )  # fmt: skip

    def _packet(
        self, ctx: Context, st: _State, direction: Direction, ptype: int, seq: int, sid: int, body: bytes,
    ) -> bool:  # fmt: skip
        """Handle one cleartext body; False when it is malformed."""
        client = direction is Direction.CLIENT_TO_SERVER
        if ptype == AUTHEN:
            if client:
                return self._start(ctx, st, sid, body) if seq == 1 else self._continue(ctx, st, sid, body)
            return self._authen_reply(ctx, st, sid, body)
        if client:
            return self._author_acct(ctx, st, ptype, sid, body)
        return self._author_acct_reply(ptype, body)

    # -- authentication ----------------------------------------------------------------
    def _start(self, ctx: Context, st: _State, sid: int, body: bytes) -> bool:
        if len(body) < 8:
            return False
        action, priv, atype, service = body[0], body[1], body[2], body[3]
        parts = _fields(body, 8, list(body[4:8]))
        if parts is None:
            return False
        user, port, rem, data = parts
        sess = self._session(st, sid, create=True)
        assert sess is not None
        sess.action = ACTIONS.get(action, str(action))
        sess.authen_type = AUTHEN_TYPES.get(atype, str(atype))
        sess.service = SERVICES.get(service, str(service))
        sess.priv_lvl = priv
        sess.user = text(user) if user else None
        sess.port = text(port) if port else None
        sess.rem_addr = text(rem) if rem else None
        if atype == PAP:
            self._credential(ctx, sess, sid, data)
        elif atype != ASCII:
            ctx.emit(
                Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="TACACS+", username=sess.user,
                value=f"TACACS+ {sess.authen_type} login", plugin=self.name, risk="medium",
                tags=self._tags(ctx), extra=self._extra(sess, sid),
            )  # fmt: skip
        return True

    def _continue(self, ctx: Context, st: _State, sid: int, body: bytes) -> bool:
        if len(body) < 5:
            return False
        msg_len, data_len, flags = int.from_bytes(body[0:2], "big"), int.from_bytes(body[2:4], "big"), body[4]
        parts = _fields(body, 5, [msg_len, data_len])
        if parts is None:
            return False
        sess = self._session(st, sid, create=False)
        if sess is None or flags & CONTINUE_ABORT:
            return True
        asking, sess.asking = sess.asking, 0
        user_msg = parts[0]
        if asking == GETUSER:
            sess.user = text(user_msg) if user_msg else None
        elif asking == GETPASS or (asking == GETDATA and sess.noecho):
            self._credential(ctx, sess, sid, user_msg)
        return True

    def _authen_reply(self, ctx: Context, st: _State, sid: int, body: bytes) -> bool:
        if len(body) < 6:
            return False
        status, flags = body[0], body[1]
        msg_len, data_len = int.from_bytes(body[2:4], "big"), int.from_bytes(body[4:6], "big")
        parts = _fields(body, 6, [msg_len, data_len])
        if parts is None:
            return False
        sess = self._session(st, sid, create=False)
        if sess is None:
            return True
        if status in (GETUSER, GETPASS, GETDATA):
            sess.asking = status
            sess.noecho = bool(flags & REPLY_NOECHO)
        elif status in (1, 2):
            extra = self._extra(sess, sid)
            if parts[0]:
                extra["message"] = text(parts[0][:120])
            ctx.emit(
                Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="TACACS+", reverse=True,
                username=sess.user, value="login succeeded" if status == 1 else "login failed",
                plugin=self.name, tags=self._tags(ctx), extra=extra,
            )  # fmt: skip
            st.sessions.pop(sid, None)
        return True

    def _credential(self, ctx: Context, sess: _Session, sid: int, password: bytes) -> None:
        if not password:
            return
        sess.passwords += 1
        more = ["cleartext-password"]
        if sess.action == "chpass" and sess.passwords > 1:
            more.append("new-password")
        kind = Kind.CREDENTIAL if sess.user else Kind.PASSWORD
        ctx.emit(
            Direction.CLIENT_TO_SERVER, kind, protocol="TACACS+", username=sess.user,
            secret=text(password[:256]), plugin=self.name, risk="high",
            tags=self._tags(ctx, *more), extra=self._extra(sess, sid),
        )  # fmt: skip

    # -- authorization / accounting ----------------------------------------------------
    def _author_acct(self, ctx: Context, st: _State, ptype: int, sid: int, body: bytes) -> bool:
        off = 1 if ptype == ACCT else 0  # accounting requests start with a flags octet
        if len(body) < off + 8:
            return False
        acct_flags = body[0] if off else 0
        priv, atype, service = body[off + 1], body[off + 2], body[off + 3]
        user_len, port_len, rem_len, arg_cnt = body[off + 4 : off + 8]
        lens_at = off + 8
        if len(body) < lens_at + arg_cnt:
            return False
        arg_lens = list(body[lens_at : lens_at + arg_cnt])
        parts = _fields(body, lens_at + arg_cnt, [user_len, port_len, rem_len, *arg_lens])
        if parts is None:
            return False
        user, port, rem, raw_args = parts[0], parts[1], parts[2], parts[3:]
        args = _args(raw_args)
        what = TYPE_NAMES[ptype]
        if ptype == ACCT:
            names = [n for bit, n in ACCT_FLAGS if acct_flags & bit]
            if names:
                what += " " + "/".join(names)
        cmd = _command(args)
        summary = cmd if cmd is not None else ", ".join(a for a in args if a.startswith("service="))
        tags = self._tags(ctx)
        if any(w in a.lower() for a in raw_args for w in _SENSITIVE_WORDS):
            tags.append("sensitive-arguments")
        extra: dict[str, object] = {
            "session_id": f"{sid:08x}", "priv_lvl": priv,
            "authen_type": AUTHEN_TYPES.get(atype, str(atype)),
            "service": SERVICES.get(service, str(service)), "args": args[:32],
        }  # fmt: skip
        if cmd is not None:
            extra["command"] = cmd
        if port:
            extra["port"] = text(port[:64])
        if rem:
            extra["rem_addr"] = text(rem[:64])
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.INFO, protocol="TACACS+",
            username=text(user[:256]) if user else None,
            value=f"TACACS+ {what}: {summary}" if summary else f"TACACS+ {what}",
            plugin=self.name, risk="low", tags=tags, extra=extra,
        )  # fmt: skip
        return True

    @staticmethod
    def _author_acct_reply(ptype: int, body: bytes) -> bool:
        """Validate the framing of authorization / accounting replies (nothing is reported)."""
        if ptype == AUTHOR:
            if len(body) < 6:
                return False
            arg_cnt = body[1]
            msg_len, data_len = int.from_bytes(body[2:4], "big"), int.from_bytes(body[4:6], "big")
            if len(body) < 6 + arg_cnt:
                return False
            return _fields(body, 6 + arg_cnt, [msg_len, data_len, *body[6 : 6 + arg_cnt]]) is not None
        if len(body) < 5:
            return False
        msg_len, data_len = int.from_bytes(body[0:2], "big"), int.from_bytes(body[2:4], "big")
        return _fields(body, 5, [msg_len, data_len]) is not None

    # -- helpers -----------------------------------------------------------------------
    def _tags(self, ctx: Context, *more: str) -> list[str]:
        tags = list(more)
        if ctx.flow.server.port != 49:
            tags.append("nonstandard-port")
        return tags

    @staticmethod
    def _extra(sess: _Session, sid: int) -> dict[str, object]:
        extra: dict[str, object] = {
            "session_id": f"{sid:08x}", "action": sess.action, "authen_type": sess.authen_type,
            "service": sess.service, "priv_lvl": sess.priv_lvl,
        }  # fmt: skip
        if sess.port:
            extra["port"] = sess.port
        if sess.rem_addr:
            extra["rem_addr"] = sess.rem_addr
        return extra
