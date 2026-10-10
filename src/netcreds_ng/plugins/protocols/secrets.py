"""Well-known cloud / API credential formats crossing the wire in cleartext.

Scans every cleartext TCP stream (both directions, any port) for credential
formats with distinctive shapes: AWS access keys (optionally paired with a
nearby secret access key), GCP API keys and service-account key files, Azure
storage account keys and SAS tokens, GitHub, Slack and Stripe tokens, and PEM
private-key blocks. A token that crossed the wire in cleartext is the exposure,
so it is reported as seen (in ``secret``). PEM blocks
are reported by header type and length only; the key body is never kept.

JWTs are reported by the HTTP plugin and are not duplicated here.

Scanning uses a sliding window (the last bytes of each direction are carried
into the next segment so tokens split across segments are found), is capped
per direction, skips TLS flows, and resets the window on capture gaps.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

SCAN_LIMIT = 1 << 20  # bytes scanned per direction per flow
WINDOW = 512  # carried bytes: longest token, or AWS key id + 200 bytes + secret, must fit
_AWS_PAIR_DISTANCE = 200
_PEM_MAX = 64 * 1024  # an unterminated PEM block is reported after this many bytes
_MAX_SAS = 400

_AWS_KEY = re.compile(rb"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")
_AWS_SECRET = re.compile(rb"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")
_PEM_BEGIN = re.compile(rb"-----BEGIN ((?:[A-Z0-9]{1,16} ){0,3}PRIVATE KEY(?: BLOCK)?)-----")
_SA_KEY_ID = re.compile(rb'"private_key_id"\s{0,8}:\s{0,8}"([0-9a-f]{40})"')
_SA_EMAIL = re.compile(rb'"client_email"\s{0,8}:\s{0,8}"([A-Za-z0-9._-]{1,128}@[A-Za-z0-9.-]{1,128}\.gserviceaccount\.com)"')
_AZ_ACCOUNT = re.compile(rb"(?<![A-Za-z0-9])AccountName=([a-z0-9]{3,24})(?![A-Za-z0-9])")
_SAS_SIG = re.compile(rb"(?<![A-Za-z0-9_])sig=([A-Za-z0-9%+/=]{40,128})(?![A-Za-z0-9%+/=])")
_SAS_EDGE = re.compile(rb"[\s\"'<>?#,;]")

# Simple single-regex detectors: name -> (provider, regex). Group 0 is the token.
_SIMPLE: dict[str, tuple[str, re.Pattern[bytes]]] = {
    "gcp_api_key": ("gcp", re.compile(rb"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])")),
    "azure_storage_key": ("azure", re.compile(rb"(?<![A-Za-z0-9])AccountKey=([A-Za-z0-9+/]{86}==)(?![A-Za-z0-9+/=])")),
    "github_token": ("github", re.compile(rb"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])")),
    "github_pat": ("github", re.compile(rb"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9_])")),
    "slack_token": ("slack", re.compile(rb"(?<![A-Za-z0-9_-])xox[baprs]-[0-9]{6,20}-[0-9A-Za-z-]{8,200}(?![0-9A-Za-z-])")),
    "stripe_secret_key": ("stripe", re.compile(rb"(?<![A-Za-z0-9_])(?:sk|rk)_live_[0-9A-Za-z]{24,99}(?![0-9A-Za-z])")),
}  # fmt: skip


# Literal text every detector's match contains; buffers without any are skipped. Keep in sync
# with the detectors above (tests/test_proto_secrets.py exercises each one).
_ANCHORS = re.compile(
    rb"AKIA|ASIA|AIza|AccountKey=|AccountName=|gh[pousr]_|github_pat_|xox[baprs]-|_live_|sig=|-----BEGIN|-----END"
    rb"|private_key_id|client_email"
)


# Values published in vendor documentation; reported at info risk, tagged documentation-example.
_DOC_EXAMPLES = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


def _looks_tls(head: bytes) -> bool:
    return len(head) >= 2 and head[0] == 0x16 and head[1] == 0x03


@dataclass
class _Dir:
    window: bytearray = field(default_factory=bytearray)
    scanned: int = 0  # absolute stream offset of the end of the window
    origin: int = 0  # first stream offset whose preceding byte is known (moves past gaps)
    started: bool = False
    pem_type: str | None = None  # PEM block open since pem_start (absolute stream offset)
    pem_start: int = 0
    pem_end_marker: bytes = b""
    pem_pos: int = 0  # absolute offset up to which PEM markers have been consumed
    sa_key_id: str | None = None
    sa_email: str | None = None
    sa_reported: bool = False


@dataclass
class _State:
    dirs: tuple[_Dir, _Dir] = field(default_factory=lambda: (_Dir(), _Dir()))
    seen: set[tuple[str, str]] = field(default_factory=set)


class SecretsPlugin(ProtocolPlugin):
    name = "secrets"
    wants_encrypted = False
    sets = ("generic",)
    description = "Cloud/API credential formats (AWS, GCP, Azure, GitHub, Slack, Stripe, PEM keys) in cleartext streams"
    priority = 210  # after http (50) and keyvalue (200)

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        d: _Dir = ctx.state.dirs[direction]
        if d.window:  # a match deferred at the end of the window is complete now (review L7)
            self._scan(ctx, direction, d, bytes(d.window), d.scanned - len(d.window), final=True)
        if d.pem_type is not None:
            self._pem(ctx, direction, d, None)
        d.window.clear()
        d.scanned += size
        d.origin = d.scanned + 1  # the first byte after the hole only serves as look-behind context
        d.pem_pos = d.scanned

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        d = st.dirs[direction]
        if not d.started:
            d.started = True
            if _looks_tls(data):
                ctx.detach()
                return
        budget = SCAN_LIMIT - d.scanned
        if budget <= 0:
            if all(x.scanned >= SCAN_LIMIT for x in st.dirs):
                ctx.detach()
            return
        data = data[:budget]
        base = d.scanned - len(d.window)  # absolute stream offset of buf[0]
        d.scanned += len(data)
        buf = bytes(d.window) + data
        self._scan(ctx, direction, d, buf, base, final=False)
        keep = min(len(buf), WINDOW)
        d.window = bytearray(buf[len(buf) - keep :])

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        for direction in Direction:
            d = st.dirs[direction]
            if d.window:
                self._scan(ctx, direction, d, bytes(d.window), d.scanned - len(d.window), final=True)
            if d.pem_type is not None:
                self._pem(ctx, direction, d, None)

    # -- scanning -----------------------------------------------------------

    def _scan(self, ctx: Context, direction: Direction, d: _Dir, buf: bytes, base: int, final: bool) -> None:
        # Positions before ``start`` were already scanned (carried window) or have
        # unknown preceding bytes (start of stream after a gap).
        start = min(len(buf), max(0, d.origin - base, 1 if base > d.origin else 0))
        end = len(buf)
        if d.pem_type is None and d.sa_key_id is None and d.sa_email is None and not _ANCHORS.search(buf, start):
            return  # no detector can match: one pass instead of one per detector (bulk traffic)

        def complete(m: re.Match[bytes]) -> bool:
            # A match touching the buffer end may still grow (or be followed by a
            # token character) in the next segment: defer it unless closing.
            return final or m.end() < end

        for detector, (provider, rx) in _SIMPLE.items():
            for m in rx.finditer(buf, start):
                if complete(m):
                    self._simple(ctx, direction, buf, m, detector, provider)
        for m in _AWS_KEY.finditer(buf, start):
            if complete(m):
                self._aws(ctx, direction, buf, m, final)
        for m in _SAS_SIG.finditer(buf, start):
            if complete(m):
                self._sas(ctx, direction, buf, m, final)
        self._service_account(ctx, direction, d, buf, start)
        self._pem_scan(ctx, direction, d, buf, base, start, complete)

    def _report(self, ctx: Context, direction: Direction, detector: str, provider: str, key: str,
                extra: dict[str, object] | None = None, risk: str = "high", tags: tuple[str, ...] = (),
                **fields: Any) -> None:  # fmt: skip
        st: _State = ctx.state
        if (detector, key) in st.seen:
            return
        st.seen.add((detector, key))
        extra = {"detector": detector, **(extra or {})}
        all_tags = [provider, *tags]
        if any(ex in key for ex in _DOC_EXAMPLES):
            # Published documentation sample (e.g. AWS's AKIAIOSFODNN7EXAMPLE): not a live credential.
            risk, all_tags = "info", [*all_tags, "documentation-example"]
        ctx.emit(direction, Kind.API_KEY, protocol="Cleartext", plugin=self.name, risk=risk,
                 tags=all_tags, extra=extra, **fields)  # fmt: skip

    def _simple(self, ctx: Context, direction: Direction, buf: bytes, m: re.Match[bytes], detector: str,
                provider: str) -> None:  # fmt: skip
        if detector == "azure_storage_key":
            token = text(m.group(1))
            account = None
            for a in _AZ_ACCOUNT.finditer(buf, max(0, m.start() - 128), m.start()):
                account = text(a.group(1))
            self._report(ctx, direction, detector, provider, token, secret=token, username=account,
                         extra={"account": account} if account else {})  # fmt: skip
            return
        token = text(m.group())
        self._report(ctx, direction, detector, provider, token, secret=token)

    def _aws(self, ctx: Context, direction: Direction, buf: bytes, m: re.Match[bytes], final: bool) -> None:
        key_id = text(m.group())
        lo, hi = max(0, m.start() - _AWS_PAIR_DISTANCE), m.end() + _AWS_PAIR_DISTANCE
        secret = None
        for s in _AWS_SECRET.finditer(buf, lo, min(hi, len(buf))):
            if s.end() >= len(buf) and not final:
                continue  # may still be growing
            cand = s.group()
            # A real secret mixes character classes; this rejects hex digests and plain words.
            if any(c.isupper() for c in cand.decode()) and any(c.islower() for c in cand.decode()):
                secret = text(cand)
                break
        if secret is None and hi > len(buf) and not final:
            return  # the secret may follow in the next segment (window keeps the key id)
        if secret is not None:
            self._report(ctx, direction, "aws_access_key", "aws", key_id, username=key_id, secret=secret,
                         extra={"paired_secret": True})  # fmt: skip
        else:
            # A key id alone identifies a key but does not grant access by itself.
            self._report(ctx, direction, "aws_access_key", "aws", key_id, secret=key_id, risk="medium",
                         tags=("key-id-only",))  # fmt: skip

    def _sas(self, ctx: Context, direction: Direction, buf: bytes, m: re.Match[bytes], final: bool) -> None:
        lo = m.start()
        while lo > 0 and lo > m.start() - _MAX_SAS and not _SAS_EDGE.match(buf, lo - 1):
            lo -= 1
        hi = m.end()
        while hi < len(buf) and hi < m.end() + _MAX_SAS and not _SAS_EDGE.match(buf, hi):
            hi += 1
        if hi >= len(buf) and not final:
            return  # the query string may continue in the next segment
        query = buf[lo:hi]
        params = {p.split(b"=", 1)[0] for p in query.split(b"&")}
        if b"sv" not in params or b"se" not in params:
            return
        token = text(query)
        self._report(ctx, direction, "azure_sas_token", "azure", token, secret=token)

    def _service_account(self, ctx: Context, direction: Direction, d: _Dir, buf: bytes, start: int) -> None:
        if d.sa_reported:
            return
        if d.sa_key_id is None:
            k = _SA_KEY_ID.search(buf, start)
            if k:
                d.sa_key_id = text(k.group(1))
        if d.sa_email is None:
            e = _SA_EMAIL.search(buf, start)
            if e:
                d.sa_email = text(e.group(1))
        if d.sa_key_id and d.sa_email:
            d.sa_reported = True
            self._report(ctx, direction, "gcp_service_account", "gcp", d.sa_email, username=d.sa_email,
                         value=f"GCP service account key file for {d.sa_email}",
                         extra={"private_key_id": d.sa_key_id})  # fmt: skip

    def _pem_scan(self, ctx: Context, direction: Direction, d: _Dir, buf: bytes, base: int, start: int,
                  complete: Callable[[re.Match[bytes]], bool]) -> None:  # fmt: skip
        pos = max(start, d.pem_pos - base)
        while pos <= len(buf):
            if d.pem_type is None:
                m = _PEM_BEGIN.search(buf, pos)
                if m is None or not complete(m):
                    return
                d.pem_type = text(m.group(1))
                d.pem_start = base + m.start()
                d.pem_end_marker = b"-----END " + m.group(1) + b"-----"
                pos = m.end()
                d.pem_pos = base + pos
            # search only from where this block can end (begin marker excluded)
            rel = max(pos, d.pem_start - base)
            idx = buf.find(d.pem_end_marker, rel)
            if idx < 0:
                if base + len(buf) - d.pem_start > _PEM_MAX:
                    self._pem(ctx, direction, d, None)
                return
            end_abs = base + idx + len(d.pem_end_marker)
            self._pem(ctx, direction, d, end_abs - d.pem_start)
            pos = idx + len(d.pem_end_marker)
            d.pem_pos = end_abs

    def _pem(self, ctx: Context, direction: Direction, d: _Dir, length: int | None) -> None:
        pem_type = d.pem_type or "PRIVATE KEY"
        d.pem_type = None
        if length is None:
            value = f"PEM {pem_type} block (incomplete)"
        else:
            value = f"PEM {pem_type} block ({length} bytes)"
        extra: dict[str, object] = {"pem_type": pem_type, "length": length, "complete": length is not None}
        self._report(ctx, direction, "pem_private_key", "pem", f"{pem_type}@{d.pem_start}", value=value, extra=extra)
