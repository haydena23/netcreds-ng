"""TLS decryption with an NSS key-log file (``SSLKEYLOGFILE``), for traffic you are authorised to inspect.

The engine hands each TCP direction's reassembled bytes to a :class:`TLSSession`, which
parses records, reads the handshake (client/server random, version, cipher suite,
encrypt-then-MAC), looks the session up in the key log, and returns decrypted
application data, which then goes to the protocol plugins like any cleartext stream.

Supported: TLS 1.2 with AES-GCM, ChaCha20-Poly1305 and AES-CBC (HMAC-SHA1/256/384,
including encrypt-then-MAC), and TLS 1.3 with AES-128/256-GCM and ChaCha20-Poly1305,
including KeyUpdate. Not supported: TLS 1.0/1.1, 0-RTT early data, RSA key exchange
without a key log, compression. Records that fail authentication are never passed on.

Needs the optional ``cryptography`` package (``pip install netcreds-ng[tls]``).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# record content types
CCS, ALERT, HANDSHAKE, APPDATA = 20, 21, 22, 23
TLS12, TLS13 = 0x0303, 0x0304
MAX_RECORD = (1 << 14) + 2048
_HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()


def crypto_available() -> bool:
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
    except ImportError:
        return False
    return True


# --- key log -----------------------------------------------------------------------------------


class KeyLog:
    """NSS key-log file. Re-read when it changes, so a browser can keep appending during live capture."""

    LABELS = ("CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
              "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")  # fmt: skip

    def __init__(self, path: str | None = None, text: str | None = None) -> None:
        self.path = path
        self.secrets: dict[bytes, dict[str, bytes]] = {}
        self._stamp: tuple[float, int] | None = None
        self.bad_lines = 0
        if text is not None:
            self._parse(text)
        elif path is not None:
            self.reload()

    def _parse(self, text: str) -> None:
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) != 3 or parts[0].startswith("#"):
                continue
            label, random_hex, secret_hex = parts
            if label not in self.LABELS:
                continue
            try:
                self.secrets.setdefault(bytes.fromhex(random_hex), {})[label] = bytes.fromhex(secret_hex)
            except ValueError:
                self.bad_lines += 1

    def reload(self) -> bool:
        """Re-read the file if it changed; True if it was (re)loaded."""
        if self.path is None:
            return False
        try:
            st = os.stat(self.path)
        except OSError:
            return False
        stamp = (st.st_mtime, st.st_size)
        if stamp == self._stamp:
            return False
        self._stamp = stamp
        with open(self.path, encoding="ascii", errors="replace") as fh:
            self._parse(fh.read())
        return True

    def lookup(self, client_random: bytes) -> dict[str, bytes] | None:
        found = self.secrets.get(client_random)
        if found is None and self.reload():
            found = self.secrets.get(client_random)
        return found

    def __len__(self) -> int:
        return len(self.secrets)


# --- key schedule ------------------------------------------------------------------------------


def _hmac(hash_name: str, key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hash_name).digest()


def prf12(hash_name: str, secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.2 PRF (RFC 5246 section 5): P_hash(secret, label + seed)."""
    seed = label + seed
    out = b""
    a = seed
    while len(out) < length:
        a = _hmac(hash_name, secret, a)
        out += _hmac(hash_name, secret, a + seed)
    return out[:length]


def hkdf_expand_label(hash_name: str, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1)."""
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = _hmac(hash_name, secret, block + info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


@dataclass(frozen=True)
class Suite:
    name: str
    mode: str  # gcm / chacha / cbc
    key_len: int
    prf_hash: str = "sha256"
    mac_hash: str | None = None  # CBC only

    @property
    def mac_len(self) -> int:
        return hashlib.new(self.mac_hash).digest_size if self.mac_hash else 0

    @property
    def fixed_iv_len(self) -> int:
        return {"gcm": 4, "chacha": 12, "cbc": 0}[self.mode]


def _suites() -> dict[int, Suite]:
    s: dict[int, Suite] = {}
    for code, name in ((0x009C, "RSA_AES_128_GCM_SHA256"), (0x009E, "DHE_RSA_AES_128_GCM_SHA256"),
                       (0xC02B, "ECDHE_ECDSA_AES_128_GCM_SHA256"), (0xC02F, "ECDHE_RSA_AES_128_GCM_SHA256")):
        s[code] = Suite(name, "gcm", 16)
    for code, name in ((0x009D, "RSA_AES_256_GCM_SHA384"), (0x009F, "DHE_RSA_AES_256_GCM_SHA384"),
                       (0xC02C, "ECDHE_ECDSA_AES_256_GCM_SHA384"), (0xC030, "ECDHE_RSA_AES_256_GCM_SHA384")):
        s[code] = Suite(name, "gcm", 32, "sha384")
    for code, name in ((0xCCA8, "ECDHE_RSA_CHACHA20_POLY1305"), (0xCCA9, "ECDHE_ECDSA_CHACHA20_POLY1305"),
                       (0xCCAA, "DHE_RSA_CHACHA20_POLY1305")):
        s[code] = Suite(name, "chacha", 32)
    for code, name, key, mac in (
        (0x002F, "RSA_AES_128_CBC_SHA", 16, "sha1"), (0x0035, "RSA_AES_256_CBC_SHA", 32, "sha1"),
        (0x0033, "DHE_RSA_AES_128_CBC_SHA", 16, "sha1"), (0x0039, "DHE_RSA_AES_256_CBC_SHA", 32, "sha1"),
        (0xC009, "ECDHE_ECDSA_AES_128_CBC_SHA", 16, "sha1"), (0xC00A, "ECDHE_ECDSA_AES_256_CBC_SHA", 32, "sha1"),
        (0xC013, "ECDHE_RSA_AES_128_CBC_SHA", 16, "sha1"), (0xC014, "ECDHE_RSA_AES_256_CBC_SHA", 32, "sha1"),
        (0x003C, "RSA_AES_128_CBC_SHA256", 16, "sha256"), (0x003D, "RSA_AES_256_CBC_SHA256", 32, "sha256"),
        (0x0067, "DHE_RSA_AES_128_CBC_SHA256", 16, "sha256"), (0x006B, "DHE_RSA_AES_256_CBC_SHA256", 32, "sha256"),
        (0xC023, "ECDHE_ECDSA_AES_128_CBC_SHA256", 16, "sha256"), (0xC027, "ECDHE_RSA_AES_128_CBC_SHA256", 16, "sha256"),
    ):  # fmt: skip
        s[code] = Suite(name, "cbc", key, "sha256", mac)
    for code, name in ((0xC024, "ECDHE_ECDSA_AES_256_CBC_SHA384"), (0xC028, "ECDHE_RSA_AES_256_CBC_SHA384")):
        s[code] = Suite(name, "cbc", 32, "sha384", "sha384")
    return s


SUITES12 = _suites()
SUITES13 = {
    0x1301: Suite("AES_128_GCM_SHA256", "gcm", 16),
    0x1302: Suite("AES_256_GCM_SHA384", "gcm", 32, "sha384"),
    0x1303: Suite("CHACHA20_POLY1305_SHA256", "chacha", 32),
}


# --- record protection -------------------------------------------------------------------------


class DecryptError(Exception):
    pass


@dataclass
class _Keys:
    suite: Suite
    key: bytes
    iv: bytes
    mac_key: bytes = b""
    secret: bytes = b""  # TLS 1.3 traffic secret (for KeyUpdate)
    seq: int = 0
    aead: Any = None

    def __post_init__(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        if self.suite.mode == "gcm":
            self.aead = AESGCM(self.key)
        elif self.suite.mode == "chacha":
            self.aead = ChaCha20Poly1305(self.key)


def _xor_nonce(iv: bytes, seq: int) -> bytes:
    padded = seq.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, padded, strict=True))


def decrypt12(k: _Keys, rtype: int, version: int, body: bytes, etm: bool) -> bytes:
    from cryptography.exceptions import InvalidTag

    seq = struct.pack("!Q", k.seq)
    try:
        if k.suite.mode == "gcm":
            if len(body) < 8 + 16:
                raise DecryptError("short GCM record")
            nonce, ct = k.iv + body[:8], body[8:]
            aad = seq + struct.pack("!BHH", rtype, version, len(ct) - 16)
            out = bytes(k.aead.decrypt(nonce, ct, aad))
        elif k.suite.mode == "chacha":
            if len(body) < 16:
                raise DecryptError("short ChaCha record")
            aad = seq + struct.pack("!BHH", rtype, version, len(body) - 16)
            out = bytes(k.aead.decrypt(_xor_nonce(k.iv, k.seq), body, aad))
        else:
            out = _cbc12(k, rtype, version, body, etm, seq)
    except InvalidTag:
        raise DecryptError("authentication failed") from None
    k.seq += 1
    return out


def _cbc12(k: _Keys, rtype: int, version: int, body: bytes, etm: bool, seq: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    mac_len = k.suite.mac_len
    if etm:
        if len(body) < 16 + 16 + mac_len:
            raise DecryptError("short CBC record")
        enc, mac = body[:-mac_len], body[-mac_len:]
        expect = _hmac(k.suite.mac_hash or "sha1", k.mac_key, seq + struct.pack("!BHH", rtype, version, len(enc)) + enc)
        if not hmac.compare_digest(mac, expect):
            raise DecryptError("MAC check failed")
        body = enc
    if len(body) < 32 or len(body) % 16:
        raise DecryptError("bad CBC length")
    dec = Cipher(algorithms.AES(k.key), modes.CBC(body[:16])).decryptor()
    plain = dec.update(body[16:]) + dec.finalize()
    pad = plain[-1]
    if pad + 1 > len(plain) or plain[-pad - 1 :] != bytes([pad]) * (pad + 1):
        raise DecryptError("bad CBC padding")
    plain = plain[: -pad - 1]
    if etm:
        return plain
    if len(plain) < mac_len:
        raise DecryptError("short CBC plaintext")
    content, mac = plain[: len(plain) - mac_len], plain[len(plain) - mac_len :]
    expect = _hmac(k.suite.mac_hash or "sha1", k.mac_key, seq + struct.pack("!BHH", rtype, version, len(content)) + content)
    if not hmac.compare_digest(mac, expect):
        raise DecryptError("MAC check failed")
    return content


def decrypt13(k: _Keys, header: bytes, body: bytes) -> tuple[int, bytes]:
    from cryptography.exceptions import InvalidTag

    try:
        plain = bytes(k.aead.decrypt(_xor_nonce(k.iv, k.seq), body, header))
    except InvalidTag:
        raise DecryptError("authentication failed") from None
    k.seq += 1
    end = len(plain)
    while end and plain[end - 1] == 0:
        end -= 1
    if not end:
        raise DecryptError("no inner content type")
    return plain[end - 1], plain[: end - 1]


def keys13(suite: Suite, secret: bytes) -> _Keys:
    return _Keys(suite, hkdf_expand_label(suite.prf_hash, secret, b"key", b"", suite.key_len),
                 hkdf_expand_label(suite.prf_hash, secret, b"iv", b"", 12), secret=secret)  # fmt: skip


def keys12(suite: Suite, master: bytes, client_random: bytes, server_random: bytes) -> tuple[_Keys, _Keys]:
    mac, key, iv = suite.mac_len, suite.key_len, suite.fixed_iv_len
    block = prf12(suite.prf_hash, master, b"key expansion", server_random + client_random, 2 * (mac + key + iv))
    parts, pos = [], 0
    for n in (mac, mac, key, key, iv, iv):
        parts.append(block[pos : pos + n])
        pos += n
    cmac, smac, ckey, skey, civ, siv = parts
    return _Keys(suite, ckey, civ, cmac), _Keys(suite, skey, siv, smac)


# --- session ------------------------------------------------------------------------------------


@dataclass
class _Side:
    buf: bytearray = field(default_factory=bytearray)
    hs: bytearray = field(default_factory=bytearray)  # plaintext handshake bytes
    keys: list[_Keys] = field(default_factory=list)  # candidates, current first
    encrypted: bool = False
    broken: bool = False
    opened: bool = False  # a protected record has been decrypted in this direction
    hs13: bytearray = field(default_factory=bytearray)  # decrypted TLS 1.3 handshake bytes (one key epoch)
    resync: bool = False  # after a gap in the plaintext handshake: look for the next record header (E-12)
    hs_lost: bool = False  # plaintext handshake bytes were lost: stop parsing them on this side
    hs12: bytearray = field(default_factory=bytearray)  # decrypted TLS 1.2 handshake bytes (renegotiation)
    pending: _Keys | None = None  # TLS 1.2 keys from a renegotiation, used from this side's next CCS
    renegotiating: bool = False  # a renegotiation handshake started: a CCS switches keys


class TLSSession:
    """Decrypts one TCP connection. ``feed`` returns the plaintext application data, in order."""

    def __init__(self, keylog: KeyLog) -> None:
        self.keylog = keylog
        self.sides = (_Side(), _Side())  # index by Direction (0 client->server, 1 server->client)
        self.client_random: bytes | None = None
        self.server_random: bytes | None = None
        self.version: int | None = None
        self.suite: Suite | None = None
        self.suite_id: int | None = None
        self.etm = False
        self.alpn: str | None = None
        self.sni: str | None = None
        self.status = "handshake"  # handshake / decrypting / no-key / unsupported / failed
        self.reason = ""
        self.records = 0
        self.decrypted = 0
        self._reneg_client_random: bytes | None = None  # TLS 1.2 renegotiation in progress

    # public ------------------------------------------------------------------------------

    def feed(self, direction: int, data: bytes) -> list[bytes]:
        side = self.sides[direction]
        if side.broken or self.status in ("unsupported", "failed"):
            return []
        side.buf += data
        out: list[bytes] = []
        if side.resync:
            start = _record_start(side.buf)
            if start is None:
                del side.buf[: max(0, len(side.buf) - 4)]  # a header may begin in the last bytes
                return out
            if start < 0:
                return out  # a candidate record is not complete yet
            del side.buf[:start]
            side.resync = False
        if direction == 0 and self.client_random is None and not side.hs and len(side.buf) >= 43 \
                and side.buf[0] == HANDSHAKE and side.buf[5] == 1:  # fmt: skip
            # Record header (5), handshake header (4), version (2), then the random: keep it as soon
            # as it arrives, so a gap in the rest of the ClientHello does not lose the session (E-12).
            self.client_random = bytes(side.buf[11:43])
        while len(side.buf) >= 5:
            rtype, version, length = struct.unpack("!BHH", side.buf[:5])
            if rtype not in (CCS, ALERT, HANDSHAKE, APPDATA) or version >> 8 != 3 or length > MAX_RECORD:
                self._fail(side, "not a TLS record stream")
                return out
            if len(side.buf) < 5 + length:
                break
            header, body = bytes(side.buf[:5]), bytes(side.buf[5 : 5 + length])
            del side.buf[: 5 + length]
            self.records += 1
            try:
                self._record(direction, side, rtype, version, header, body, out)
            except DecryptError as exc:
                self._fail(side, str(exc))
                return out
        return out

    def gap(self, direction: int) -> bool:
        """Bytes were lost in ``direction``; returns whether decrypted data may be missing.

        Once records are protected the sequence number is unknown, so the direction cannot
        continue. Before that (E-12), lost plaintext handshake bytes do not matter as long as
        what decryption needs was seen: the client random (client side) or the ServerHello
        (server side). The direction then resumes at the next record boundary, and no
        application data was lost.
        """
        side = self.sides[direction]
        if side.broken:
            return True
        needed = self.client_random if direction == 0 else self.server_random
        if not side.encrypted and needed is not None:
            side.buf.clear()
            side.hs.clear()
            side.resync = side.hs_lost = True
            return False
        self._fail(side, "capture gap")
        return True

    # internals ---------------------------------------------------------------------------

    def _fail(self, side: _Side, reason: str) -> None:
        side.broken = True
        side.buf.clear()
        if self.status in ("handshake", "decrypting") and all(s.broken for s in self.sides):
            self.status = "failed"
        self.reason = self.reason or reason

    def _record(self, d: int, side: _Side, rtype: int, version: int, header: bytes, body: bytes,
                out: list[bytes]) -> None:  # fmt: skip
        if rtype == CCS:
            if self.version == TLS12:
                if side.encrypted and side.renegotiating:
                    # E-12: a renegotiation finished; this side now uses the new keys (or, without a
                    # key for the new handshake, stops decrypting instead of failing).
                    side.keys = [side.pending] if side.pending is not None else []
                    side.pending, side.renegotiating = None, False
                    side.hs12.clear()
                # Everything after a TLS 1.2 ChangeCipherSpec is protected. Without keys it is skipped,
                # rather than misread as plaintext handshake (review L4).
                side.encrypted = True
            return
        if not side.encrypted:
            if side.hs_lost and side.keys and (rtype == APPDATA or (rtype == HANDSHAKE and not _plain_handshake(body))):
                # After a handshake gap, a protected record before any ChangeCipherSpec means the
                # gap swallowed the CCS: the direction cannot be followed (review M32 MED-2).
                raise DecryptError("capture gap before ChangeCipherSpec")
            if rtype == HANDSHAKE and not side.hs_lost:
                side.hs += body
                self._handshake(d, side)
            return  # plaintext alerts are not interesting
        if not side.keys:
            return
        if self.version == TLS13:
            if rtype != APPDATA:
                return
            inner, plain = self._try13(side, header, body)
            if inner == APPDATA:
                self.decrypted += 1
                out.append(plain)
            elif inner == HANDSHAKE:
                self._post_handshake13(side, plain)
        else:
            plain = decrypt12(side.keys[0], rtype, version, body, self.etm)
            if rtype == APPDATA:
                self.decrypted += 1
                out.append(plain)
            elif rtype == HANDSHAKE:
                self._handshake12(d, side, plain)

    def _try13(self, side: _Side, header: bytes, body: bytes) -> tuple[int, bytes]:
        """Try the current key, then the later ones (handshake -> application traffic secret).

        Before anything has decrypted in this direction, a record no key opens is skipped:
        it is a handshake record whose secret the key log does not contain.
        """
        for i, keys in enumerate(side.keys):
            try:
                result = decrypt13(keys, header, body)
            except DecryptError:
                continue
            if i:
                side.hs13.clear()  # a handshake message never spans a key change
            del side.keys[:i]
            side.opened = True
            return result
        if not side.opened:
            return HANDSHAKE, b""
        raise DecryptError("authentication failed")

    def _post_handshake13(self, side: _Side, plain: bytes) -> None:
        """Parse complete handshake messages only: one may span several records (review L2)."""
        side.hs13 += plain
        if len(side.hs13) > 1 << 20:
            side.hs13.clear()  # absurd handshake message: drop rather than buffer without bound
            return
        while len(side.hs13) >= 4:
            mtype, mlen = side.hs13[0], int.from_bytes(side.hs13[1:4], "big")
            if len(side.hs13) < 4 + mlen:
                return
            del side.hs13[: 4 + mlen]
            if mtype == 24 and self.suite is not None and len(side.keys) == 1:
                # KeyUpdate (only on application traffic): next generation of this direction's secret
                nxt = hkdf_expand_label(self.suite.prf_hash, side.keys[0].secret, b"traffic upd", b"",
                                        hashlib.new(self.suite.prf_hash).digest_size)  # fmt: skip
                side.keys[0] = keys13(self.suite, nxt)

    def _handshake12(self, d: int, side: _Side, plain: bytes) -> None:
        """Encrypted TLS 1.2 handshake messages: Finished, and the hellos of a renegotiation (E-12)."""
        side.hs12 += plain
        if len(side.hs12) > 1 << 20:
            side.hs12.clear()
            return
        while len(side.hs12) >= 4:
            mtype, mlen = side.hs12[0], int.from_bytes(side.hs12[1:4], "big")
            if len(side.hs12) < 4 + mlen:
                return
            msg = bytes(side.hs12[4 : 4 + mlen])
            del side.hs12[: 4 + mlen]
            if mtype == 1 and d == 0 and len(msg) >= 34:
                self._reneg_client_random = msg[2:34]
                for s in self.sides:
                    s.renegotiating, s.pending = True, None
            elif mtype == 2 and d == 1 and self._reneg_client_random is not None:
                self._renegotiated_server_hello(msg)

    def _renegotiated_server_hello(self, msg: bytes) -> None:
        if len(msg) < 38 or struct.unpack("!H", msg[0:2])[0] != TLS12:
            return
        server_random, pos = msg[2:34], 35 + msg[34]
        if pos + 3 > len(msg):
            return
        suite = SUITES12.get(struct.unpack("!H", msg[pos : pos + 2])[0])
        client_random, self._reneg_client_random = self._reneg_client_random, None
        secrets = self.keylog.lookup(client_random or b"")
        master = secrets.get("CLIENT_RANDOM") if secrets else None
        if suite is None or master is None or client_random is None:
            return  # no key for the new handshake: each side stops decrypting at its CCS
        etm = 0x0016 in _extensions(msg, pos + 3, client=False)
        if etm != self.etm and suite.mode == "cbc":
            return  # a changed MAC order is not followed; stop at the CCS rather than misread
        ck, sk = keys12(suite, master, client_random, server_random)
        self.sides[0].pending, self.sides[1].pending = ck, sk
        self.suite, self.suite_id = suite, struct.unpack("!H", msg[pos : pos + 2])[0]

    def _handshake(self, d: int, side: _Side) -> None:
        while len(side.hs) >= 4:
            mtype, mlen = side.hs[0], int.from_bytes(side.hs[1:4], "big")
            if len(side.hs) < 4 + mlen:
                return
            msg = bytes(side.hs[4 : 4 + mlen])
            del side.hs[: 4 + mlen]
            if mtype == 1 and d == 0:
                self._client_hello(msg)
            elif mtype == 2 and d == 1:
                self._server_hello(msg)

    def _client_hello(self, msg: bytes) -> None:
        if len(msg) < 38:
            raise DecryptError("short ClientHello")
        self.client_random = msg[2:34]
        exts = _extensions(msg, 34, client=True)
        sni = exts.get(0x0000)
        if sni and len(sni) > 5:
            self.sni = sni[5:].decode("ascii", "replace")
        alpn = exts.get(0x0010)
        if alpn and len(alpn) > 3:
            self.alpn = alpn[3 : 3 + alpn[2]].decode("ascii", "replace")

    def _server_hello(self, msg: bytes) -> None:
        if len(msg) < 38:
            raise DecryptError("short ServerHello")
        random = msg[2:34]
        if random == _HRR_RANDOM:
            return  # HelloRetryRequest: a second ServerHello follows
        self.server_random = random
        sid_len = msg[34]
        pos = 35 + sid_len
        if pos + 3 > len(msg):
            raise DecryptError("short ServerHello")
        (self.suite_id,) = struct.unpack("!H", msg[pos : pos + 2])
        exts = _extensions(msg, pos + 3, client=False)
        version = struct.unpack("!H", msg[0:2])[0]
        sv = exts.get(0x002B)
        if sv is not None and len(sv) == 2:
            version = struct.unpack("!H", sv)[0]
        self.version = version
        self.etm = 0x0016 in exts
        alpn = exts.get(0x0010)
        if alpn and len(alpn) > 3:
            self.alpn = alpn[3 : 3 + alpn[2]].decode("ascii", "replace")
        self._derive()

    def _derive(self) -> None:
        if self.version not in (TLS12, TLS13):
            self.status, self.reason = "unsupported", f"TLS version 0x{self.version or 0:04x}"
            return
        table = SUITES13 if self.version == TLS13 else SUITES12
        suite = table.get(self.suite_id or -1)
        if suite is None:
            self.status, self.reason = "unsupported", f"cipher suite 0x{self.suite_id or 0:04x}"
            return
        self.suite = suite
        secrets = self.keylog.lookup(self.client_random or b"")
        if not secrets:
            self.status, self.reason = "no-key", "client random not in key log"
            return
        client, server = self.sides
        if self.version == TLS13:
            for side, prefix in ((client, "CLIENT"), (server, "SERVER")):
                for label in (f"{prefix}_HANDSHAKE_TRAFFIC_SECRET", f"{prefix}_TRAFFIC_SECRET_0"):
                    if label in secrets:
                        side.keys.append(keys13(suite, secrets[label]))
                side.encrypted = True  # every later TLS 1.3 record (except CCS) is protected
            if not client.keys and not server.keys:
                self.status, self.reason = "no-key", "no TLS 1.3 secrets for this session"
                return
        else:
            master = secrets.get("CLIENT_RANDOM")
            if master is None:
                self.status, self.reason = "no-key", "no TLS 1.2 master secret for this session"
                return
            ck, sk = keys12(suite, master, self.client_random or b"", self.server_random or b"")
            client.keys, server.keys = [ck], [sk]
        self.status = "decrypting"


#: Handshake message types sent in plaintext before ChangeCipherSpec (TLS 1.2).
_PLAIN_HS_TYPES = frozenset({1, 2, 11, 12, 13, 14, 15, 16, 22})


def _plain_handshake(body: bytes) -> bool:
    """Whether a record body starts with a plaintext handshake message (type and a fitting length)."""
    return len(body) >= 4 and body[0] in _PLAIN_HS_TYPES and int.from_bytes(body[1:4], "big") <= 1 << 16


def _plausible_header(buf: bytes | bytearray, pos: int) -> int | None:
    """Length of the record whose header starts at ``pos``, if it looks like one."""
    rtype, major, minor = buf[pos], buf[pos + 1], buf[pos + 2]
    length = int.from_bytes(buf[pos + 3 : pos + 5], "big")
    if rtype in (CCS, ALERT, HANDSHAKE, APPDATA) and major == 3 and minor <= 4 and 0 < length <= MAX_RECORD:
        return length
    return None


def _record_start(buf: bytes | bytearray) -> int | None:
    """After a gap: the offset of the first record header from which complete records chain.

    Returns None if there is none, or ``-1`` while the first candidate's record is incomplete.
    A false candidate inside lost data can only misframe records, which then fail the record
    checks or authentication: decryption never produces wrong plaintext from it.
    """
    for i in range(len(buf) - 4):
        pos, records = i, 0
        while pos + 5 <= len(buf) and (length := _plausible_header(buf, pos)) is not None:
            pos += 5 + length
            records += 1
        if pos + 5 <= len(buf):
            continue  # the chain reaches an implausible header: not a record boundary
        if pos > len(buf) and records == 1:
            return -1  # the candidate record is not complete yet
        return i
    return None


def _extensions(msg: bytes, pos: int, client: bool) -> dict[int, bytes]:
    """Extensions of a ClientHello (``pos`` at session_id) or ServerHello (``pos`` at extensions length)."""
    if client:
        if pos >= len(msg):
            return {}
        pos += 1 + msg[pos]  # session id
        if pos + 2 > len(msg):
            return {}
        pos += 2 + int.from_bytes(msg[pos : pos + 2], "big")  # cipher suites
        if pos >= len(msg):
            return {}
        pos += 1 + msg[pos]  # compression methods
    if pos + 2 > len(msg):
        return {}
    end = min(len(msg), pos + 2 + int.from_bytes(msg[pos : pos + 2], "big"))
    pos += 2
    out: dict[int, bytes] = {}
    while pos + 4 <= end:
        etype, elen = struct.unpack("!HH", msg[pos : pos + 4])
        out[etype] = msg[pos + 4 : pos + 4 + elen]
        pos += 4 + elen
    return out


def could_start_client_hello(data: bytes) -> bool:
    """True if ``data`` (fewer than 6 bytes) is a prefix of a ClientHello record."""
    pattern = (lambda b: b == HANDSHAKE, lambda b: b == 3, lambda b: b <= 4, lambda b: True, lambda b: True)
    return all(check(b) for check, b in zip(pattern, data, strict=False))


def looks_like_client_hello(data: bytes) -> bool:
    """A TLS handshake record carrying a ClientHello (``16 03 0x .. .. 01``)."""
    return len(data) >= 6 and data[0] == HANDSHAKE and data[1] == 3 and data[2] <= 4 and data[5] == 1


class TLSDecryptor:
    """Engine-level factory: holds the key log and the per-run counters."""

    def __init__(self, keylog: KeyLog) -> None:
        if not crypto_available():
            raise RuntimeError("TLS decryption needs the 'cryptography' package: pip install netcreds-ng[tls]")
        self.keylog = keylog
        self.sessions: list[TLSSession] = []
        self.on_new: Callable[[TLSSession], None] | None = None

    def new_session(self) -> TLSSession:
        session = TLSSession(self.keylog)
        if len(self.sessions) < 10_000:
            self.sessions.append(session)
        return session

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.sessions:
            out[s.status] = out.get(s.status, 0) + 1
        return out
