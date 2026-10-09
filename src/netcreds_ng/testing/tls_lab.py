"""Real TLS conversations for tests, produced in memory by OpenSSL (Python's ``ssl`` module).

No sockets are opened: client and server talk through ``ssl.MemoryBIO`` pairs and every
byte they exchange is recorded into a :class:`TCPConversation`. OpenSSL writes the NSS
key log, so decryption is checked against an independent TLS implementation.

Needs ``cryptography`` (for the throw-away self-signed certificate).
"""

from __future__ import annotations

import datetime as dt
import ssl
from collections.abc import Sequence
from pathlib import Path

from netcreds_ng.testing.packets import TCPConversation

OP_NO_ENCRYPT_THEN_MAC = 1 << 19  # OpenSSL SSL_OP_NO_ENCRYPT_THEN_MAC


def self_signed(directory: Path, rsa: bool = False) -> tuple[str, str]:
    """Write a throw-away certificate and key for ``test.example`` into ``directory``."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    from cryptography.x509.oid import NameOID

    key = rsa_mod.generate_private_key(65537, 2048) if rsa else ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=7)).sign(key, hashes.SHA256())
    )  # fmt: skip
    certfile, keyfile = directory / ("rsa.crt" if rsa else "ec.crt"), directory / ("rsa.key" if rsa else "ec.key")
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))  # fmt: skip
    return str(certfile), str(keyfile)


def _move(src: ssl.MemoryBIO, dst: ssl.MemoryBIO, record: TCPConversation, from_client: bool) -> bool:
    data = src.read()
    if not data:
        return False
    dst.write(data)
    if from_client:
        record.client(data)
    else:
        record.server(data)
    return True


def tls_conversation(
    directory: Path,
    exchanges: Sequence[tuple[bytes, bytes]],
    *,
    keylog: str | None,
    version: str = "1.3",
    ciphers: str | None = None,
    no_etm: bool = False,
    rsa: bool = False,
    port: int = 443,
    conv: TCPConversation | None = None,
    alpn: list[str] | None = None,
) -> tuple[TCPConversation, str]:
    """Run a TLS session; each (request, response) pair is sent after the handshake.

    Returns the recorded conversation and the negotiated cipher name. ``conv`` lets a test
    prepend plaintext (STARTTLS).
    """
    certfile, keyfile = self_signed(directory, rsa=rsa)
    tls_version = ssl.TLSVersion.TLSv1_3 if version == "1.3" else ssl.TLSVersion.TLSv1_2
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile, keyfile)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    for ctx in (server_ctx, client_ctx):
        ctx.minimum_version = ctx.maximum_version = tls_version
        if ciphers:
            ctx.set_ciphers(ciphers)
        if no_etm:
            ctx.options |= OP_NO_ENCRYPT_THEN_MAC
        if alpn:
            ctx.set_alpn_protocols(alpn)
    if keylog:
        client_ctx.keylog_filename = keylog
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname="test.example")
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    record = conv or TCPConversation("192.0.2.10", 50443, "198.51.100.20", port).handshake()

    done = [False, False]
    for _ in range(20):
        for i, side in enumerate((client, server)):
            if not done[i]:
                try:
                    side.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        moved = _move(c_out, s_in, record, True) | _move(s_out, c_in, record, False)
        if all(done) and not moved:
            break
    if not all(done):
        raise RuntimeError("TLS handshake did not complete")

    for request, response in exchanges:
        client.write(request)
        _move(c_out, s_in, record, True)
        got = b""
        while len(got) < len(request):
            got += server.read(65536)
        server.write(response)
        _move(s_out, c_in, record, False)
        got = b""
        while len(got) < len(response):
            try:
                got += client.read(65536)
            except ssl.SSLWantReadError:  # e.g. a TLS 1.3 session ticket only
                break
    cipher = client.cipher()
    return record, cipher[0] if cipher else ""
