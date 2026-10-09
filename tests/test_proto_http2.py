"""HTTP/2 plugin tests (synthetic h2c traffic, documentation IPs, fake values)."""

from __future__ import annotations

import base64
import json
import random

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.http2 import HTTP2Plugin
from netcreds_ng.testing import h2_msgs as h2
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

BASIC = b"Basic " + base64.b64encode(b"alice:Fake-Pass-1")
JWT = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.ZmFrZS1zaWduYXR1cmUtZmFrZQ"


def conv(port: int = 80) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50000, "198.51.100.20", port).handshake()


def run(c: TCPConversation, **options):
    return analyze(c.close().frames, plugins=[HTTP2Plugin(options or None)], enrichers=[])


def start(c: TCPConversation, segment: int | None = None, server_settings: dict[int, int] | None = None):
    """Client preface + SETTINGS, server SETTINGS + ACK."""
    c.client(h2.PREFACE + h2.settings({0x3: 100, 0x4: 65535}), segment=segment)
    c.server(h2.settings(server_settings or {0x3: 128}) + h2.settings(ack=True), segment=segment)
    c.client(h2.settings(ack=True), segment=segment)
    return c


def response(enc: h2.Encoder, sid: int, status: bytes, body: bytes = b"") -> bytes:
    block = enc.encode([(b":status", status), (b"content-type", b"text/plain")])
    if body:
        return h2.headers_frame(sid, block) + h2.data_frame(sid, body, end_stream=True)
    return h2.headers_frame(sid, block, end_stream=True)


def by_kind(findings, kind):
    return [f for f in findings if f.kind is kind]


# ------------------------------------------------------------------ positive


def test_basic_auth_and_failed_result():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    req = h2.request_headers(b"GET", b"/admin", extra=[(b"authorization", BASIC)])
    c.client(h2.headers_frame(1, enc.encode(req), end_stream=True))
    c.server(response(senc, 1, b"401"))
    url, cred, result = run(c)
    assert (url.kind, url.value, url.protocol, url.plugin) == (Kind.URL, "GET www.example.com/admin", "HTTP/2", "http2")
    assert url.extra == {"host": "www.example.com"}
    assert cred.kind is Kind.CREDENTIAL
    assert (cred.username, cred.secret, cred.risk) == ("alice", "Fake-Pass-1", "high")
    assert cred.extra == {"header": "authorization", "url": "GET www.example.com/admin", "mechanism": "Basic"}
    assert (str(cred.src), str(cred.dst)) == ("192.0.2.10:50000", "198.51.100.20:80")
    assert result.kind is Kind.AUTH_RESULT and result.outcome == "failure"
    assert (result.username, result.value) == ("alice", "Basic login failed (HTTP/2 401)")
    assert (str(result.src), str(result.dst)) == ("192.0.2.10:50000", "198.51.100.20:80")


def test_basic_auth_success_result():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    req = h2.request_headers(b"GET", b"/", extra=[(b"authorization", BASIC)])
    c.client(h2.headers_frame(1, enc.encode(req), end_stream=True))
    c.server(response(senc, 1, b"200", b"welcome"))
    result = by_kind(run(c), Kind.AUTH_RESULT)
    assert [r.value for r in result] == ["Basic login succeeded (HTTP/2 200)"]


def test_never_indexed_huffman_authorization_split_into_7_byte_segments():
    c, enc, senc = start(conv(), segment=7), h2.Encoder(), h2.Encoder()
    block = enc.encode(h2.request_headers(b"GET", b"/private"), huffman=True)
    block += enc.literal(b"authorization", BASIC, mode="never", huffman=True)
    c.client(h2.headers_frame(1, block, end_stream=True), segment=7)
    c.server(response(senc, 1, b"403"), segment=7)
    findings = run(c)
    (cred,) = by_kind(findings, Kind.CREDENTIAL)
    assert (cred.username, cred.secret) == ("alice", "Fake-Pass-1")
    (result,) = by_kind(findings, Kind.AUTH_RESULT)
    assert result.value == "Basic login failed (HTTP/2 403)"


def test_form_post_credentials_with_padding_and_priority():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    body = b"username=alice&password=Fake-Pass-1"
    req = h2.request_headers(b"POST", b"/login", extra=[
        (b"content-type", b"application/x-www-form-urlencoded"), (b"content-length", str(len(body)).encode())])  # fmt: skip
    c.client(h2.headers_frame(1, enc.encode(req), pad=5, priority=True))
    c.client(h2.data_frame(1, body[:10], pad=3) + h2.data_frame(1, body[10:], end_stream=True, pad=0))
    c.server(response(senc, 1, b"401"))
    findings = run(c)
    (cred,) = by_kind(findings, Kind.CREDENTIAL)
    assert (cred.username, cred.secret) == ("alice", "Fake-Pass-1")
    assert cred.extra == {"mechanism": "form", "url": "POST www.example.com/login"}
    (post,) = by_kind(findings, Kind.POST)
    assert post.value == body.decode()
    (result,) = by_kind(findings, Kind.AUTH_RESULT)
    assert (result.username, result.value) == ("alice", "form login failed (HTTP/2 401)")


def test_form_login_200_is_not_a_verdict():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    req = h2.request_headers(b"POST", b"/login", extra=[(b"content-type", b"application/x-www-form-urlencoded")])
    c.client(h2.headers_frame(1, enc.encode(req)) + h2.data_frame(1, b"user=alice&pass=Fake-Pass-1", end_stream=True))
    c.server(response(senc, 1, b"200"))
    findings = run(c)
    assert len(by_kind(findings, Kind.CREDENTIAL)) == 1
    assert by_kind(findings, Kind.AUTH_RESULT) == []


def test_json_body_credentials():
    c, enc = start(conv()), h2.Encoder()
    body = json.dumps({"auth": {"email": "alice@example.com", "password": "Fake-Pass-1"}}).encode()
    req = h2.request_headers(b"POST", b"/api/session", extra=[(b"content-type", b"application/json")])
    c.client(h2.headers_frame(1, enc.encode(req)) + h2.data_frame(1, body, end_stream=True))
    (cred,) = by_kind(run(c), Kind.CREDENTIAL)
    assert (cred.username, cred.secret) == ("alice@example.com", "Fake-Pass-1")


def test_bearer_jwt_cookie_api_key_and_query_secrets():
    c, enc = start(conv()), h2.Encoder()
    req = h2.request_headers(b"GET", b"/v1/items?q=fake+search&access_token=FakeToken1234", extra=[
        (b"authorization", b"Bearer " + JWT),
        (b"cookie", b"theme=dark"),
        (b"cookie", b"sessionid=FakeSession99"),  # HTTP/2 split cookie fields
        (b"x-api-key", b"FAKE-API-KEY-0001"),
    ])  # fmt: skip
    c.client(h2.headers_frame(1, enc.encode(req), end_stream=True))
    findings = run(c)
    url = "GET www.example.com/v1/items?q=fake+search&access_token=FakeToken1234"
    (search,) = by_kind(findings, Kind.SEARCH)
    assert search.value == "fake search"
    tokens = by_kind(findings, Kind.TOKEN)
    assert {(t.secret, t.extra.get("mechanism"), t.extra.get("token_type")) for t in tokens} == {
        ("FakeToken1234", None, None), (JWT.decode(), "Bearer", "JWT"),
    }  # fmt: skip
    assert all(t.extra["url"] == url for t in tokens)
    (cookie,) = by_kind(findings, Kind.COOKIE)
    assert (cookie.secret, cookie.risk, cookie.extra) == (
        "sessionid=FakeSession99", "medium", {"cookie": "sessionid", "host": "www.example.com"})  # fmt: skip
    (key,) = by_kind(findings, Kind.API_KEY)
    assert (key.secret, key.extra) == ("FAKE-API-KEY-0001", {"header": "x-api-key", "url": url})


@pytest.mark.parametrize(("mode", "expected"), [("all", 2), ("off", 0), ("session", 1)])
def test_cookie_mode_option(mode, expected):
    c, enc = start(conv()), h2.Encoder()
    req = h2.request_headers(b"GET", b"/", extra=[(b"cookie", b"theme=dark; sid=FakeSid")])
    c.client(h2.headers_frame(1, enc.encode(req), end_stream=True))
    assert len(by_kind(run(c, cookies=mode), Kind.COOKIE)) == expected


def test_header_block_split_with_continuation():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    block = enc.encode(h2.request_headers(b"GET", b"/split", extra=[(b"authorization", BASIC)]))
    a, b, rest = block[:5], block[5:20], block[20:]
    c.client(h2.headers_frame(1, a, end_stream=True, end_headers=False)
             + h2.continuation(1, b, end_headers=False) + h2.continuation(1, rest), segment=7)  # fmt: skip
    c.server(response(senc, 1, b"401"))
    findings = run(c)
    assert [f.kind for f in findings] == [Kind.URL, Kind.CREDENTIAL, Kind.AUTH_RESULT]
    assert findings[0].value == "GET www.example.com/split"


def test_dynamic_table_reuse_across_requests():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    req = h2.request_headers(b"GET", b"/one", extra=[(b"authorization", BASIC)])
    first = enc.encode(req)
    second = enc.encode(h2.request_headers(b"GET", b"/two", extra=[(b"authorization", BASIC)]))
    # The second block refers to :authority and authorization through the dynamic table.
    assert len(second) < len(first) and BASIC not in second
    c.client(h2.headers_frame(1, first, end_stream=True))
    c.server(response(senc, 1, b"401"))
    c.client(h2.headers_frame(3, second, end_stream=True))
    c.server(response(senc, 3, b"200"))
    findings = run(c)
    assert [f.value for f in by_kind(findings, Kind.URL)] == ["GET www.example.com/one", "GET www.example.com/two"]
    creds = by_kind(findings, Kind.CREDENTIAL)
    assert len(creds) == 1  # identical credential de-duplicated by the pipeline
    assert [r.value for r in by_kind(findings, Kind.AUTH_RESULT)] == [
        "Basic login failed (HTTP/2 401)", "Basic login succeeded (HTTP/2 200)"]  # fmt: skip


def test_table_size_settings_and_size_update():
    c = start(conv(), server_settings={0x1: 8192})
    enc = h2.Encoder()
    block = enc.size_update(8192) + enc.encode(h2.request_headers(b"GET", b"/big", extra=[(b"authorization", BASIC)]))
    c.client(h2.headers_frame(1, block, end_stream=True))
    assert len(by_kind(run(c), Kind.CREDENTIAL)) == 1


def test_interleaved_streams_and_early_401():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    req1 = h2.request_headers(b"POST", b"/upload", extra=[(b"authorization", BASIC)])
    req3 = h2.request_headers(b"GET", b"/other")
    c.client(h2.headers_frame(1, enc.encode(req1)) + h2.data_frame(1, b"part-1"))
    c.client(h2.headers_frame(3, enc.encode(req3), end_stream=True))
    c.server(response(senc, 1, b"401"))  # before the request body finished
    c.client(h2.data_frame(1, b"part-2", end_stream=True))
    findings = run(c)
    assert sorted(f.value for f in by_kind(findings, Kind.URL)) == ["GET www.example.com/other",
                                                                    "POST www.example.com/upload"]  # fmt: skip
    (result,) = by_kind(findings, Kind.AUTH_RESULT)
    assert result.value == "Basic login failed (HTTP/2 401)"


def test_ntlm_negotiate_and_digest_are_metadata_only():
    c, enc = start(conv()), h2.Encoder()
    spnego = b"Negotiate " + base64.b64encode(b"\x60\x82\x01\x00" + b"\x55" * 16)
    digest = b'Digest username="alice", realm="example", nonce="FakeNonceZZ", response="FakeRespQQ", algorithm=SHA-256'
    c.client(h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/a", extra=[(b"authorization", spnego)])),
                              end_stream=True))  # fmt: skip
    c.client(h2.headers_frame(3, enc.encode(h2.request_headers(b"GET", b"/b", extra=[(b"authorization", digest)])),
                              end_stream=True))  # fmt: skip
    events = by_kind(run(c), Kind.AUTH_EVENT)
    assert [(e.value, e.username, e.secret) for e in events] == [
        ("Kerberos (SPNEGO) authentication over HTTP/2", None, None),
        ("HTTP Digest (SHA-256)", "alice", None),
    ]  # fmt: skip
    dumped = json.dumps([e.to_dict() for e in events])
    assert "FakeRespQQ" not in dumped and "FakeNonceZZ" not in dumped and "VVVV" not in dumped


def test_rst_stream_still_reports_sent_headers_and_push_promise_keeps_sync():
    c, enc, senc = start(conv()), h2.Encoder(), h2.Encoder()
    c.client(h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/x", extra=[(b"authorization", BASIC)]))))
    c.client(h2.rst_stream(1))
    # server pushes a promise (its header block uses the server->client HPACK context)
    promise = senc.encode(h2.request_headers(b"GET", b"/pushed.css"))
    c.server(h2.frame(h2.PUSH_PROMISE, h2.END_HEADERS, 3, b"\x00\x00\x00\x02" + promise))
    c.server(response(senc, 2, b"200", b"body{}"))
    c.client(h2.window_update() + h2.ping())
    c.client(h2.headers_frame(5, enc.encode(h2.request_headers(b"GET", b"/y")), end_stream=True))
    c.client(h2.goaway(5))
    findings = run(c)
    assert [f.value for f in by_kind(findings, Kind.URL)] == ["GET www.example.com/x", "GET www.example.com/y"]
    assert len(by_kind(findings, Kind.CREDENTIAL)) == 1


def test_unfinished_stream_reported_on_close():
    c, enc = start(conv()), h2.Encoder()
    c.client(h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/hang", extra=[(b"authorization", BASIC)]))))
    findings = run(c)
    assert [f.kind for f in findings] == [Kind.URL, Kind.CREDENTIAL]


def test_large_data_frame_is_streamed_and_capped():
    c, enc = start(conv()), h2.Encoder()
    req = h2.request_headers(b"POST", b"/upload", extra=[(b"content-type", b"application/octet-stream")])
    c.client(h2.headers_frame(1, enc.encode(req)))
    c.client(h2.data_frame(1, b"\x00" * 300_000, end_stream=True), segment=1400)
    c.client(h2.headers_frame(3, enc.encode(h2.request_headers(b"GET", b"/after")), end_stream=True))
    assert [f.value for f in by_kind(run(c), Kind.URL)] == ["POST www.example.com/upload", "GET www.example.com/after"]


def test_server_settings_before_client_preface_completes():
    c, enc = conv(443), h2.Encoder()
    c.client(h2.PREFACE[:10])
    c.server(h2.settings({0x3: 100}))
    c.client(h2.PREFACE[10:] + h2.settings())
    c.client(h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/tls")), end_stream=True))
    (url,) = run(c)
    assert (url.value, url.dst.port) == ("GET www.example.com/tls", 443)


# ------------------------------------------------------------------ negative


def assert_nothing(c: TCPConversation) -> None:
    assert run(c) == []


def test_http11_is_ignored():
    c = conv()
    c.client(
        b"GET /?user=alice&pass=Fake-Pass-1 HTTP/1.1\r\nHost: www.example.com\r\nAuthorization: " + BASIC + b"\r\n\r\n"
    )
    c.server(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
    assert_nothing(c)


def test_server_http1_response_detaches():
    c, enc = conv(), h2.Encoder()
    c.server(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    c.client(h2.PREFACE + h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/", extra=[
        (b"authorization", BASIC)])), end_stream=True))  # fmt: skip
    assert_nothing(c)


def test_tls_and_random_bytes_are_ignored():
    rnd = random.Random(7)
    for payload in (bytes.fromhex("16030100c4010000c00303") + bytes(180), bytes(rnd.randrange(256) for _ in range(500)),
                    b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n"):  # fmt: skip
        c = conv(443)
        c.client(payload, segment=7)
        assert_nothing(c)


def test_truncated_frames_produce_nothing():
    c, enc = start(conv()), h2.Encoder()
    frame = h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/", extra=[(b"authorization", BASIC)])),
                             end_stream=True)  # fmt: skip
    c.client(frame[: len(frame) - 3])
    assert_nothing(c)


@pytest.mark.parametrize(
    "bad",
    [
        bytes([0xFF, 0xFF, 0xFF, h2.HEADERS, h2.END_HEADERS, 0, 0, 0, 1]),  # 16 MiB HEADERS length
        b"\xff\xff\xff" + bytes([h2.SETTINGS, 0]) + b"\x00" * 4,  # absurd SETTINGS length
        h2.frame(h2.SETTINGS, 0, 0, b"\x00" * 5),  # SETTINGS not a multiple of 6
        h2.frame(h2.HEADERS, h2.END_HEADERS, 0, b"\x82"),  # HEADERS on stream 0
        h2.frame(h2.HEADERS, h2.END_HEADERS | h2.PADDED, 1, b"\x09\x82"),  # padding longer than the frame
        h2.frame(h2.HEADERS, h2.END_HEADERS, 1, b"\xbf\x80"),  # HPACK index out of range
        h2.frame(h2.HEADERS, 0, 1, b"\x82") + h2.data_frame(1, b"x"),  # missing CONTINUATION
        h2.frame(h2.CONTINUATION, h2.END_HEADERS, 1, b"\x82"),  # stray CONTINUATION
        h2.frame(h2.DATA, h2.PADDED, 1, b""),  # PADDED DATA without pad length
        h2.frame(h2.DATA, h2.PADDED, 1, b"\x05abc"),  # DATA padding too long
    ],
)
def test_malformed_frames_detach_without_error(bad):
    c, enc = start(conv()), h2.Encoder()
    c.client(bad)
    # nothing decodable follows a protocol error
    c.client(h2.headers_frame(3, enc.encode(h2.request_headers(b"GET", b"/later")), end_stream=True))
    assert_nothing(c)


def test_server_first_frame_must_be_settings():
    c, enc = conv(), h2.Encoder()
    c.client(h2.PREFACE + h2.settings())
    c.server(h2.ping())
    c.client(h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/")), end_stream=True))
    assert_nothing(c)


def test_gap_detaches():
    c, enc = start(conv()), h2.Encoder()
    c.advance(True, 50)  # 50 client bytes never captured
    c.client(h2.headers_frame(1, enc.encode(h2.request_headers(b"GET", b"/", extra=[(b"authorization", BASIC)])),
                              end_stream=True))  # fmt: skip
    assert_nothing(c)


def test_fuzzed_frames_never_raise():
    rnd = random.Random(1234)
    for _ in range(40):
        c = start(conv())
        blob = bytearray()
        for _ in range(rnd.randrange(1, 6)):
            ftype = rnd.randrange(12)
            payload = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 40)))
            blob += h2.frame(ftype, rnd.randrange(256), rnd.randrange(4), payload)
        c.client(bytes(blob), segment=rnd.randrange(1, 20))
        c.server(bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 60))))
        run(c)  # the harness raises on any plugin error
