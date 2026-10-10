"""Cloud/API secret-format detector tests.

Every token below is fake: built by concatenation from obvious filler so no
literal token appears in the source, but each is format-valid for its detector.
"""

from __future__ import annotations

import json
import random

import pytest

from netcreds_ng.model import Kind
from netcreds_ng.plugins.protocols.secrets import SCAN_LIMIT, SecretsPlugin
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

AWS_ID = "AKIA" + "FAKEKEYID0000042"  # format-valid, obviously fake
AWS_SECRET = "Fake/Secret+Key" + "0123456789abcdefGHIJKLMNO"  # 40 chars, mixed case, fake
DOC_ID = "AKIA" + "IOSFODNN7" + "EXAMPLE"  # AWS's documented example key id
DOC_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"  # AWS's documented example secret
GCP_KEY = "AIza" + "Sy" + "FAKE" * 8 + "x"
GITHUB = "ghp_" + "x" * 36
GITHUB_PAT = "github_pat_" + "FAKE" * 5 + "xx" + "_" + "x" * 59
SLACK = "xoxb-" + "0" * 10 + "-" + "1" * 10 + "-" + "FAKEFAKEFAKE"
STRIPE = "sk_" + "live_" + "FAKE" * 6
AZ_KEY = "FAKE" * 21 + "xx" + "=="
SAS = "sv=2022-11-02&ss=b&srt=sco&sp=r&se=2030-01-01T00:00:00Z&sig=" + "FAKEsig" * 6 + "%3D"


def conv(port: int = 8080) -> TCPConversation:
    return TCPConversation("192.0.2.10", 50000, "198.51.100.20", port).handshake()


def run(c: TCPConversation):
    return analyze(c.close().frames, plugins=[SecretsPlugin()], enrichers=[])


def detectors(findings) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in findings:
        out.setdefault(f.extra["detector"], []).append(f)
    return out


def test_token_formats_detected():
    assert len(GCP_KEY) == 39 and len(AZ_KEY) == 88
    body = (
        f"gcp={GCP_KEY}\n"
        f"gh: {GITHUB}\n"
        f"pat '{GITHUB_PAT}'\n"
        f"slack={SLACK}\n"
        f"stripe:{STRIPE}\n"
    ).encode()
    c = conv()
    c.client(b"PUT /config HTTP/1.1\r\n\r\n" + body)
    found = detectors(run(c))
    expect = {
        "gcp_api_key": ("gcp", GCP_KEY), "github_token": ("github", GITHUB), "github_pat": ("github", GITHUB_PAT),
        "slack_token": ("slack", SLACK), "stripe_secret_key": ("stripe", STRIPE),
    }  # fmt: skip
    assert set(found) == set(expect)
    for name, (provider, token) in expect.items():
        (f,) = found[name]
        assert f.kind is Kind.API_KEY and f.protocol == "Cleartext" and f.plugin == "secrets"
        assert (f.secret, f.risk, f.tags) == (token, "high", [provider])
        assert f.extra == {"detector": name}
        assert f.src.ip == "192.0.2.10"


def test_server_to_client_direction():
    c = conv()
    c.client(b"GET /creds\n").server(f'{{"token": "{GITHUB}"}}'.encode())
    (f,) = run(c)
    assert f.secret == GITHUB and f.src.ip == "198.51.100.20" and f.dst.ip == "192.0.2.10"


def test_aws_pair_and_lone_key():
    c = conv()
    c.client(f"aws_access_key_id = {AWS_ID}\naws_secret_access_key = {AWS_SECRET}\n".encode())
    (f,) = run(c)
    assert (f.username, f.secret, f.tags) == (AWS_ID, AWS_SECRET, ["aws"])
    assert f.extra == {"detector": "aws_access_key", "paired_secret": True}

    lone = "ASIA" + "FAKEFAKEFAKE0000"
    c = conv()
    c.client(f"key={lone} other data that is not a secret value at all\n".encode() + b"." * 300)
    (f,) = run(c)
    assert (f.username, f.secret) == (None, lone) and "paired_secret" not in f.extra
    assert f.risk == "medium" and "key-id-only" in f.tags


def test_documentation_example_keys_are_info_not_high():
    # Review L7: AWS's published sample key is not a live credential.
    c = conv()
    c.client(f"aws_access_key_id = {DOC_ID}\naws_secret_access_key = {DOC_SECRET}\n".encode())
    (f,) = run(c)
    assert f.risk == "info" and "documentation-example" in f.tags


@pytest.mark.parametrize("segment", [1, 5, 17])
def test_split_across_segments(segment):
    payload = f"id={AWS_ID}\nsecret={AWS_SECRET}\nx {GITHUB} y\n{SAS}\n".encode()
    c = conv()
    c.client(payload, segment=segment)
    found = detectors(run(c))
    assert found["aws_access_key"][0].secret == AWS_SECRET
    assert found["github_token"][0].secret == GITHUB
    assert found["azure_sas_token"][0].secret == SAS
    assert sum(len(v) for v in found.values()) == 3


def test_token_at_stream_end_and_stream_start():
    c = conv()
    c.client(GITHUB.encode(), segment=5)
    (f,) = run(c)
    assert f.secret == GITHUB


def test_longer_run_is_not_a_token():
    # Token-shaped prefix followed by more token characters: boundary must reject it, also when split.
    c = conv()
    c.client(("ghp_" + "x" * 40 + "\n").encode(), segment=7)
    c.client(("AKIA" + "A" * 20 + "\n").encode(), segment=7)
    assert run(c) == []


def test_dedup_per_flow():
    c = conv()
    c.client(f"{GITHUB}\n{GITHUB}\n".encode()).server(f"{GITHUB}\n".encode())
    findings = run(c)
    assert len(findings) == 1


def test_azure_connection_string_and_sas():
    conn = f"DefaultEndpointsProtocol=https;AccountName=fakeacct;AccountKey={AZ_KEY};EndpointSuffix=core.example"
    url = f"GET /container/blob.txt?{SAS} HTTP/1.1\r\n"
    c = conv()
    c.client(conn.encode() + b"\n" + url.encode())
    found = detectors(run(c))
    (key,) = found["azure_storage_key"]
    assert (key.secret, key.username, key.tags) == (AZ_KEY, "fakeacct", ["azure"])
    assert key.extra == {"detector": "azure_storage_key", "account": "fakeacct"}
    (sas,) = found["azure_sas_token"]
    assert sas.secret == SAS


def test_sig_without_sas_fields_ignored():
    c = conv()
    c.client(("GET /x?sig=" + "FAKEsig" * 6 + "&a=b HTTP/1.1\r\n").encode())
    assert run(c) == []


def test_gcp_service_account_json_split():
    sa = {
        "type": "service_account", "project_id": "fake-project", "private_key_id": "0" * 40,
        "private_key": "-----BEGIN PRIVATE KEY-----\n" + "FAKE" * 400 + "\n-----END PRIVATE KEY-----\n",
        "client_email": "fake-sa@fake-project.iam.gserviceaccount.com", "client_id": "000000000000000000000",
    }  # fmt: skip
    blob = json.dumps(sa, indent=2).encode()
    c = conv()
    c.client(b"POST /upload HTTP/1.1\r\n\r\n" + blob, segment=100)
    found = detectors(run(c))
    (acct,) = found["gcp_service_account"]
    assert acct.username == "fake-sa@fake-project.iam.gserviceaccount.com" and acct.tags == ["gcp"]
    assert acct.extra == {"detector": "gcp_service_account", "private_key_id": "0" * 40}
    (pem,) = found["pem_private_key"]
    assert pem.extra["pem_type"] == "PRIVATE KEY" and pem.extra["complete"] is True
    assert "FAKE" not in repr(pem.to_dict())  # key body never reported


def test_pem_reports_type_and_length_only():
    body = b"MIIfakeFAKEfake" * 120
    pem = b"-----BEGIN RSA PRIVATE KEY-----\n" + body + b"\n-----END RSA PRIVATE KEY-----"
    c = conv()
    c.server(b"key follows\n" + pem + b"\ntrailer\n", segment=50)
    (f,) = run(c)
    assert f.kind is Kind.API_KEY and f.secret is None and f.tags == ["pem"]
    assert f.value == f"PEM RSA PRIVATE KEY block ({len(pem)} bytes)"
    assert f.extra == {"detector": "pem_private_key", "pem_type": "RSA PRIVATE KEY", "length": len(pem), "complete": True}
    assert b"MIIfake".decode() not in repr(f.to_dict())


def test_pem_unterminated_reported_incomplete():
    c = conv()
    c.client(b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"b3BlbnNzaC1rZXktdjEFAKE" * 10)
    (f,) = run(c)
    assert f.extra["complete"] is False and f.extra["length"] is None
    assert f.value == "PEM OPENSSH PRIVATE KEY block (incomplete)"


def test_public_key_and_certificate_ignored():
    c = conv()
    c.client(b"-----BEGIN PUBLIC KEY-----\nMIIfake\n-----END PUBLIC KEY-----\n-----BEGIN CERTIFICATE-----\n")
    assert run(c) == []


def test_tls_flow_skipped():
    c = conv(port=443)
    c.client(b"\x16\x03\x01\x02\x00\x01" + GITHUB.encode())
    c.server(GITHUB.encode())
    assert run(c) == []


def test_random_binary_no_findings():
    rng = random.Random(20261008)
    c = conv()
    c.client(rng.randbytes(256 * 1024), segment=1400)
    c.server(rng.randbytes(64 * 1024), segment=1400)
    assert run(c) == []


def test_scan_limit():
    c = conv()
    c.client(b"A" * 1000 + b"\n" + b"z" * (SCAN_LIMIT - 1001) + b"\n", segment=60000)
    c.client(f" {GITHUB}\n".encode())
    assert run(c) == []
    c = conv()
    c.client(b"z" * (SCAN_LIMIT - 200) + f" {GITHUB}\n".encode(), segment=60000)
    assert len(run(c)) == 1


def test_gap_resets_window_without_detaching():
    c = conv()
    c.client(b"first part " + GITHUB[:20].encode())
    c.advance(True, 100)  # 100 bytes lost
    c.client(GITHUB[20:].encode() + b" then " + STRIPE.encode() + b"\n")
    (f,) = run(c)
    assert f.secret == STRIPE


def test_token_starting_right_after_gap_is_not_trusted_but_later_ones_are():
    c = conv()
    c.client(b"hello\n")
    c.advance(True, 50)
    c.client(GITHUB.encode() + b"\n" + SLACK.encode() + b"\n")
    (f,) = run(c)
    assert f.secret == SLACK


# --- E-10: one key reported by both http and secrets ---------------------------------


def _api_key_request(split_body: bool = False) -> TCPConversation:
    c = TCPConversation("192.0.2.10", 50310, "198.51.100.20", 80).handshake()
    body = b"api_key=" + GITHUB.encode() + b"&note=fake"
    head = (b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nX-Api-Key: " + GITHUB.encode()
            + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n")  # fmt: skip
    if split_body:  # the token is complete in the first segment, the HTTP body is not
        c.client(head + body[:-4]).client(body[-4:])
    else:
        c.client(head + body)
    return c.close()


@pytest.mark.parametrize(
    "split_body,first",
    [
        (False, "http"),  # http runs before secrets on the same data
        (True, "secrets"),  # secrets sees the complete token before http has the complete request
    ],
)
def test_key_seen_by_http_and_secrets_is_reported_once(split_body, first):
    from netcreds_ng.model import RunStats

    stats = RunStats()
    found = analyze(_api_key_request(split_body).frames, enrichers=[], stats=stats)
    with_key = [f for f in found if f.secret == GITHUB]
    assert [(f.plugin, f.kind) for f in with_key] == [(first, Kind.API_KEY)]
    assert stats.duplicates >= 1


def test_secrets_alone_still_reports_the_key():
    found = analyze(_api_key_request().frames, plugins=[SecretsPlugin()], enrichers=[])
    assert [(f.plugin, f.secret) for f in found] == [("secrets", GITHUB)]


def test_dedup_off_keeps_both_reports():
    found = analyze(_api_key_request().frames, enrichers=[], dedup="off")
    assert sorted({f.plugin for f in found if f.secret == GITHUB}) == ["http", "secrets"]


@pytest.mark.parametrize("split_body", [False, True])
def test_form_login_with_a_token_password_keeps_the_username_however_segmented(split_body):
    # Review M32 MED-1: when secrets saw the bare token first, the http credential (with the user
    # name) was dropped as a duplicate. A later report that adds a user name is kept.
    c = TCPConversation("192.0.2.10", 50311, "198.51.100.20", 80).handshake()
    body = b"username=alice&password=" + GITHUB.encode() + b"&note=fake"
    head = (b"POST /login HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: application/x-www-form-urlencoded"
            b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")  # fmt: skip
    if split_body:
        c.client(head + body[:-4]).client(body[-4:])
    else:
        c.client(head + body)
    found = analyze(c.close().frames, enrichers=[])
    assert ("alice", GITHUB) in [(f.username, f.secret) for f in found if f.kind is Kind.CREDENTIAL]
