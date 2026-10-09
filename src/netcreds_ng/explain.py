"""Why a finding matters: plain-language reasons for its kind, risk and tags.

Every tag a built-in plugin, enricher or the engine can set has an entry here (a test
enforces it). :func:`explain` turns a finding into an ordered list of :class:`Reason`
objects; the dashboard's inspector shows them, and reports can reuse them. This module
explains exposure only. Remediation advice (what to change) is milestone M18.

Text never includes the secret itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from netcreds_ng.model import Finding, Kind

RISK_MEANING = {
    "high": "usable as-is by anyone who sees this traffic, or a configuration that hands out such material",
    "medium": "weakens authentication or leaks material that is attackable with effort",
    "low": "identifies accounts or services; useful to an attacker for targeting",
    "info": "context and inventory; no exposure on its own",
}

KIND_WHY: dict[Kind, str] = {
    Kind.CREDENTIAL: "A username and its secret were both seen, so whoever sees this traffic can log in as this account.",
    Kind.USERNAME: "An account name was seen. On its own it is not a credential, but it tells an attacker which accounts exist.",
    Kind.PASSWORD: "A password was seen without a matching username in the same message.",
    Kind.AUTH_EVENT: "An authentication exchange was observed. Its strength depends on the mechanism, shown in the tags below.",
    Kind.TOKEN: "A bearer token was seen. Whoever holds it can act as its owner until it expires or is revoked.",
    Kind.API_KEY: "An API key or cloud secret was seen. It usually stays valid until someone rotates it.",
    Kind.COOKIE: "A session cookie was seen. Replaying it can take over the logged-in session.",
    Kind.COMMUNITY: "An SNMP community string was seen. It is the only secret SNMPv1/v2c has: it grants read (or write) access to the device.",
    Kind.AUTH_RESULT: "The outcome of a login attempt. Repeated failures feed the brute-force and spraying detections.",
    Kind.URL: "A URL that was visited (browsing activity). It may carry tokens or personal data in its query string.",
    Kind.POST: "Form data sent over HTTP. It may contain credentials or personal data.",
    Kind.SEARCH: "A search query (browsing activity).",
    Kind.INFO: "Context about a connection, kept for the inventory.",
    Kind.ALERT: "A behavioural detection over many login results, not a single packet.",
}


@dataclass(frozen=True)
class TagInfo:
    title: str
    detail: str
    source: str  # who sets it: engine, analytics, detection, plugin


_TAGS: dict[str, TagInfo] = {
    # engine and enrichers ----------------------------------------------------------------
    "tls-decrypted": TagInfo(
        "Read through TLS decryption",
        "This traffic was encrypted on the wire; netcreds-ng read it with the supplied key log. "
        "It is not a cleartext exposure, but it shows what the application sends inside TLS.",
        "engine"),
    "cleartext": TagInfo(
        "Sent in cleartext",
        "The protocol carried this secret without encryption. Anyone who can see the traffic "
        "(same network segment, a tap or SPAN port, a compromised switch or router) can read it.",
        "analytics"),
    "weak-password": TagInfo(
        "Weak password",
        "The password is on the bundled list of common passwords or is shorter than 6 characters; "
        "the analytics enricher raised the risk to high.",
        "analytics"),
    "password-reuse": TagInfo(
        "Password reused",
        "The same secret was seen for another account or another service in this run, so one leak "
        "exposes every place it is used.",
        "analytics"),
    "brute-force": TagInfo(
        "Brute force",
        "One client failed to log in to one service many times within the detection window.",
        "detection"),
    "password-spraying": TagInfo(
        "Password spraying",
        "One client failed against many different accounts on one service within the detection window.",
        "detection"),
    "targeted-account": TagInfo(
        "Targeted account",
        "One account failed to log in from many different clients within the detection window.",
        "detection"),
    "login-after-failures": TagInfo(
        "Login after failures",
        "A successful login followed a brute-force or spraying burst from the same client: "
        "the guessing may have worked.",
        "detection"),
    # common plugin tags --------------------------------------------------------------------
    "nonstandard-port": TagInfo(
        "Service on a non-standard port",
        "The protocol was recognised by its content on a port other than its usual one. Inventories "
        "and firewall rules keyed on standard ports may miss this service.",
        "plugin"),
    "heuristic": TagInfo(
        "Heuristic match",
        "Recognised without strong protocol evidence (lower confidence). Check the context before "
        "acting on it; --strict-heuristics reduces these.",
        "plugin"),
    "cleartext-password": TagInfo(
        "Mechanism sends the password itself",
        "The authentication method transmits the password as-is rather than a hash or a "
        "challenge response.",
        "plugin"),
    "empty-password": TagInfo(
        "Empty password",
        "The account logged in, or tried to, with an empty password.",
        "plugin"),
    "password-change": TagInfo(
        "Password change",
        "A new password was sent. If the change succeeded, it is the account's current password.",
        "plugin"),
    "new-password": TagInfo(
        "New password sent",
        "A password change sent the new password. If it succeeded, it is the account's current password.",
        "plugin"),
    "change-user": TagInfo(
        "Re-authentication on an open connection",
        "The MySQL client switched to another account (COM_CHANGE_USER) without opening a new connection.",
        "plugin"),
    "basic-auth": TagInfo(
        "Basic authentication",
        "The username and password are only base64-encoded, which anyone can reverse.",
        "plugin"),
    "digest": TagInfo(
        "Digest authentication",
        "The password itself is not sent, but the MD5-based response can be attacked offline when "
        "the password is weak.",
        "plugin"),
    "encrypted": TagInfo(
        "Encrypted connection",
        "The connection negotiated encryption. Reported for the service inventory.",
        "plugin"),
    # directory and Windows authentication ----------------------------------------------------
    "unauthenticated-bind": TagInfo(
        "Unauthenticated LDAP bind",
        "A bind with a DN and an empty password. Servers that allow it treat it as anonymous, and "
        "applications that check a password by binding can be fooled into accepting any user.",
        "plugin"),
    "ntlmv1": TagInfo(
        "NTLMv1",
        "NTLMv1 responses are weak by design: they can be reduced to the account's NT hash. "
        "Domains should accept NTLMv2 only.",
        "plugin"),
    "weak-etype-offered": TagInfo(
        "Client offered weak Kerberos encryption",
        "The client's request lists RC4 or DES encryption types. While a domain still accepts "
        "them, tickets can be issued with them.",
        "plugin"),
    "no-preauth": TagInfo(
        "Kerberos pre-authentication not required",
        "The KDC issued an AS-REP without pre-authentication. Anyone can request such a reply for "
        "this account and attack it offline, without knowing the password.",
        "plugin"),
    "weak-service-ticket": TagInfo(
        "Service ticket with weak encryption",
        "The ticket for this service is encrypted with RC4 or DES, so the service account still "
        "allows weak encryption types and its ticket is easier to attack offline.",
        "plugin"),
    # SNMP -----------------------------------------------------------------------------------
    "write-access": TagInfo(
        "SNMP write request",
        "The community string was used in a SET request, so it grants write access: it can change "
        "the device's configuration.",
        "plugin"),
    "default-community": TagInfo(
        "Default community string",
        "A well-known default such as 'public' or 'private'. Attackers try these first; the "
        "analytics enricher raised the risk to high.",
        "plugin"),
    "snmpv3-noAuthNoPriv": TagInfo(
        "SNMPv3 without authentication or privacy",
        "noAuthNoPriv: messages are neither authenticated nor encrypted.",
        "plugin"),
    "snmpv3-authNoPriv": TagInfo(
        "SNMPv3 without privacy",
        "authNoPriv: messages are authenticated but not encrypted, so their contents are readable.",
        "plugin"),
    "snmpv3-invalid": TagInfo(
        "SNMPv3 with an invalid security level",
        "The message flags carry an invalid security level (privacy without authentication).",
        "plugin"),
    # remote access ----------------------------------------------------------------------------
    "rdp-cookie": TagInfo(
        "RDP username sent before encryption",
        "The client put the username in its first packet (the mstshash cookie), before any "
        "encryption was negotiated.",
        "plugin"),
    "nla": TagInfo(
        "Network Level Authentication",
        "The user authenticated (CredSSP) before the session was set up. This is the recommended setting.",
        "plugin"),
    "tls": TagInfo(
        "Protected by TLS",
        "The session is encrypted with TLS.",
        "plugin"),
    "no-nla": TagInfo(
        "RDP without Network Level Authentication",
        "The server sets up a full session, logon screen included, before the user proves who they "
        "are. That exposes the server to unauthenticated attacks and resource exhaustion.",
        "plugin"),
    "standard-rdp-security": TagInfo(
        "Legacy RDP security",
        "Standard RDP Security uses RC4-based encryption without server authentication, so the "
        "connection can be intercepted.",
        "plugin"),
    "no-response": TagInfo(
        "Server reply not captured",
        "The capture does not include the server's reply, so the negotiated security is unknown.",
        "plugin"),
    "negotiation-failed": TagInfo(
        "Security negotiation failed",
        "Client and server could not agree on a security protocol.",
        "plugin"),
    "no-authentication": TagInfo(
        "No authentication required",
        "The server let the client in without any credentials.",
        "plugin"),
    "challenge-response": TagInfo(
        "VNC challenge-response",
        "VNC authentication encrypts a challenge with DES, keyed by a password of at most "
        "8 characters. The exchange can be attacked offline.",
        "plugin"),
    "unencrypted-session": TagInfo(
        "Session not encrypted",
        "Everything after login (screen contents, keystrokes) travels unencrypted.",
        "plugin"),
    "non-vnc-auth": TagInfo(
        "Other VNC security type",
        "Authentication used an extension security type; its strength depends on the type.",
        "plugin"),
    # databases --------------------------------------------------------------------------------
    "tcps": TagInfo(
        "Oracle over TLS (TCPS)",
        "The Oracle connection is wrapped in TLS.",
        "plugin"),
    "ano-encryption": TagInfo(
        "Oracle native network encryption",
        "Oracle Advanced Networking Option encryption was negotiated for this connection.",
        "plugin"),
    # AAA ------------------------------------------------------------------------------------
    "obfuscated-body": TagInfo(
        "TACACS+ body obfuscated",
        "The packet body is obfuscated with the shared key (MD5-based, not real encryption); "
        "only the header is visible.",
        "plugin"),
    "sensitive-arguments": TagInfo(
        "Sensitive command arguments",
        "A TACACS+ authorisation or accounting record carries arguments that look like secrets.",
        "plugin"),
    "eap-identity": TagInfo(
        "EAP outer identity",
        "The username was sent in cleartext as the outer EAP identity.",
        "plugin"),
    "pap": TagInfo(
        "RADIUS PAP",
        "The password is hidden only with the RADIUS shared secret (MD5). Anyone who knows or "
        "guesses a weak shared secret can recover it.",
        "plugin"),
    "chap": TagInfo(
        "CHAP challenge-response",
        "The password is not sent, but the MD5 response can be attacked offline when the password is weak.",
        "plugin"),
    "ms-chap": TagInfo(
        "MS-CHAP",
        "MS-CHAPv1 is broken: its response can be reduced to the account's NT hash.",
        "plugin"),
    "ms-chapv2": TagInfo(
        "MS-CHAPv2",
        "Without an outer TLS tunnel that validates the server certificate, MS-CHAPv2 can be "
        "reduced to a single DES key.",
        "plugin"),
    "eap": TagInfo(
        "EAP authentication",
        "Authentication used EAP; its strength depends on the EAP method.",
        "plugin"),
    # secrets plugin ---------------------------------------------------------------------------
    "key-id-only": TagInfo(
        "Key ID without its secret",
        "Only the AWS access key ID was seen. It identifies the key and its account but cannot "
        "sign requests on its own.",
        "plugin"),
    "documentation-example": TagInfo(
        "Documentation example",
        "Matches a well-known example value from vendor documentation; it is probably not a real "
        "secret, so the risk was lowered to info.",
        "plugin"),
}

# Tags made from a value: the prefix decides the explanation.
_PREFIX_TAGS: dict[str, TagInfo] = {
    "weak-preauth-": TagInfo(
        "Pre-authentication with weak encryption",
        "The encrypted timestamp was made with an RC4 or DES key. These encryption types are "
        "deprecated for Kerberos, and material encrypted with them is far easier to attack offline.",
        "plugin"),
}

# Provider tags set by the secrets plugin (the first tag names whose secret it is).
SECRET_PROVIDERS = {
    "aws": "Amazon Web Services", "azure": "Microsoft Azure", "gcp": "Google Cloud", "github": "GitHub",
    "slack": "Slack", "stripe": "Stripe", "pem": "a PEM private key",
}  # fmt: skip


def known_tags() -> frozenset[str]:
    """Every exact tag with an entry (dynamic prefixes and providers are matched separately)."""
    return frozenset(_TAGS) | frozenset(SECRET_PROVIDERS)


def tag_info(tag: str) -> TagInfo | None:
    info = _TAGS.get(tag)
    if info is not None:
        return info
    for prefix, pinfo in _PREFIX_TAGS.items():
        if tag.startswith(prefix):
            return TagInfo(f"{pinfo.title} ({tag[len(prefix):]})", pinfo.detail, pinfo.source)
    if tag in SECRET_PROVIDERS:
        return TagInfo(
            f"Secret for {SECRET_PROVIDERS[tag]}",
            f"The secret belongs to {SECRET_PROVIDERS[tag]}. It stays valid until it is revoked at the "
            "provider, wherever it is used from.",
            "plugin")  # fmt: skip
    return None


@dataclass(frozen=True)
class Reason:
    title: str
    detail: str
    source: str
    tag: str | None = None


def _weak_detail(f: Finding, weak_list: frozenset[str] | None) -> str:
    secret = f.secret or ""
    if secret and len(secret) < 6:
        why = f"The password is {len(secret)} characters long (under 6)."
    elif secret and weak_list is not None and secret.lower() in weak_list:
        why = "The password is on the bundled list of common passwords."
    else:
        return _TAGS["weak-password"].detail
    return why + " The analytics enricher raised the risk to high."


def explain(f: Finding, weak_list: frozenset[str] | None = None,
            thresholds: dict[str, Any] | None = None) -> list[Reason]:  # fmt: skip
    """The reasons ``f`` matters, most important first: the kind, the alert (if any), then each tag.

    ``weak_list`` lets the weak-password reason say which rule matched; ``thresholds`` (the
    detection plugin's settings) lets an alert reason state the rule that fired. Unknown tags
    (third-party plugins) get a generic reason naming the plugin.
    """
    reasons: list[Reason] = [Reason(f"{f.kind.value.replace('_', ' ').capitalize()} ({f.risk} risk)",
                                    KIND_WHY.get(f.kind, ""), "kind")]  # fmt: skip
    if f.kind is Kind.ALERT:
        reasons.append(_alert_reason(f, thresholds or {}))
    for tag in f.tags:
        if f.kind is Kind.ALERT and tag == f.extra.get("detection"):
            continue  # already covered by the alert reason
        info = tag_info(tag)
        if info is None:
            reasons.append(Reason(f"Tag '{tag}'", f"Set by the {f.plugin or 'unknown'} plugin; no description "
                                  "is available.", "plugin", tag))  # fmt: skip
            continue
        detail = _weak_detail(f, weak_list) if tag == "weak-password" else info.detail
        reasons.append(Reason(info.title, detail, info.source, tag))
    if f.confidence < 1.0 and "heuristic" not in f.tags:
        reasons.append(Reason(f"Confidence {f.confidence:.0%}", "The plugin is not certain this is what it "
                              "looks like; check the context.", "plugin"))  # fmt: skip
    return reasons


def _alert_reason(f: Finding, thresholds: dict[str, Any]) -> Reason:
    detection = str(f.extra.get("detection", ""))
    info = _TAGS.get(detection)
    window = f.extra.get("window_seconds", thresholds.get("window"))
    attempts = f.extra.get("attempts")
    rule = {
        "brute-force": f"at least {thresholds.get('bruteforce', 5)} failures from one client to one service",
        "password-spraying": f"failures for at least {thresholds.get('spray', 5)} accounts from one client",
        "targeted-account": f"failures of one account from at least {thresholds.get('targeted', 5)} clients",
        "login-after-failures": "a success within the window after a brute-force or spraying burst",
    }.get(detection)
    parts = [info.detail if info else "A detection rule fired."]
    if rule:
        parts.append(f"Rule: {rule}" + (f" within {float(window):.0f}s." if window else "."))
    if attempts:
        parts.append(f"{attempts} attempts were counted; the frames are listed under related findings.")
    if f.extra.get("note"):
        parts.append(str(f.extra["note"]).capitalize() + ".")
    return Reason(info.title if info else detection or "Alert", " ".join(parts), "detection", detection or None)


def headline(f: Finding) -> str:
    """A short 'why' line for list views: the titles of the tag reasons, or the kind's meaning."""
    titles = [r.title for r in explain(f)[1:]]
    if titles:
        return " · ".join(titles)
    return KIND_WHY.get(f.kind, "")
