# Design principles

These rules shape every part of netcreds-ng. Follow them in changes and plugins.

## Defensive scope

netcreds-ng is an exposure-auditing tool. It reports cleartext credentials in full because that is the exposure, and it reports weak authentication hygiene. It does not do offensive work:

- no cracking, no hashcat/John export, no hash-mode tagging;
- no Kerberos roasting extraction;
- no tooling to test whether captured material is crackable;
- challenge/response material (digests, nonces, responses, tickets, salts) is never placed in a finding, and identifiers are never derived from it. The NTLM `event_id`, for example, hashes only endpoints, time, frame and identity, never the message that contains the NT response;
- secrets protected by a shared key (RADIUS, TACACS+) are never decrypted and the key is never guessed;
- password-reuse fingerprints use a fresh random key per run, so they cannot be used to test guesses.

Features that send data over the network (webhook, syslog) are opt-in: nothing is sent unless the user names the output.

## Bytes on the wire, text at the edge

Wire data stays `bytes` through decoding, reassembly and parsing. It is decoded to `str` only when a finding is built, with `_util.text()`: UTF-8 with undecodable bytes shown as `\xNN`. Nothing is lost or silently replaced.

## Correct before clever

- Every length field is bounds-checked; every buffer has a cap.
- TCP is reassembled byte-exactly: wraparound, retransmissions, overlaps, out-of-order segments.
- Bytes from both sides of a capture gap are never joined into a reported value.
- IP fragments, VLANs, PPPoE, IPv6 extension headers and jumbograms are handled, so credentials are not missed because of how the network was built.

## Nothing dropped silently

Every problem is counted and shown: undecodable and truncated frames, gaps, retransmissions, evicted flows, ambiguous directions, TLS sessions without keys, plugin exceptions, capture-file errors, dropped live packets. `--strict` turns problems into a non-zero exit code. Plugin errors are isolated per plugin and per flow so one bug never hides the rest of the results.

## Deterministic

The same input gives the same findings in the same order: plugins and enrichers run in `(priority, name)` order, directories are read in name order, parallel results are published in file order, and timestamps come from the capture, not the clock. The only intended difference between two runs is `secret_fingerprint`.

## Detect by content

Plugins see every flow, not only those on their standard port, and decide from the content. Port numbers are hints for client/server roles. Look-alike protocols (USER/PASS in FTP, POP3 and IRC; AUTH in SMTP, IMAP and Redis) are told apart by greetings, command shapes and who speaks first.

## The original is the floor

Everything the original net-creds reported is still reported, which the parity tests check against output recorded from the original under Python 2. Its exact output is available with `--legacy`. Intentional differences outside legacy mode are documented.
