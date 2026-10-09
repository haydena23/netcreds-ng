# Parity testing

netcreds-ng promises two things about the original net-creds:

1. **`--legacy` reproduces its output byte for byte**: stdout and `credentials.txt`.
2. **Everything it reported is still reported** in normal mode, as structured findings.

Both are tested against output recorded from the *unmodified* original, run under Python 2.

## The oracle

`tools/py2_oracle.py` runs the original `net-creds.py` under Python 2.7 with scapy 2.4.4. It applies two shims, both outside the original file:

- `os.geteuid` is stubbed on Windows (it is imported at module load but never called in `-p` mode);
- `--raw-tcp` clears scapy's TCP payload bindings so every TCP payload is a `Raw` layer, as on the scapy 2.3 the original was written for. Newer scapy versions dissect SMB, NetBIOS and others and would hide those payloads from it.

## Recording goldens

```bash
python tools/make_goldens.py --py2 /path/to/python2.7 --original ../net-creds/net-creds.py
```

This runs the oracle on every capture and writes:

| File | Contents |
| --- | --- |
| `tests/golden/legacy/synthetic/<fixture>.stdout` and `.log` | plaintext goldens for the synthetic fixtures (fake values only) |
| `tests/golden/legacy/real.json` | SHA-256 digests of the output for the third-party sample captures in `test/`, so their contents are never stored |

Outputs are newline-normalised: Python 2 text mode on Windows wrote CRLF, and CRLF → LF is its exact inverse.

Python 2 and the original are needed only to *record* goldens. Running the tests needs neither.

## The tests

- `tests/test_legacy_parity.py` runs `--legacy` on every synthetic fixture and compares stdout and the log byte for byte with the goldens, and compares digests for the real captures.
- `tests/test_superset_parity.py` checks that normal mode reports, as findings, everything the original reported for each fixture.

## Documented deviations

The few places where `--legacy` cannot or should not match Python 2 literally are listed in [Legacy mode](../guide/legacy.md#documented-deviations-from-python-2) and in the `netcreds_ng.legacy` module docstring.
