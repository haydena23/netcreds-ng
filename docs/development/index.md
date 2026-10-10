# Development

## Set up

```bash
git clone https://github.com/haydena23/netcreds-ng.git
cd netcreds-ng
python -m venv .venv
.venv/bin/pip install -e ".[dev]"        # Windows: .venv\Scripts\pip install -e ".[dev]"
```

The `dev` extra installs `cryptography`, `pytest`, `hypothesis`, `ruff` and `mypy`.

## Checks

Run these before every change is considered done. CI runs them on Python 3.11–3.14 on Linux, Windows and macOS (`.github/workflows/ci.yml`), plus the example plugin's tests.

```bash
python -m pytest -q                 # the full suite
python -m ruff check src tests tools
python -m mypy                      # configured in pyproject.toml
```

Useful variations:

```bash
python -m pytest -q tests/test_proto_ldap.py         # one protocol
python -m pytest -q -k "gap or retrans"              # by name
python -B -m pytest -q -p no:cacheprovider           # leave no cache files behind
```

## Repository layout

| Path | Contents |
| --- | --- |
| `src/netcreds_ng/` | the package; see the [module map](../architecture/index.md#module-map) |
| `src/netcreds_ng/data/weak_passwords.txt` | the weak-password list used by `analytics` |
| `tests/` | the test suite |
| `tests/fixtures/synthetic/` | generated captures with fake credentials |
| `tests/golden/legacy/` | output recorded from the original net-creds |
| `test/` | third-party sample captures, compared by digest only |
| `tools/` | fixture generator, golden recorder, Python 2 oracle shim, benchmark |
| `examples/netcreds-ng-example-plugin/` | an installable third-party plugin |
| `docs/` | this documentation |

## Tests

| Test module | Covers |
| --- | --- |
| `test_engine_core.py` | capture I/O, decoding, TCP reassembly and IP defragmentation |
| `test_platform.py` | registry, plugin sets, plugin isolation, pipeline and dedup, enrichers, robustness |
| `test_plugins_core.py` | exact expected findings for each synthetic fixture |
| `test_proto_*.py` | one module per protocol plugin added in netcreds-ng |
| `test_cross_protocol.py` | with every plugin enabled, each fixture triggers only the plugins that own its protocol |
| `test_cross_protocol_ng.py` | the same cross-protocol matrix for the protocols netcreds-ng added |
| `test_superset_parity.py` | the parity floor: every exposure the original reports is also found by the new engine |
| `test_legacy_parity.py` | `--legacy` output byte for byte against the goldens |
| `test_tls.py` | TLS decryption checked against real OpenSSL sessions (in memory, no sockets) |
| `test_detection.py` | behavioural detections, service inventory and host scores |
| `test_heuristics.py` | Telnet heuristic evidence and strict mode |
| `test_evidence.py` | evidence pcapng export and the pcapng writer |
| `test_integrations.py` | CEF, syslog and chat webhooks; no traffic leaves the process |
| `test_jobs.py` | parallel analysis gives the same result as a sequential run |
| `test_cli.py` | end-to-end CLI behaviour, in-process and as a real subprocess |
| `test_tui.py`, `test_filters.py` | headless live-table tests (Textual pilot) and the filter language |
| `test_hpack.py` | HPACK decoder: RFC 7541 Appendix C examples and malformed input |
| `test_review_regressions.py` | regressions found by the independent protocol review |

Robustness tests use [Hypothesis](https://hypothesis.readthedocs.io/): random bytes, random segmentations and truncated captures must never crash the engine or make a plugin raise.

## Fixtures

```bash
python tools/gen_fixtures.py
```

regenerates `tests/fixtures/synthetic/`. Output is byte-identical between runs. Fixtures use documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`) and obviously fake credentials. Never commit real captures or real credentials.

After changing fixtures, re-record the legacy goldens; see [Parity testing](parity.md).

## Benchmarks

```bash
python tools/bench.py --flows 20000                    # generate a capture and time the analysis
python tools/bench.py --pcap capture.pcapng --profile  # profile an existing capture (cProfile top 25)
python tools/bench.py --pcap a.pcap --pcap b.pcap --jobs 2
```

The generated capture mixes credential-bearing protocols with bulk binary and HTTP traffic. Run it before and after engine or plugin changes to catch throughput regressions.

## Real-traffic validation

```bash
python tools/corpus.py fetch && python tools/corpus.py run
```

Runs every plugin over public sample captures and compares the results with tshark. See [Real-traffic validation](real-traffic.md).

## Adding a protocol

See [Adding a built-in plugin](../plugins/protocol-plugins.md#adding-a-built-in-plugin).

## Building the documentation

The site is built with [MkDocs](https://www.mkdocs.org/) and [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/); the API pages are generated from docstrings by [mkdocstrings](https://mkdocstrings.github.io/).

```bash
pip install -e ".[docs]"
mkdocs serve              # live preview at http://127.0.0.1:8000
mkdocs build --strict     # build into site/, failing on warnings (broken links, bad references)
```

Sources are Markdown files in `docs/`, the navigation is in `mkdocs.yml`. API pages contain `::: module.name` directives; improving a docstring improves the API reference.

The `docs` GitHub Actions workflow (`.github/workflows/docs.yml`) builds the site with `--strict` on every push and pull request, and publishes it to GitHub Pages from the default branch once Pages is enabled for the repository (Settings → Pages → Source: GitHub Actions).

When you change behaviour, update the page that describes it: the [protocol reference](../reference/protocols.md) for plugins, the [CLI reference](../reference/cli.md) for options, the [outputs reference](../reference/outputs.md) for formats.

## Conventions

- Python 3.11+, typed; `ruff` with the rules in `pyproject.toml`, line length 120.
- Wire data stays `bytes` until a finding is built. See [Design principles](../architecture/principles.md).
- Bounded dependency versions in `pyproject.toml`; pure-Python or prebuilt-wheel dependencies only.
- Features that send data over the network must be opt-in.
