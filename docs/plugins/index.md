# Plugins

Everything netcreds-ng detects or writes is a plugin. The 23 protocol parsers, the two enrichers and the nine outputs are built-in plugins written against the same public API you can use.

| Kind | Base class | Purpose | Examples |
| --- | --- | --- | --- |
| Protocol | `ProtocolPlugin` | inspect reassembled TCP streams and UDP datagrams; emit findings | `ftp`, `http`, `kerberos` |
| Enricher | `EnricherPlugin` | annotate findings (tags, risk) and raise new ones, before outputs | `analytics`, `detection` |
| Sink | `SinkPlugin` | write findings somewhere | `jsonl`, `sqlite`, `webhook` |

The API is versioned: **plugin API 1** (`netcreds_ng.plugins.api.PLUGIN_API`). A plugin whose `api_version` differs is refused at load time with a message in `--list-plugins`.

## Guides

1. **[Protocol plugins](protocol-plugins.md)**: a complete walkthrough, from a first plugin to login results, gaps, look-alike protocols, UDP and TLS.
2. **[Enrichers and sinks](enrichers-and-sinks.md)**: annotate findings, add outputs.
3. **[Testing plugins](testing.md)**: build traffic in Python, run it through the real engine, test segmentation, gaps and TLS.
4. **[Distributing plugins](distributing.md)**: drop-in files, installable packages with entry points, and how discovery works.

The [Plugin API reference](../api/plugin-api.md) is generated from the source.

## Scope for plugins

netcreds-ng is a defensive exposure-auditing tool, and plugins are expected to stay within that scope:

- report cleartext credentials and secrets exactly as they crossed the wire, because that is the exposure;
- report challenge/response or encrypted authentication as an `AUTH_EVENT` with metadata only (user, mechanism, strength). Never put digests, nonces, responses, tickets or ciphertext in a finding, and never derive identifiers from them.

## Example plugin package

The repository contains an installable third-party plugin in `examples/netcreds-ng-example-plugin`. It reports BSD **rexec** (TCP 512) logins, which carry the password in cleartext:

```bash
pip install ./examples/netcreds-ng-example-plugin
netcreds-ng --list-plugins      # shows "rexec" with source entry-point:netcreds-ng-example-plugin
pytest examples/netcreds-ng-example-plugin/tests
```
