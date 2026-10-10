# API reference

This reference is generated from the source code and its docstrings. It covers the modules you use to write plugins, embed netcreds-ng in other tools, or work on the engine.

| Page | Modules | Use it to |
| --- | --- | --- |
| [Data model](model.md) | `netcreds_ng.model` | read and build findings and run statistics |
| [Plugin API](plugin-api.md) | `netcreds_ng.plugins.api` | write protocol, enricher and sink plugins |
| [Plugin registry](registry.md) | `netcreds_ng.plugins.registry` | discover and select plugins |
| [Session](session.md) | `netcreds_ng.session` | run an analysis from Python |
| [Engine](engine.md) | `netcreds_ng.engine.engine`, `.pipeline`, `.tcp`, `.ipfrag`, `.decode` | work on the packet engine |
| [Capture I/O](capture-io.md) | `netcreds_ng.engine.pcapio`, `.sources` | read and write captures, live capture |
| [TLS](tls.md) | `netcreds_ng.engine.tls` | TLS key logs and decryption |
| [Output helpers](output.md) | `netcreds_ng.output.*`, `netcreds_ng.tui.filters` | console rendering, SIEM formats, filters |
| [Protocol parsers](proto.md) | `netcreds_ng.proto.*`, `plugins.protocols._util` | shared parsers and helpers for plugins |
| [Configuration](config.md) | `netcreds_ng.config` | read configuration files |
| [Testing SDK](testing.md) | `netcreds_ng.testing.*` | build traffic and test plugins |

**Stability.** The plugin API (`netcreds_ng.plugins.api`, version `PLUGIN_API = 1`), `netcreds_ng.model`, `netcreds_ng.session` and `netcreds_ng.testing` are the supported surface for third-party code. Engine internals may change between releases. Names starting with an underscore are private and are not documented here.

## Embedding example

```python
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig

findings = []
config = SessionConfig(disable=["keyvalue"], plugin_options={"http": {"cookies": "off"}})
session = Session(load_registry(), config, listeners=[findings.append])
session.open()
session.run_files(["capture.pcapng"])
session.close()

for f in findings:
    print(f.to_dict())
```
