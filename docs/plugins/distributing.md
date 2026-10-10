# Distributing plugins

## Discovery

`netcreds_ng.plugins.registry.load_registry()` collects plugin classes from, in order:

1. **built-in modules** listed in `BUILTIN_MODULES`;
2. **entry points** in the `netcreds_ng.plugins` group of installed distributions;
3. **plugin directories**: every `*.py` file in each `--plugin-dir`, in `[plugins] dirs`, and in the user plugin directory (`%APPDATA%\netcreds-ng\plugins` on Windows, `~/.config/netcreds-ng/plugins` elsewhere) if it exists.

A class is registered when it subclasses `ProtocolPlugin`, `EnricherPlugin` or `SinkPlugin` and has a `name`. It is refused, with a *load error* listed by `--list-plugins`, when:

- it has no name;
- its `api_version` is not the current plugin API;
- an earlier source already registered the same name (built-ins cannot be shadowed);
- importing the module or loading the entry point raised an exception.

Load errors never stop the run.

## Drop-in files

For quick experiments and site-specific plugins, put a `.py` file in a directory:

```bash
netcreds-ng -p cap.pcap --plugin-dir ./my-plugins
netcreds-ng --list-plugins --plugin-dir ./my-plugins
```

```text
| acme | protocol | on | file:./my-plugins/acme.py | ACME LOGIN credentials and results (any port) |
```

Every `*.py` file in the directory is imported as its own module (`netcreds_ng_userplugin_<stem>`), so:

- keep tests and helper scripts out of plugin directories: a `test_acme.py` there is imported too, and fails with a load error if it imports something that is not on the path;
- one file can define several plugins (for example an enricher and a sink);
- files cannot import each other by module name; put shared code in an installed package instead.

## Installable packages

For plugins you share, publish a Python package that exposes the plugin class through the `netcreds_ng.plugins` entry-point group:

```toml title="pyproject.toml"
[project]
name = "netcreds-acme"
version = "1.0.0"
requires-python = ">=3.11"
dependencies = ["netcreds-ng>=2.0.0.dev0"]

[project.entry-points."netcreds_ng.plugins"]
acme = "netcreds_acme.plugin:AcmePlugin"
```

An entry point may also point at a module; every plugin class defined in that module is then registered.

After `pip install`, the plugin is available everywhere:

```console
$ pip install netcreds-acme
$ netcreds-ng --list-plugins | grep acme
| acme | protocol | on | entry-point:netcreds-acme | ACME LOGIN credentials and results (any port) |
```

The repository's `examples/netcreds-ng-example-plugin` is a complete, tested package of this kind (a BSD rexec plugin with `ports_only = True`).

## Versioning

- Set your plugin's own `version` class attribute.
- Leave `api_version` at its default (`PLUGIN_API`). If a future netcreds-ng changes the plugin API, it raises `PLUGIN_API`, and your plugin is refused with a clear message instead of failing at run time.
- Depend on a bounded netcreds-ng range in your package metadata.

## Opt-in plugins

Set `opt_in = True` for plugins that are expensive, noisy or specialised. They are listed as `opt-in` by `--list-plugins` and run only when named (`-P <name>`, `--enable <name>`, a set containing them, or `all`).

## Plugin sets

Set `sets = ("databases",)` to join a built-in set, or name a new one; users can then select your plugin with `-P <set>`. Pick set names that do not clash with plugin names (clashes are reported by `--list-plugins` and ignored).

## Security

Plugins are ordinary Python code that runs with the user's privileges, which for live capture means root or administrator. Install plugins only from sources you trust, and keep plugin directories writable only by their owner.
