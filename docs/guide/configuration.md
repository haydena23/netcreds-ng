# Configuration

Every setting can be given on the command line. Settings you use every time can live in a TOML file instead.

## Where configuration is read from

netcreds-ng loads **one** configuration file, the first it finds:

1. the file given with `--config FILE` (an error if it does not exist);
2. `netcreds-ng.toml` in the current directory;
3. `.netcreds-ng.toml` in the current directory;
4. the user configuration file:

    | Platform | Location |
    | --- | --- |
    | Windows | `%APPDATA%\netcreds-ng\config.toml` |
    | Linux/macOS | `$XDG_CONFIG_HOME/netcreds-ng/config.toml`, by default `~/.config/netcreds-ng/config.toml` |

Files are not merged: a project file in the current directory replaces the user file entirely. An unreadable or invalid file stops the run with `[ERROR] cannot read config: ...` and exit code 1.

## A complete example

```toml title="netcreds-ng.toml"
[plugins]
enable = ["all"]               # include opt-in plugins
disable = ["keyvalue"]         # merged with --disable
dirs = ["./my-plugins"]        # extra plugin directories, merged with --plugin-dir

[plugins.http]                 # options for the http plugin
cookies = "all"                # session | all | off
urls = true

[plugins.telnet]
strict = true                  # same as --strict-heuristics for telnet

[plugins.detection]
bruteforce = 10                # failed logins from one client to one service...
window = 600                   # ...within this many seconds

[output]
mask = true                    # same as --mask
dedup = "run"                  # off | run | persistent
dedup_db = "state.sqlite3"     # for dedup = "persistent"
tls_keylog = "keys.log"        # same as --tls-keylog
jsonl = "findings.jsonl"       # any of: jsonl csv log sqlite html evidence cef
html = "report.html"

[output.html]                  # options for the html output
include_secrets = false

[output.webhook]
url = "https://hooks.slack.com/services/..."
format = "slack"               # generic | slack | teams | discord
min_risk = "high"

[output.syslog]
url = "udp://siem.example:514"
format = "cef"                 # cef | json
```

## How the file maps to options

### `[plugins]`

| Key | Type | Meaning |
| --- | --- | --- |
| `enable` | list of names | plugins to enable; `"all"` enables opt-in plugins too |
| `disable` | list of names | plugins to disable |
| `dirs` | list of paths | directories to load `*.py` plugins from |
| `tls_keylog` | path | accepted as an alternative to `[output] tls_keylog` |

Each `[plugins.<name>]` table holds options for that plugin or enricher. See [plugin options](../reference/plugin-options.md) for the full list.

### `[output]`

| Key | Type | Meaning |
| --- | --- | --- |
| `mask` | bool | mask secrets on screen and in outputs |
| `dedup` | string | `off`, `run` or `persistent` |
| `dedup_db` | path | state file for persistent dedup |
| `tls_keylog` | path | NSS key-log file |
| `jsonl`, `csv`, `log`, `sqlite`, `html`, `evidence`, `cef` | path | write that output |
| `webhook` | URL, or a table with `url` | enable the webhook output |
| `syslog` | URL, or a table with `url` | enable the syslog output |

Any `[output.<name>]` table is passed to the output plugin `<name>` as options (except `url`, which is the target). `[output.html]` and `[plugins.html]` are equivalent; the `[output]` form reads better for outputs.

## Precedence

Command-line options win over the file:

| Setting | Rule |
| --- | --- |
| output paths, webhook and syslog URLs | the command-line value if given, otherwise the file |
| `--mask` | on if either the command line or the file turns it on |
| `--dedup`, `--dedup-db`, `--tls-keylog` | the command-line value if given, otherwise the file |
| `--enable`, `--disable`, `--plugin-dir` | the command line and the file are **combined** |
| `--option plugin.key=value` | overrides the same key from the file |
| `--webhook-format` | overrides `format` from the file |

A plugin in both `enable` and `disable` is disabled.

## Plugin options on the command line

`--option` sets one plugin option and can be repeated:

```bash
netcreds-ng -p cap.pcap --option http.cookies=all --option detection.bruteforce=10
```

The value is parsed as a TOML value when possible, so `10` is an integer, `true` a boolean, and `[1, 2]` a list. Anything else is taken as a string, so `all` needs no quotes. Quote a value that would otherwise parse as another type, for example `--option 'syslog.hostname="1234"'`.

Options for outputs use the output's name: `--option html.include_secrets=true`, `--option webhook.batch=50`, `--option evidence.after=32`.

## Choosing plugins

```bash
netcreds-ng --list-plugins                              # names, kinds, default state and source
netcreds-ng -p cap.pcap --disable keyvalue,secrets      # comma separated, repeatable
netcreds-ng -p cap.pcap --enable all                    # also enable opt-in plugins
```

Plugins are selected by name across all kinds, so `--disable detection` turns off the behavioural alerts and `--disable analytics` turns off weak-password and reuse analysis. An unknown name, on the command line or in the config file, is a usage error (exit code 2) that names it: `unknown plugin(s): ... (see --list-plugins)`.

## Plugin directories

Plugins are loaded from, in this order:

1. the built-in plugins;
2. installed packages that declare the `netcreds_ng.plugins` entry point;
3. `*.py` files in `--plugin-dir` directories and `[plugins] dirs`;
4. `*.py` files in the user plugin directory, if it exists:

    | Platform | Location |
    | --- | --- |
    | Windows | `%APPDATA%\netcreds-ng\plugins` |
    | Linux/macOS | `~/.config/netcreds-ng/plugins` |

A later source cannot replace a plugin name an earlier one already provides; the conflict is listed as a load error in `--list-plugins`. See [distributing plugins](../plugins/distributing.md).

!!! danger "Plugin files are code"

    Plugin directories hold Python files that run with your privileges, and live capture runs as root or administrator. Keep these directories writable only by you.
