# Choosing plugins

Every protocol netcreds-ng understands is a plugin. By default all built-in protocol plugins run. You can run only the ones you name, whole **sets** of them, everything except some, or sets you define yourself.

```bash
netcreds-ng --list-plugins                         # every plugin, its sets, and the resolved sets
```

## Run only some plugins: `-P` / `--plugins`

`-P` takes a comma-separated list of plugin names and set names. Only those plugins run.

```bash
sudo netcreds-ng -i eth0 -P ftp,telnet             # two plugins
sudo netcreds-ng -i eth0 -P databases              # one set
sudo netcreds-ng -i eth0 -P legacy                 # what the original net-creds looked for
sudo netcreds-ng -i eth0 -P databases,remote-access,ftp
netcreds-ng -p capture.pcapng -P all               # everything, opt-in plugins included
```

`-P` can be repeated; the lists are combined. It selects **protocol** plugins only. The two enrichers (`analytics`, `detection`) keep running; turn them off with `--disable`.

## Add and remove: `--enable` / `--disable`

Both accept plugin and set names, are comma separated, and can be repeated. They apply after `-P` (or after the default selection when there is no `-P`):

```bash
sudo netcreds-ng -i eth0 --disable web,keyvalue    # everything except HTTP, HTTP/2 and keyvalue
sudo netcreds-ng -i eth0 -P legacy --disable web   # the legacy set without HTTP
sudo netcreds-ng -i eth0 -P databases --enable ftp # same as -P databases,ftp
netcreds-ng -p cap.pcap --disable detection        # no brute-force/spraying alerts
netcreds-ng -p cap.pcap --enable all               # the default plus every opt-in plugin
```

A name in both `--enable` and `--disable` is disabled. A selection that leaves no protocol plugin is a usage error.

## Built-in sets

| Set | Plugins | For |
| --- | --- | --- |
| `legacy` | ftp, http, irc, kerberos, keyvalue, mail, ntlm, snmp, telnet | what the original net-creds covered |
| `web` | http, http2 | HTTP/1.x and HTTP/2 |
| `email` | mail | SMTP, POP3, IMAP |
| `file-transfer` | ftp | FTP |
| `remote-access` | rdp, telnet, vnc | remote shells and desktops |
| `databases` | mssql, mysql, oracle, postgres, redis | database logins |
| `directory` | kerberos, ldap, ntlm | Windows/AD authentication |
| `aaa` | radius, tacacs | authentication servers |
| `network` | radius, snmp, tacacs | network-device management |
| `chat` | irc | |
| `iot` | mqtt | |
| `voip` | sip | |
| `generic` | keyvalue, secrets | pattern scanners over any cleartext stream |
| `default` | every plugin that is not opt-in | what runs without `-P` |
| `all` | every protocol plugin | |

Sets can overlap: RADIUS is in `aaa` and `network`. Third-party plugins can join any of these sets or declare new ones, so `--list-plugins` is the authoritative list on your machine.

## Your own sets

Define sets in the [configuration file](configuration.md) under `[sets]`. A set lists plugin names and other set names, including your own:

```toml
[sets]
office   = ["email", "web", "ftp"]
servers  = ["databases", "directory", "remote-access"]
everyday = ["office", "servers"]

# naming a built-in set extends it
databases = ["mqtt"]
```

Use them anywhere a set name works: `-P office`, `--disable servers`. To make one the default selection, use `select`:

```toml
[plugins]
select = ["everyday"]           # like -P; a -P on the command line replaces it
disable = ["keyvalue"]          # combined with --disable
```

A set name cannot be a plugin name, `all` or `default`; sets cannot refer to each other in a cycle; every member must be a protocol plugin or a set. Each of these is a usage error naming the problem.

## Opt-in plugins

A plugin can mark itself opt-in (expensive, noisy or specialised plugins). It is left out of `default`, and runs when named with `-P`, `--enable`, a set that contains it, or `-P all` / `--enable all`. None of the built-in plugins is opt-in today.

## Plugins with options

Many plugins have options, such as `--option http.cookies=all` or `--option detection.bruteforce=10`. See [plugin options](../reference/plugin-options.md).

## Writing a plugin that joins a set

```python
class AcmeDbPlugin(ProtocolPlugin):
    name = "acme-db"
    sets = ("databases", "acme")   # joins a built-in set and declares a new one
```

See [protocol plugins](../plugins/protocol-plugins.md).
