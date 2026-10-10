# Installation

## Requirements

- **Python 3.11 or newer.** CI covers 3.11 to 3.14 on Linux, Windows and macOS.
- **For live capture only:** a packet-capture driver (Npcap on Windows) and permission to capture: root or `CAP_NET_RAW` on Linux and macOS; on Windows only if Npcap is set to "administrators only". Reading capture files needs neither.

  | Platform | Driver |
  | --- | --- |
  | Windows | [Npcap](https://npcap.com/) |
  | Linux | libpcap (usually preinstalled) |
  | macOS | libpcap (preinstalled) |

## Install

From a checkout of the repository:

=== "Standard"

    ```bash
    pip install .
    ```

=== "With TLS decryption"

    ```bash
    pip install ".[tls]"
    ```

    Adds the `cryptography` package, needed for [`--tls-keylog`](../guide/tls-decryption.md).

=== "Development"

    ```bash
    python -m venv .venv
    .venv/bin/pip install -e ".[dev]"      # Windows: .venv\Scripts\pip install -e ".[dev]"
    ```

    Adds `cryptography`, `pytest`, `hypothesis`, `ruff` and `mypy`. See [Development](../development/index.md).

=== "Documentation"

    ```bash
    pip install ".[docs]"
    mkdocs serve
    ```

    Builds this site. See [Building the documentation](../development/index.md#building-the-documentation).

Using a virtual environment or `pipx` keeps netcreds-ng's dependencies separate from the rest of your system:

```bash
pipx install .
```

## Dependencies

All dependencies are pure Python or ship prebuilt wheels, so no compiler is needed.

| Package | Used for |
| --- | --- |
| `rich` | console output and tables |
| `textual` | the live table (`--tui`) |
| `scapy` | live capture only; capture files are read by netcreds-ng's own reader |
| `psutil` | network interface discovery (`--list-interfaces`) |
| `cryptography` | TLS decryption (optional `[tls]` extra) |

Version ranges are bounded in `pyproject.toml`.

## Check the installation

```console
$ netcreds-ng --version
netcreds-ng 2.0.0.dev0
$ netcreds-ng --list-plugins
```

`--list-plugins` prints every protocol, enricher and output plugin with its source. If any plugin failed to load, the error is printed below the table. See the [output in the CLI reference](../reference/cli.md#-list-plugins).

You can also run the package as a module, which is handy inside a virtual environment that is not activated:

```bash
python -m netcreds_ng --version
```

## Live capture setup

=== "Linux"

    Run as root. netcreds-ng checks for an effective user ID of 0, so granting capture capabilities (`setcap`) to the interpreter is not enough on its own.

    ```bash
    sudo netcreds-ng -i eth0
    ```

=== "macOS"

    ```bash
    sudo netcreds-ng -i en0
    ```

=== "Windows"

    Install [Npcap](https://npcap.com/). A standard install lets any user capture; if you chose "administrators only", run from an Administrator terminal:

    ```powershell
    netcreds-ng                      # capture on the default interface
    netcreds-ng --list-interfaces
    netcreds-ng -i "Wi-Fi"
    ```

netcreds-ng checks that it can capture before it starts, and the error message says what is missing. See [Live capture](../guide/live-capture.md).
