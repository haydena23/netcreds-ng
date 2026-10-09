# About

netcreds-ng finds the credentials and weak authentication a network exposes, so defenders can fix them.

## History

netcreds-ng is the Python 3 successor of [net-creds](https://github.com/DanMcInerney/net-creds) by Dan McInerney, a Python 2 tool that sniffed passwords and hashes from an interface or a capture file. Version 2.0 is a complete rewrite: a real packet engine with TCP reassembly, a plugin system, structured findings, many more protocols, TLS decryption, analytics and integrations. The original's behaviour is the floor, verified by tests against its recorded output, and `--legacy` reproduces it exactly.

## Scope

netcreds-ng is a defensive, blue-team auditing tool. It reports cleartext credentials and authentication weaknesses seen on the wire. It does not crack passwords, export hashes for cracking, extract Kerberos tickets for roasting, or test whether captured material is crackable. Network outputs are opt-in and mask secrets by default. See [Design principles](../architecture/principles.md#defensive-scope).

## Responsible use

Only analyse traffic you are authorised to inspect. Captures, evidence files, key logs and outputs contain real credentials: store them securely, use `--mask` for reports you share, and delete what you no longer need.

## License

netcreds-ng is licensed under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See the `LICENSE` file in the repository.

## Links

- Source code and issues: <https://github.com/haydena23/netcreds-ng>
- Original net-creds: <https://github.com/DanMcInerney/net-creds>
