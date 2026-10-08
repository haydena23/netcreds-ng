# netcreds-ng example plugin

An installable third-party plugin for netcreds-ng that reports BSD **rexec** (TCP 512) logins, which carry the password in cleartext.

```bash
pip install ./examples/netcreds-ng-example-plugin
netcreds-ng --list-plugins      # shows "rexec" with source entry-point:netcreds-ng-example-plugin
pytest examples/netcreds-ng-example-plugin/tests
```

See ../../docs/PLUGINS.md for the plugin API.
