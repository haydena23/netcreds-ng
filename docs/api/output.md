# Output helpers

## Wire formats (CEF, syslog, chat)

::: netcreds_ng.output.formats
    options:
      heading_level: 3

## Console rendering

::: netcreds_ng.output.console
    options:
      heading_level: 3

## Filter language

The [live table's filter language](../guide/live-table.md#filter-language), usable on any list of findings:

```python
from netcreds_ng.tui.filters import parse_filter

wanted = parse_filter("risk:medium+ -tag:heuristic proto:ldap")
selected = [f for f in findings if wanted(f)]
```

::: netcreds_ng.tui.filters
    options:
      heading_level: 3
      show_docstring_description: false
