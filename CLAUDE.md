# Claude Guidance — attackforge-mcp

MCP server connecting Claude to the AttackForge Self-Service API (SSAPI).
Use during penetration testing engagements to read and update projects,
vulnerabilities, test cases, assets, and reports.

---

## Cache behaviour

Static and slow-changing data is cached in a local SQLite DB
(`~/.attackforge-mcp/cache.db`) to avoid redundant API calls.

| Tool · Action | TTL |
|---|---|
| `utils` · `get_form_config` | 24 h |
| `testsuites` · `list` | 12 h |
| `testsuites` · `get` | 12 h |
| `projects` · `list` | 1 h |

Everything else (vulnerabilities, testcases, assets, analytics, remediation)
is always fetched live.

Call `cache` · `stats` to inspect the cache.
Call `cache` · `invalidate` (with or without a key) to force a refresh.

---

## Key patterns

- **Scope by project** — always pass `project_id` to `vulnerabilities.list`
  and `testcases.list`. Global lists can return 500+ items.
- **Summary → detail** — list actions return slimmed summaries. Call `.get`
  for full text (descriptions, recommendations, steps to reproduce).
- **Rich text** — call `utils` · `markdown_to_richtext` before writing to
  `description`, `attack_scenario`, `remediation_recommendation`, or note
  fields. AF stores rich text in its own format.
- **Escape hatch** — `raw_request` reaches any SSAPI endpoint not covered by
  a named tool. Use it when a named tool does not expose the param you need.

## Response shapes

All list actions return a consistent envelope:

```json
{ "total": N, "shown": N, "has_more": true|false, "<items>": [...] }
```

`has_more: true` means pass a higher `limit` or narrow by `project_id`.
