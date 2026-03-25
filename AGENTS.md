# Agent Coding Guide — attackforge-mcp

Guidelines for AI agents modifying this codebase.

---

## Adding a tool

1. Decorate with `@mcp.tool()` in `server.py`.
2. Use a single `action: str` parameter plus named optional params.
   Do **not** create one top-level tool per SSAPI endpoint.
3. Write a docstring that lists every action, its required/optional params,
   and the SSAPI path it calls. Claude reads these at runtime.

## Adding a cached action

Use the explicit cache-check pattern already present in `projects.list`,
`testsuites.get`, etc. Do **not** add middleware or decorators.

```python
cache_key = "tool:action:discriminator"
data = _cache.get(cache_key)
if data is None:
    data = await client.request("GET", "/endpoint")
    _cache.set(cache_key, data, ttl=N)
return data
```

Cache key format: `{tool}:{action}` or `{tool}:{action}:{id}`.

Only cache data that is static or slow-changing. **Never** cache responses
to write operations (POST / PUT / DELETE).

## Field projection

For list actions that could return large payloads, define a `_SUMMARY_KEYS`
set near the top of `server.py` and slice to it before returning. Always
wrap the result in `{ "total", "shown", "has_more", "<items>" }`.

## Constraints

- Do not hold a persistent DB connection — `cache.py` opens and closes per
  call by design (SQLite, single-process, no pooling needed).
- Do not add HTML-stripping logic — `client.strip_html_keys` handles this
  globally on every API response.
- Do not cache active engagement data: vulnerabilities, testcases, assets,
  remediation notes, or analytics.
