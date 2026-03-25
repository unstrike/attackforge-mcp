# attackforge-mcp

An MCP server that connects AI assistants (Claude, etc.) to the
[AttackForge](https://attackforge.com) Self-Service API (SSAPI).

---

## vs. the official AttackForge MCP

AttackForge publishes an official MCP server. It exposes a limited subset of
the SSAPI — specifically: `whoami`, `get_file`, `count_projects`,
`count_vulnerabilities`, `count_writeups`, `find_affected_assets`,
`find_projects`, `find_writeups`, `find_vulnerabilities`, and
`get_field_structure`.

This server covers the **full SSAPI** and adds a layer of **context efficiency**
on top, designed specifically for use inside long AI conversations:

| | Official MCP | attackforge-mcp |
|---|---|---|
| API coverage | 10 endpoints | Full SSAPI |
| Response passthrough | Raw API JSON | Slimmed (see below) |
| HTML fields | Returned | Stripped globally (−40–60% size) |
| List responses | Full objects | Summary projection + `total`/`has_more` envelope |
| Static data (form configs, testsuite library, project index) | Re-fetched every call | SQLite cache with TTLs |
| Cache management | — | `cache` tool (stats, invalidate) |
| Escape hatch | — | `raw_request` for any unlisted endpoint |

**Why it matters:** Large tool responses dump hundreds of lines of JSON into
context on every call. Over a multi-step engagement that context fills up fast.
By stripping HTML duplicates, projecting summary fields, and caching data that
never changes mid-engagement, this server keeps each tool response as small as
possible without losing information.

---

## Setup

### Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

### Install

```bash
git clone https://github.com/unstrike/attackforge-mcp
cd attackforge-mcp
uv sync
```

### Configuration

Set two environment variables before starting the server:

| Variable | Description | Default |
|---|---|---|
| `AF_HOSTNAME` | Your AttackForge instance hostname | *(required)* |
| `X_SSAPI_KEY` | Your SSAPI key | *(required)* |

### Run

```bash
AF_HOSTNAME=your.attackforge.com X_SSAPI_KEY=your-key uv run attackforge-mcp
```

Or add to your MCP client config (e.g. Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "attackforge-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/attackforge-mcp", "attackforge-mcp"],
      "env": {
        "AF_HOSTNAME": "your.attackforge.com",
        "X_SSAPI_KEY": "your-key"
      }
    }
  }
}
```

---

## Tools

| Tool | What it does |
|---|---|
| `projects` | List, get, create, update, clone, archive projects and notes |
| `vulnerabilities` | List, get, create, update, bulk-create vulnerabilities |
| `testsuites` | Browse and manage the testsuite library |
| `testcases` | List, assign, update test cases on a project |
| `assets` | Manage project and library assets |
| `remediation` | Create and update remediation notes on vulnerabilities |
| `reports` | Generate and retrieve project reports |
| `analytics` | Failed testcases, vulnerable assets, common vulnerabilities |
| `utils` | Markdown → rich text conversion; form config lookup |
| `cache` | Inspect and invalidate the local SQLite cache |
| `raw_request` | Direct access to any SSAPI endpoint |

See `CLAUDE.md` for usage patterns.
