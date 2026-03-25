"""AttackForge MCP server."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import cache as _cache
from . import client

# Summary fields returned by projects.list — use projects.get for full detail.
_PROJECT_SUMMARY_KEYS = {
    "project_id",
    "project_name",
    "project_code",
    "project_status",
    "project_start_date",
    "project_end_date",
    "project_groups",
    "project_total_vulnerabilities",
    "project_open_vulnerabilities",
    "project_custom_fields",
}

# Summary fields for vulnerabilities.list — strips long text bodies and redundant fields.
# vulnerability_tags omitted: CVSS data is already in cvssv3_vector + cvssv3_base_score.
# Use vulnerabilities.get for full detail on a specific finding.
_VULN_SUMMARY_KEYS = {
    "vulnerability_id",
    "vulnerability_alternate_id",
    "vulnerability_title",
    "vulnerability_priority",
    "vulnerability_status",
    "vulnerability_status_updated",
    "vulnerability_retest",
    "vulnerability_is_zeroday",
    "vulnerability_project_id",
    "vulnerability_project_name",
    "vulnerability_project_code",
    "vulnerability_affected_asset_id",
    "vulnerability_affected_asset_name",
    "vulnerability_cvssv3_base_score",
    "vulnerability_cvssv3_vector",
    "vulnerability_user",
    "vulnerability_created",
    "vulnerability_modified",
    "vulnerability_custom_fields",
    "vulnerability_library_id",
}

# Summary fields for assets.list — strips audit timestamps.
_ASSET_SUMMARY_KEYS = {"id", "asset", "belongs_to_projects"}

# Summary fields for testcases.list — drops audit metadata (created, locked,
# last_updated, last_updated_by) which add ~115 chars/item with no triage value.
_TESTCASE_SUMMARY_KEYS = {
    "id",
    "testcase",
    "status",
    "tags",
    "is_failed",
    "is_remediated",
    "testsuite",
    "linked_vulnerabilities",
    "notes",
}

# Max items returned by analytics list actions.
_ANALYTICS_LIST_LIMIT = 50

# Form config field keys that are removed when null/empty to reduce noise.
_FORM_NULL_KEYS = {"custom_field_script", "custom_field_value"}
_FORM_EMPTY_ARRAY_KEYS = {
    "custom_field_edit_roles",
    "custom_field_edit_groups",
    "custom_field_edit_users",
    "custom_field_view_roles",
    "custom_field_view_groups",
    "custom_field_view_users",
}


def _slim_form_field(cfg: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in cfg.items():
        if k in _FORM_NULL_KEYS and (v is None or v == ""):
            continue
        if k in _FORM_EMPTY_ARRAY_KEYS and v == []:
            continue
        out[k] = v
    return out


def _slim_form_config(sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for section in sections:
        if section.get("type") == "custom" and "config" in section:
            section = {**section, "config": _slim_form_field(section["config"])}
        elif "config" in section:
            sc = section["config"]
            slimmed_fields = []
            for f in sc.get("fields", []):
                if f.get("type") == "custom" and "config" in f:
                    f = {**f, "config": _slim_form_field(f["config"])}
                slimmed_fields.append(f)
            section = {**section, "config": {**sc, "fields": slimmed_fields}}
        result.append(section)
    return result


mcp = FastMCP("attackforge-mcp")


# ---------------------------------------------------------------------------
# Escape hatch
# ---------------------------------------------------------------------------


@mcp.tool()
async def raw_request(
    method: str,
    endpoint: str,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> Any:
    """
    Make a raw request to any AttackForge SSAPI endpoint.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, PATCH)
        endpoint: SSAPI path, e.g. "/vulnerabilities" or "/project/123/testcases"
        params: Optional query string parameters
        body: Optional JSON request body
    """
    return await client.request(method, endpoint, params=params, body=body)


# ---------------------------------------------------------------------------
# projects
# ---------------------------------------------------------------------------


@mcp.tool()
async def projects(
    action: str,
    id: str | None = None,
    fields: dict[str, Any] | None = None,
    note_id: str | None = None,
    note_content: str | None = None,
    limit: int | None = None,
) -> Any:
    """
    Manage AttackForge projects.

    Actions:
      list        — GET /projects (summary; optional: limit default 25)
                    Returns total + has_more. Use projects.get for full detail.
      get         — GET /project/:id  (requires: id)
      create      — POST /project  (requires: fields)
      update      — PUT /project/:id  (requires: id, fields)
      clone       — POST /project/:id/clone  (requires: id)
      archive     — PUT /project/:id/archive  (requires: id)
      restore     — PUT /project/:id/restore  (requires: id)
      get_notes   — GET /project/:id/notes  (requires: id)
      create_note — POST /project/:id/note  (requires: id, note_content)
      update_note — PUT /project/:id/note/:noteId  (requires: id, note_id, note_content)
      workspace   — GET /project/:id/workspace  (requires: id)
    """
    match action:
        case "list":
            data = _cache.get("projects:list")
            if data is None:
                data = await client.request("GET", "/projects")
                _cache.set("projects:list", data, ttl=3600)
            projects_list = data.get("projects", [])
            cap = limit if limit is not None else 25
            slimmed = [
                {k: v for k, v in p.items() if k in _PROJECT_SUMMARY_KEYS}
                for p in projects_list[:cap]
            ]
            return {
                "total": data.get("count", len(projects_list)),
                "shown": len(slimmed),
                "has_more": len(projects_list) > cap,
                "projects": slimmed,
            }
        case "get":
            return await client.request("GET", f"/project/{id}")
        case "create":
            return await client.request("POST", "/project", body=fields)
        case "update":
            return await client.request("PUT", f"/project/{id}", body=fields)
        case "clone":
            return await client.request(
                "POST", f"/project/{id}/clone", body=fields or {}
            )
        case "archive":
            return await client.request("PUT", f"/project/{id}/archive")
        case "restore":
            return await client.request("PUT", f"/project/{id}/restore")
        case "get_notes":
            return await client.request("GET", f"/project/{id}/notes")
        case "create_note":
            return await client.request(
                "POST", f"/project/{id}/note", body={"note": note_content}
            )
        case "update_note":
            return await client.request(
                "PUT", f"/project/{id}/note/{note_id}", body={"note": note_content}
            )
        case "workspace":
            return await client.request("GET", f"/project/{id}/workspace")
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# vulnerabilities
# ---------------------------------------------------------------------------


@mcp.tool()
async def vulnerabilities(
    action: str,
    id: str | None = None,
    project_id: str | None = None,
    asset_name: str | None = None,
    fields: dict[str, Any] | None = None,
    items: list[dict[str, Any]] | None = None,
    limit: int | None = None,
) -> Any:
    """
    Manage AttackForge vulnerabilities.

    Actions:
      list                    — GET /vulnerabilities  (summary only; optional: project_id, limit default 25)
                                Prefer project_id scope — global list can return 500+ items.
                                Returns total + has_more. Use get for full text fields.
      get                     — GET /vulnerability/:id  (requires: id; returns full detail)
      list_by_asset           — GET /vulnerabilities/asset  (requires: asset_name)
      create                  — POST /vulnerability  (requires: fields incl. project_id)
      update                  — PUT /vulnerability/:id  (requires: id, fields)
      bulk_create             — POST /vulnerability/bulk  (requires: project_id, items=[{...},...])
      summarize_custom_fields — Scan all vulns in a project and return each custom field key
                                with its distinct non-empty values.  (requires: project_id)
                                Optional: fields={"key": "apmid"} to filter to one field.
                                Use this to discover what custom fields an org uses before
                                querying by value — works for any AF instance, not just T-Mobile.
      list_by_custom_field    — Return slimmed vuln summaries where a custom field matches a value.
                                (requires: project_id, fields={"key": "...", "value": "..."})
                                Optional: limit (default 25).

    Key fields for create: projectId (camelCase, required), title (required),
      affected_asset_name (required), priority (required), description (required),
      attack_scenario (required), remediation_recommendation (required),
      steps_to_reproduce (required), tags, notes=[{note, type}], is_zeroday,
      is_visible, custom_fields=[{key, value}], linked_testcases,
      custom_tags=[{name, value}].
    Key fields for update: project_id (snake_case), title, priority, status,
      likelihood_of_exploitation, description, attack_scenario,
      remediation_recommendation, steps_to_reproduce, tags, notes=[{note, type}],
      is_zeroday, is_visible, is_deleted, custom_fields=[{key, value}],
      linked_testcases, custom_tags=[{name, value}].
    """
    match action:
        case "list":
            if project_id:
                data = await client.request(
                    "GET", f"/project/{project_id}/vulnerabilities"
                )
            else:
                data = await client.request("GET", "/vulnerabilities")
            vulns = data.get("vulnerabilities", [])
            cap = limit if limit is not None else 25
            slimmed = [
                {k: v for k, v in vuln.items() if k in _VULN_SUMMARY_KEYS}
                for vuln in vulns[:cap]
            ]
            return {
                "total": data.get("count", len(vulns)),
                "shown": len(slimmed),
                "has_more": len(vulns) > cap,
                "vulnerabilities": slimmed,
            }
        case "get":
            return await client.request("GET", f"/vulnerability/{id}")
        case "list_by_asset":
            return await client.request(
                "GET", "/vulnerabilities/asset", params={"asset": asset_name}
            )
        case "create":
            return await client.request("POST", "/vulnerability", body=fields)
        case "update":
            return await client.request("PUT", f"/vulnerability/{id}", body=fields)
        case "bulk_create":
            return await client.request(
                "POST",
                "/vulnerability/bulk",
                body={"project_id": project_id, "vulnerabilities": items},
            )
        case "summarize_custom_fields":
            if not project_id:
                raise ValueError("project_id is required")
            data = await client.request("GET", f"/project/{project_id}/vulnerabilities")
            vulns = data.get("vulnerabilities", [])
            filter_key = (fields or {}).get("key")
            summary: dict[str, set] = {}
            for vuln in vulns:
                for cf in vuln.get("vulnerability_custom_fields", []):
                    k = cf.get("key", "")
                    if filter_key and k != filter_key:
                        continue
                    val = cf.get("value")
                    if val is None or val == "" or val == []:
                        continue
                    if k not in summary:
                        summary[k] = set()
                    vals = val if isinstance(val, list) else [val]
                    for v in vals:
                        stripped = str(v).strip()
                        if stripped:
                            summary[k].add(stripped)
            return {
                "total_vulnerabilities": len(vulns),
                "custom_fields": {k: sorted(v) for k, v in sorted(summary.items())},
            }
        case "list_by_custom_field":
            if not project_id:
                raise ValueError("project_id is required")
            if not fields or "key" not in fields or "value" not in fields:
                raise ValueError("fields.key and fields.value are required")
            data = await client.request("GET", f"/project/{project_id}/vulnerabilities")
            vulns = data.get("vulnerabilities", [])
            match_key = fields["key"]
            match_val = str(fields["value"]).strip().lower()
            matched = []
            for vuln in vulns:
                for cf in vuln.get("vulnerability_custom_fields", []):
                    if cf.get("key") != match_key:
                        continue
                    val = cf.get("value")
                    if val is None:
                        continue
                    vals = val if isinstance(val, list) else [val]
                    if any(str(v).strip().lower() == match_val for v in vals):
                        matched.append(
                            {k: v for k, v in vuln.items() if k in _VULN_SUMMARY_KEYS}
                        )
                        break
            cap = limit if limit is not None else 25
            return {
                "total_matched": len(matched),
                "shown": len(matched[:cap]),
                "has_more": len(matched) > cap,
                "vulnerabilities": matched[:cap],
            }
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# testsuites
# ---------------------------------------------------------------------------


@mcp.tool()
async def testsuites(
    action: str,
    id: str | None = None,
    testcase_id: str | None = None,
    fields: dict[str, Any] | None = None,
    items: list[dict[str, Any]] | None = None,
) -> Any:
    """
    Manage AttackForge testsuite libraries.

    Actions:
      list           — GET /testsuites
      get            — GET /testsuites/:id  (requires: id)
      create         — POST /testsuite  (requires: fields: name, description)
      update         — PUT /testsuite/:id  (requires: id, fields)
      add_testcase   — POST /testsuite/:id/testcase  (requires: id, fields)
      add_testcases  — POST /testsuite/:id/testcases  (requires: id, items=[{...},...])
      update_testcase — PUT /testsuite/:id/testcase/:testcase_id
                        (requires: id, testcase_id, fields)
    """
    match action:
        case "list":
            data = _cache.get("testsuites:list")
            if data is None:
                data = await client.request("GET", "/testsuites")
                _cache.set("testsuites:list", data, ttl=43200)
            return data
        case "get":
            cache_key = f"testsuites:get:{id}"
            data = _cache.get(cache_key)
            if data is None:
                data = await client.request("GET", f"/testsuites/{id}")
                _cache.set(cache_key, data, ttl=43200)
            return data
        case "create":
            return await client.request("POST", "/testsuite", body=fields)
        case "update":
            return await client.request("PUT", f"/testsuite/{id}", body=fields)
        case "add_testcase":
            return await client.request(
                "POST", f"/testsuite/{id}/testcase", body=fields
            )
        case "add_testcases":
            return await client.request(
                "POST", f"/testsuite/{id}/testcases", body={"testcases": items}
            )
        case "update_testcase":
            return await client.request(
                "PUT", f"/testsuite/{id}/testcase/{testcase_id}", body=fields
            )
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# testcases
# ---------------------------------------------------------------------------


@mcp.tool()
async def testcases(
    action: str,
    project_id: str | None = None,
    testcase_id: str | None = None,
    fields: dict[str, Any] | None = None,
    note: str | None = None,
    limit: int | None = None,
) -> Any:
    """
    Manage test cases assigned to AttackForge projects.

    Actions:
      list      — GET /project/:project_id/testcases  (requires: project_id)
                  Optional: limit (default 50). Returns total + has_more.
      assign    — POST /project/:project_id/testcase  (requires: project_id, fields)
      update    — PUT /project/:project_id/testcase/:testcase_id
                  (requires: project_id, testcase_id, fields)
                  Key fields: status (Tested/Not Tested), linked_vulnerabilities
      add_note  — POST /project/:project_id/testcase/:testcase_id/note
                  (requires: project_id, testcase_id, note)
      analytics — GET /analytics/failed/testcases
    """
    match action:
        case "list":
            data = await client.request("GET", f"/project/{project_id}/testcases")
            tc_list = data.get("testcases", [])
            cap = limit if limit is not None else 50
            slimmed = [
                {k: v for k, v in tc.items() if k in _TESTCASE_SUMMARY_KEYS}
                for tc in tc_list[:cap]
            ]
            return {
                "total": data.get("count", len(tc_list)),
                "shown": len(slimmed),
                "has_more": len(tc_list) > cap,
                "testcases": slimmed,
            }
        case "assign":
            return await client.request(
                "POST", f"/project/{project_id}/testcase", body=fields
            )
        case "update":
            return await client.request(
                "PUT", f"/project/{project_id}/testcase/{testcase_id}", body=fields
            )
        case "add_note":
            return await client.request(
                "POST",
                f"/project/{project_id}/testcase/{testcase_id}/note",
                body={"note": note},
            )
        case "analytics":
            return await client.request("GET", "/analytics/failed/testcases")
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# assets
# ---------------------------------------------------------------------------


@mcp.tool()
async def assets(
    action: str,
    id: str | None = None,
    project_id: str | None = None,
    asset_id: str | None = None,
    fields: dict[str, Any] | None = None,
    items: list[dict[str, Any]] | None = None,
    limit: int | None = None,
) -> Any:
    """
    Manage assets in AttackForge (project scope and library).

    Actions:
      list              — GET /assets  (all user assets; optional: limit, default 100)
      list_by_group     — GET /assets/group/:id  (requires: id = group_id)
      create_on_project — POST /project/:project_id/assets
                          (requires: project_id, items=[{asset_name, asset_type,...},...])
      update_on_project — PUT /project/:project_id/asset/:asset_id
                          (requires: project_id, asset_id, fields)
      list_library      — GET /library/assets
      get_library       — GET /library/asset  (params via fields)
      create_library    — POST /library/asset  (requires: fields)
      update_library    — PUT /library/asset/:id  (requires: id, fields)
    """
    match action:
        case "list":
            data = await client.request("GET", "/assets")
            asset_list = data.get("assets", [])
            cap = limit if limit is not None else 100
            slimmed = [
                {k: v for k, v in a.items() if k in _ASSET_SUMMARY_KEYS}
                for a in asset_list[:cap]
            ]
            return {
                "total": data.get("count", len(asset_list)),
                "shown": len(slimmed),
                "has_more": len(asset_list) > cap,
                "assets": slimmed,
            }
        case "list_by_group":
            return await client.request("GET", f"/assets/group/{id}")
        case "create_on_project":
            return await client.request(
                "POST", f"/project/{project_id}/assets", body={"assets": items}
            )
        case "update_on_project":
            return await client.request(
                "PUT", f"/project/{project_id}/asset/{asset_id}", body=fields
            )
        case "list_library":
            return await client.request("GET", "/library/assets")
        case "get_library":
            return await client.request("GET", "/library/asset", params=fields)
        case "create_library":
            return await client.request("POST", "/library/asset", body=fields)
        case "update_library":
            return await client.request("PUT", f"/library/asset/{id}", body=fields)
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# remediation
# ---------------------------------------------------------------------------


@mcp.tool()
async def remediation(
    action: str,
    vulnerability_id: str | None = None,
    note_id: str | None = None,
    fields: dict[str, Any] | None = None,
) -> Any:
    """
    Manage remediation notes on AttackForge vulnerabilities.

    Actions:
      create_note — POST /vulnerability/:vulnerability_id/remediationNote
                    (requires: vulnerability_id, fields)
                    Key fields: projectId (required), note (required),
                      note_type ("PLAINTEXT" or "RICHTEXT")
      update_note — PUT /vulnerability/:vulnerability_id/remediationNote/:note_id
                    (requires: vulnerability_id, note_id, fields)
    """
    match action:
        case "create_note":
            return await client.request(
                "POST",
                f"/vulnerability/{vulnerability_id}/remediationNote",
                body=fields,
            )
        case "update_note":
            return await client.request(
                "PUT",
                f"/vulnerability/{vulnerability_id}/remediationNote/{note_id}",
                body=fields,
            )
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# analytics
# ---------------------------------------------------------------------------


@mcp.tool()
async def analytics(action: str) -> Any:
    """
    Query AttackForge analytics endpoints.

    Actions:
      failed_testcases  — GET /analytics/failed/testcases
      vulnerable_assets — GET /analytics/vulnerable/assets  (top 100 by vuln count)
      common_vulns      — GET /analytics/common/vulnerabilities  (top 50 by count)
    """
    match action:
        case "failed_testcases":
            return await client.request("GET", "/analytics/failed/testcases")
        case "vulnerable_assets":
            data = await client.request("GET", "/analytics/vulnerable/assets")
            assets = data.get("assets", [])
            top = sorted(
                assets,
                key=lambda a: (
                    a.get("critical_vulnerabilities", 0)
                    + a.get("high_vulnerabilities", 0)
                    + a.get("medium_vulnerabilities", 0)
                    + a.get("low_vulnerabilities", 0)
                ),
                reverse=True,
            )[:_ANALYTICS_LIST_LIMIT]
            return {
                "total_assets": data.get("count", len(assets)),
                "shown": len(top),
                "assets": top,
            }
        case "common_vulns":
            data = await client.request("GET", "/analytics/common/vulnerabilities")
            vulns = data.get("vulnerabilities", [])
            top = sorted(vulns, key=lambda v: v.get("count", 0), reverse=True)
            top = top[:_ANALYTICS_LIST_LIMIT]
            return {
                "total_count": len(vulns),
                "shown": len(top),
                "vulnerabilities": top,
            }
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# reports
# ---------------------------------------------------------------------------


@mcp.tool()
async def reports(
    action: str,
    project_id: str | None = None,
    report_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> Any:
    """
    Generate and retrieve AttackForge project reports.

    Actions:
      get_data   — POST /project/:project_id/report/:report_type
                   (requires: project_id, report_type, optional options)
                   report_type examples: pentest, vulnerability, executive
      get_report — GET /project/:project_id/report/:report_type
                   (requires: project_id, report_type)
    """
    match action:
        case "get_data":
            return await client.request(
                "POST",
                f"/project/{project_id}/report/{report_type}",
                body=options or {},
            )
        case "get_report":
            return await client.request(
                "GET", f"/project/{project_id}/report/{report_type}"
            )
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# utils
# ---------------------------------------------------------------------------


@mcp.tool()
async def utils(
    action: str,
    markdown: str | None = None,
    config_type: str | None = None,
) -> Any:
    """
    AttackForge utility functions.

    Actions:
      markdown_to_richtext — POST /utils/markdown-to-richtext
                             (requires: markdown)
                             Convert markdown to AF rich text format. Use before
                             setting description/recommendation/note fields.
      get_form_config      — GET /config/form/:config_type
                             (requires: config_type e.g. "vulnerability", "project")
    """
    match action:
        case "markdown_to_richtext":
            return await client.request(
                "POST", "/utils/markdown-to-richtext", body={"markdown": markdown}
            )
        case "get_form_config":
            cache_key = f"utils:get_form_config:{config_type}"
            cached = _cache.get(cache_key)
            if cached is not None:
                return cached
            data = await client.request("GET", f"/config/form/{config_type}")
            if isinstance(data.get("config"), list):
                data = {**data, "config": _slim_form_config(data["config"])}
            _cache.set(cache_key, data, ttl=86400)
            return data
        case _:
            raise ValueError(f"Unknown action: {action}")


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------


@mcp.tool()
async def cache(
    action: str,
    key: str | None = None,
) -> Any:
    """
    Manage the local SQLite cache for static AF data.

    Actions:
      stats      — list all cache entries with key, age_seconds, ttl_seconds, expired
      invalidate — delete by key (or all entries if no key given)
    """
    match action:
        case "stats":
            return _cache.stats()
        case "invalidate":
            deleted = _cache.invalidate(key)
            return {"deleted": deleted}
        case _:
            raise ValueError(f"Unknown action: {action}")
