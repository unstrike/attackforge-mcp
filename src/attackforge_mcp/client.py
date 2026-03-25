"""Thin async wrapper around the AttackForge Self-Service API."""

import os
from typing import Any

import httpx

_http = httpx.AsyncClient(timeout=30)


def strip_html_keys(data: Any) -> Any:
    """Recursively remove keys ending in '_html' (duplicate rich-text fields).

    AF returns both plaintext and HTML versions of every text field.
    Stripping the HTML copies cuts response size by 40-60% with no information loss
    for Claude since it works with plaintext natively.
    """
    if isinstance(data, dict):
        return {
            k: strip_html_keys(v)
            for k, v in data.items()
            if not k.lower().endswith("_html")
        }
    if isinstance(data, list):
        return [strip_html_keys(item) for item in data]
    return data


async def request(
    method: str,
    endpoint: str,
    *,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> Any:
    """Make an authenticated SSAPI request. Returns parsed JSON."""
    base = f"https://{os.environ['AF_HOSTNAME']}/api/ss"
    headers = {
        "X-SSAPI-KEY": os.environ.get("X_SSAPI_KEY", ""),
        "Content-Type": "application/json",
    }
    url = f"{base}/{endpoint.lstrip('/')}"
    resp = await _http.request(
        method.upper(),
        url,
        headers=headers,
        params=params,
        json=body,
    )
    if resp.is_error:
        detail = ""
        try:
            detail = f" — {resp.json()}"
        except Exception:
            if resp.text:
                detail = f" — {resp.text[:200]}"
        raise httpx.HTTPStatusError(
            f"{resp.status_code} {resp.reason_phrase} for {url}{detail}",
            request=resp.request,
            response=resp,
        )
    if resp.content:
        return strip_html_keys(resp.json())
    return {}
