"""SQLite-backed cache for static/slow-changing AF data."""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

_DB_DIR = Path.home() / ".attackforge-mcp"
_DB_PATH = _DB_DIR / "cache.db"
_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS cache (
    key        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    ttl        INTEGER NOT NULL
)
"""


def _connect() -> sqlite3.Connection:
    _DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.execute(_CREATE_SQL)
    conn.commit()
    return conn


def get(key: str) -> Any | None:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT data, fetched_at, ttl FROM cache WHERE key = ?", (key,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    data_str, fetched_at, ttl = row
    if time.time() - fetched_at > ttl:
        return None
    return json.loads(data_str)


def set(key: str, data: Any, ttl: int) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO cache (key, data, fetched_at, ttl) VALUES (?, ?, ?, ?)",
            (key, json.dumps(data), int(time.time()), ttl),
        )
        conn.commit()
    finally:
        conn.close()


def invalidate(key: str | None = None) -> int:
    conn = _connect()
    try:
        if key is None:
            cur = conn.execute("DELETE FROM cache")
        else:
            cur = conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def stats() -> list[dict]:
    now = int(time.time())
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT key, fetched_at, ttl FROM cache ORDER BY key"
        ).fetchall()
    finally:
        conn.close()
    result = []
    for key, fetched_at, ttl in rows:
        age = now - fetched_at
        result.append(
            {
                "key": key,
                "age_seconds": age,
                "ttl_seconds": ttl,
                "expired": age > ttl,
            }
        )
    return result
