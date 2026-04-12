"""SQLite schema and query helpers."""

import json
import os
import sqlite3
from datetime import datetime
from typing import Any

DB_PATH = os.environ.get("SCANNER_DB_PATH", "/data/scanner.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS images (
    image_id TEXT PRIMARY KEY,
    tags TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_id TEXT NOT NULL,
    scanned_at TIMESTAMP NOT NULL,
    grype_db_version TEXT,
    finding_count INTEGER,
    FOREIGN KEY (image_id) REFERENCES images(image_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    package_name TEXT,
    package_version TEXT,
    fixed_version TEXT,
    package_type TEXT,
    description TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

def upsert_image(image_id: str, tags: list[str]) -> None:
    now = datetime.now().isoformat(sep=" ", timespec="seconds")
    tags_json = json.dumps(tags)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO images (image_id, tags, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(image_id) DO UPDATE SET
                tags = excluded.tags,
                last_seen = excluded.last_seen
            """,
            (image_id, tags_json, now, now),
        )


def get_all_images() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM images ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]


def get_image(image_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM images WHERE image_id = ?", (image_id,)
        ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def insert_scan(image_id: str, grype_db_version: str | None, finding_count: int) -> int:
    now = datetime.now().isoformat(sep=" ", timespec="seconds")
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (image_id, scanned_at, grype_db_version, finding_count)
            VALUES (?, ?, ?, ?)
            """,
            (image_id, now, grype_db_version, finding_count),
        )
        return cur.lastrowid  # type: ignore[return-value]


def get_scans_for_image(image_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE image_id = ? ORDER BY scanned_at DESC",
            (image_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_latest_scan(image_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE image_id = ? ORDER BY scanned_at DESC LIMIT 1",
            (image_id,),
        ).fetchone()
    return dict(row) if row else None


def get_previous_scan(image_id: str) -> dict | None:
    """Return the second-most-recent scan for an image."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE image_id = ? ORDER BY scanned_at DESC LIMIT 1 OFFSET 1",
            (image_id,),
        ).fetchone()
    return dict(row) if row else None


def get_last_global_scan_time() -> str | None:
    """Return the most recent scanned_at timestamp across all images."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT MAX(scanned_at) AS t FROM scans"
        ).fetchone()
    return row["t"] if row else None


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def bulk_insert_findings(scan_id: int, findings: list[dict]) -> None:
    rows = [
        (
            scan_id,
            f["cve_id"],
            f["severity"],
            f.get("package_name"),
            f.get("package_version"),
            f.get("fixed_version"),
            f.get("package_type"),
            f.get("description"),
        )
        for f in findings
    ]
    with get_conn() as conn:
        conn.executemany(
            """
            INSERT INTO findings
                (scan_id, cve_id, severity, package_name, package_version,
                 fixed_version, package_type, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def get_findings_for_scan(scan_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, cve_id",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_findings_api(
    severity: str | None = None,
    image_id: str | None = None,
    fixable_only: bool = False,
) -> list[dict]:
    """Flexible query used by the JSON API endpoint."""
    query = """
        SELECT f.*, s.image_id, s.scanned_at
        FROM findings f
        JOIN scans s ON f.scan_id = s.scan_id
        WHERE 1=1
    """
    params: list[Any] = []
    if severity:
        query += " AND LOWER(f.severity) = LOWER(?)"
        params.append(severity)
    if image_id:
        query += " AND s.image_id = ?"
        params.append(image_id)
    if fixable_only:
        query += " AND f.fixed_version IS NOT NULL AND f.fixed_version != ''"
    query += " ORDER BY f.severity, f.cve_id"
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Dashboard helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def get_dashboard_data() -> list[dict]:
    """
    Return one row per image with the latest scan's severity counts.
    """
    images = get_all_images()
    result = []
    for img in images:
        tags = json.loads(img["tags"] or "[]")
        scan = get_latest_scan(img["image_id"])
        severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        if scan:
            with get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT severity, COUNT(*) AS cnt
                    FROM findings WHERE scan_id = ?
                    GROUP BY severity
                    """,
                    (scan["scan_id"],),
                ).fetchall()
            for row in rows:
                sev = row["severity"].capitalize()
                if sev in severity_counts:
                    severity_counts[sev] = row["cnt"]
                else:
                    severity_counts["Unknown"] += row["cnt"]
        result.append(
            {
                "image_id": img["image_id"],
                "short_id": img["image_id"].replace("sha256:", "")[:12],
                "tags": tags,
                "last_seen": img["last_seen"],
                "last_scan": scan["scanned_at"] if scan else None,
                "grype_db_version": scan["grype_db_version"] if scan else None,
                **severity_counts,
            }
        )
    # Sort by Critical desc, then High desc
    result.sort(key=lambda x: (-x["Critical"], -x["High"]))
    return result
