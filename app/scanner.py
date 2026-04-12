"""Grype subprocess wrapper + JSON parsing."""

import json
import logging
import os
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

GRYPE_DB_CACHE_DIR = os.environ.get("GRYPE_DB_CACHE_DIR", "/data/grype-db")

# ---------------------------------------------------------------------------
# Extension point: post-scan hook
# ---------------------------------------------------------------------------
# If you want to add notifications (email, webhook, ntfy, etc.) after a scan
# completes, implement the function below and wire it up in run_scan().
#
# def on_scan_complete(image_id: str, new_cves: list[str], resolved_cves: list[str]) -> None:
#     """Called after every scan. new_cves and resolved_cves are CVE ID lists."""
#     pass
# ---------------------------------------------------------------------------


def _grype_env() -> dict[str, str]:
    env = os.environ.copy()
    env["GRYPE_DB_CACHE_DIR"] = GRYPE_DB_CACHE_DIR
    return env


def update_grype_db() -> None:
    """Run `grype db update` to warm / refresh the vulnerability database."""
    logger.info("Updating Grype vulnerability database …")
    try:
        result = subprocess.run(
            ["grype", "db", "update"],
            capture_output=True,
            text=True,
            env=_grype_env(),
            timeout=300,
        )
        if result.returncode == 0:
            logger.info("Grype DB update complete: %s", result.stdout.strip())
        else:
            logger.warning("Grype DB update returned non-zero: %s", result.stderr.strip())
    except subprocess.TimeoutExpired:
        logger.error("Grype DB update timed out")
    except FileNotFoundError:
        logger.error("grype binary not found — is it installed?")


def get_grype_db_version() -> str | None:
    """Return the current Grype DB schema/version string, or None on failure."""
    try:
        result = subprocess.run(
            ["grype", "db", "status"],
            capture_output=True,
            text=True,
            env=_grype_env(),
            timeout=30,
        )
        if result.returncode == 0:
            # Output looks like: "No vulnerabilities provider data is available"
            # or "Vulnerability DB  Location: /data/grype-db  Built: 2024-01-01 ..."
            for line in result.stdout.splitlines():
                if "built" in line.lower() or "schema" in line.lower():
                    return line.strip()
            return result.stdout.strip()[:120] or None
    except Exception as exc:
        logger.debug("Could not get Grype DB version: %s", exc)
    return None


def get_grype_db_age_days() -> float | None:
    """
    Parse `grype db status` output to find the DB build date
    and return age in days, or None if unparseable.
    """
    import re
    from datetime import datetime, timezone

    try:
        result = subprocess.run(
            ["grype", "db", "status"],
            capture_output=True,
            text=True,
            env=_grype_env(),
            timeout=30,
        )
        text = result.stdout + result.stderr
        # Look for ISO-8601 date patterns like 2024-01-01T00:00:00Z or 2024-01-01
        match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if match:
            built = datetime.strptime(match.group(1), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(timezone.utc)
            return (now - built).total_seconds() / 86400
    except Exception as exc:
        logger.debug("Could not compute Grype DB age: %s", exc)
    return None


def scan_image(image_id: str) -> dict[str, Any]:
    """
    Run Grype against *image_id* (full sha256) and return a dict:
      {
        "grype_db_version": str | None,
        "findings": [
            {
                "cve_id": str,
                "severity": str,
                "package_name": str,
                "package_version": str,
                "fixed_version": str | None,
                "package_type": str,
                "description": str,
            }, …
        ]
      }
    """
    os.makedirs(GRYPE_DB_CACHE_DIR, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        suffix=".json", prefix="grype-", delete=False
    ) as tmp:
        tmp_path = tmp.name

    logger.info("Scanning image %s …", image_id[:20])
    try:
        result = subprocess.run(
            ["grype", image_id, "-o", "json", "--file", tmp_path],
            capture_output=True,
            text=True,
            env=_grype_env(),
            timeout=600,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            # Log both start and end so neither context is lost for long error messages
            if len(stderr) > 1000:
                stderr_display = stderr[:500] + "\n…\n" + stderr[-500:]
            else:
                stderr_display = stderr
            logger.error(
                "Grype exited %d for %s: %s",
                result.returncode,
                image_id[:20],
                stderr_display,
            )
            return {"grype_db_version": None, "findings": []}

        with open(tmp_path, "r") as fh:
            raw = json.load(fh)
    except subprocess.TimeoutExpired:
        logger.error("Grype scan timed out for %s", image_id[:20])
        return {"grype_db_version": None, "findings": []}
    except Exception as exc:
        logger.error("Error scanning %s: %s", image_id[:20], exc)
        return {"grype_db_version": None, "findings": []}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return _parse_grype_output(raw)


def _parse_grype_output(raw: dict) -> dict[str, Any]:
    """Parse Grype JSON output into our internal format."""
    db_version: str | None = None
    try:
        descriptor = raw.get("descriptor", {})
        db_info = descriptor.get("db", {})
        db_version = (
            db_info.get("schemaVersion")
            or db_info.get("built")
            or None
        )
        if db_version:
            db_version = str(db_version)
    except Exception:
        pass

    findings: list[dict] = []
    for match in raw.get("matches", []):
        try:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            cve_id: str = vuln.get("id", "")
            if not cve_id:
                continue

            severity: str = vuln.get("severity", "Unknown").capitalize()

            fix_versions = vuln.get("fix", {}).get("versions", [])
            fixed_version: str | None = fix_versions[0] if fix_versions else None

            findings.append(
                {
                    "cve_id": cve_id,
                    "severity": severity,
                    "package_name": artifact.get("name", ""),
                    "package_version": artifact.get("version", ""),
                    "fixed_version": fixed_version,
                    "package_type": artifact.get("type", ""),
                    "description": vuln.get("description", ""),
                }
            )
        except Exception as exc:
            logger.debug("Skipping malformed match: %s", exc)

    return {"grype_db_version": db_version, "findings": findings}
