# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**docker-inspector** is a self-contained Dockerized web application that scans all running Docker containers on the host for known CVEs. It exposes a FastAPI/HTMX/Tailwind UI on port 8000.

Key technologies:
- **Python 3.12** with [uv](https://github.com/astral-sh/uv) as package manager
- **FastAPI** + **Uvicorn** for the web layer
- **Jinja2** templates with **HTMX** for interactivity (no JS build step)
- **Grype** (Anchore) for CVE scanning, invoked as a subprocess
- **SQLite** (WAL mode) for persistence via the built-in `sqlite3` module
- **APScheduler** for nightly scheduled scans
- **Docker SDK for Python** to enumerate running containers

## Repository Structure

```
docker-inspector/
├── app/
│   ├── __init__.py
│   ├── db.py          # SQLite schema + all query helpers
│   ├── inventory.py   # Docker SDK: list running container images
│   ├── main.py        # FastAPI routes, background scan tasks, lifespan
│   ├── scanner.py     # Grype subprocess wrapper, DB update
│   ├── scheduler.py   # APScheduler setup (SCAN_CRON)
│   └── templates/     # Jinja2 HTML templates
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml     # Project metadata + dependencies
└── uv.lock
```

## Development Commands

```bash
# Install dependencies (uses uv)
uv sync

# Run locally (requires Grype installed and Docker socket access)
uv run uvicorn app.main:app --reload --port 8000

# Build and run with Docker Compose
docker compose up --build

# Run tests (if added)
uv run pytest
```

## Architecture Notes

### Scan flow
1. `inventory.get_running_images()` → calls `docker.from_env().containers.list()`, returns unique `{image_id, tags}` dicts keyed on SHA256.
2. `scanner.scan_image(image_id)` → runs `grype <image_id> -o json` as a subprocess (10-minute timeout), parses JSON output.
3. Results stored in SQLite via `db.upsert_image()`, `db.insert_scan()`, `db.bulk_insert_findings()`.

### Database schema (3 tables)
- `images` — one row per unique image SHA256; stores tags as JSON, `first_seen`, `last_seen`.
- `scans` — one row per scan run; references `images`; stores `grype_db_version`, `finding_count`.
- `findings` — one row per CVE per scan; stores `cve_id`, `severity`, `package_name`, `package_version`, `fixed_version`, `package_type`, `description`.

### Scan state
Scan status (`idle | running | done | error`) is held in two module-level globals in `main.py` (`_scan_running`, `_scan_status`). This is intentional for a single-instance app and does not survive container restarts.

### Environment variables
| Variable | Default | Description |
|---|---|---|
| `SCANNER_DB_PATH` | `/data/scanner.db` | SQLite database path |
| `GRYPE_DB_CACHE_DIR` | `/data/grype-db` | Grype vulnerability DB cache directory |
| `SCAN_CRON` | `0 3 * * *` | Cron expression for scheduled scans |
| `TZ` | `Europe/Amsterdam` | Timezone for the scheduler |

### Docker socket access
The container mounts `/var/run/docker.sock` read-only. The non-root user `scanner` (UID 1000) belongs to GID 999 (conventional Docker socket GID). If the host uses a different GID, add `group_add: ["<gid>"]` to `docker-compose.yml`.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard |
| `/image/{id}` | GET | Per-image findings detail |
| `/image/{id}/history` | GET | Scan history for one image |
| `/diff` | GET | New/resolved CVEs since previous scan |
| `/scan` | POST | Trigger full scan (async, returns 202) |
| `/scan/{id}` | POST | Trigger single-image scan (async) |
| `/scan/status` | GET | `{"status": "...", "running": bool}` |
| `/api/findings` | GET | JSON findings; supports `severity`, `image_id`, `fixable_only` query params |
| `/healthz` | GET | Liveness probe |

## Common Tasks

### Add a new route
Edit `app/main.py`. Add the FastAPI route function and, if it renders HTML, a corresponding Jinja2 template in `app/templates/`.

### Add a new DB query
Edit `app/db.py`. Use `get_conn()` as a context manager; `conn.row_factory = sqlite3.Row` is set so rows can be accessed by column name and converted with `dict(row)`.

### Change the scan schedule
Set `SCAN_CRON` in `docker-compose.yml` to any valid cron expression (5 fields). The scheduler is set up in `app/scheduler.py` using APScheduler's `CronTrigger`.

### Add a Python dependency
```bash
uv add <package>
# commit both pyproject.toml and uv.lock
```
