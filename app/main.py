"""FastAPI application — routes and startup."""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import app.db as db
import app.inventory as inventory
import app.scanner as scanner
from app.scheduler import setup_scheduler, shutdown_scheduler

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Scan-status state (in-process; good enough for a single-instance app)
# ---------------------------------------------------------------------------
_scan_running = False
_scan_status: str = "idle"  # idle | running | done | error


# ---------------------------------------------------------------------------
# Background scan task
# ---------------------------------------------------------------------------

async def _run_full_scan() -> None:
    global _scan_running, _scan_status
    if _scan_running:
        logger.info("Scan already in progress — skipping")
        return
    _scan_running = True
    _scan_status = "running"
    try:
        logger.info("=== Full scan started ===")
        images = await asyncio.to_thread(inventory.get_running_images)
        for img in images:
            db.upsert_image(img["image_id"], img["tags"])

        for img in images:
            iid = img["image_id"]
            result = await asyncio.to_thread(scanner.scan_image, iid)
            scan_id = db.insert_scan(
                iid,
                result["grype_db_version"],
                len(result["findings"]),
            )
            if result["findings"]:
                db.bulk_insert_findings(scan_id, result["findings"])
            logger.info(
                "Stored %d finding(s) for %s", len(result["findings"]), iid[:20]
            )
        _scan_status = "done"
        logger.info("=== Full scan complete ===")
    except Exception as exc:
        _scan_status = "error"
        logger.exception("Scan failed: %s", exc)
    finally:
        _scan_running = False


async def _run_single_scan(image_id: str) -> None:
    global _scan_running, _scan_status
    _scan_running = True
    _scan_status = "running"
    try:
        result = await asyncio.to_thread(scanner.scan_image, image_id)
        scan_id = db.insert_scan(
            image_id,
            result["grype_db_version"],
            len(result["findings"]),
        )
        if result["findings"]:
            db.bulk_insert_findings(scan_id, result["findings"])
        logger.info("Single scan complete for %s: %d finding(s)", image_id[:20], len(result["findings"]))
        _scan_status = "done"
    except Exception as exc:
        _scan_status = "error"
        logger.exception("Single scan failed: %s", exc)
    finally:
        _scan_running = False


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    db.init_db()
    os.makedirs(os.environ.get("GRYPE_DB_CACHE_DIR", "/data/grype-db"), exist_ok=True)
    # Warm Grype DB in background so startup is fast
    asyncio.create_task(asyncio.to_thread(scanner.update_grype_db))
    setup_scheduler(_run_full_scan)
    yield
    # Shutdown
    shutdown_scheduler()


app = FastAPI(title="Docker Vulnerability Scanner", lifespan=lifespan)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _tags_display(tags_json: str | list) -> list[str]:
    if isinstance(tags_json, list):
        return tags_json
    try:
        return json.loads(tags_json or "[]")
    except Exception:
        return []


templates.env.globals["tags_display"] = _tags_display


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    rows = db.get_dashboard_data()
    db_age = scanner.get_grype_db_age_days()
    last_scan_time = db.get_last_global_scan_time()
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "rows": rows,
            "db_age_days": db_age,
            "last_scan_time": last_scan_time,
            "scan_status": _scan_status,
        },
    )


@app.get("/image/{image_id}", response_class=HTMLResponse)
async def image_detail(request: Request, image_id: str):
    img = db.get_image(image_id)
    if not img:
        raise HTTPException(status_code=404, detail="Image not found")
    scan = db.get_latest_scan(image_id)
    findings: list[dict] = []
    if scan:
        findings = db.get_findings_for_scan(scan["scan_id"])
    # Group by severity
    severity_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    grouped: dict[str, list] = {s: [] for s in severity_order}
    for f in findings:
        sev = f["severity"].capitalize()
        grouped.setdefault(sev, []).append(f)
    tags = _tags_display(img["tags"])
    return templates.TemplateResponse(
        "image_detail.html",
        {
            "request": request,
            "image": img,
            "tags": tags,
            "short_id": image_id.replace("sha256:", "")[:12],
            "scan": scan,
            "grouped": grouped,
            "severity_order": severity_order,
        },
    )


@app.get("/image/{image_id}/history", response_class=HTMLResponse)
async def image_history(request: Request, image_id: str):
    img = db.get_image(image_id)
    if not img:
        raise HTTPException(status_code=404, detail="Image not found")
    scans = db.get_scans_for_image(image_id)
    tags = _tags_display(img["tags"])
    return templates.TemplateResponse(
        "image_history.html",
        {
            "request": request,
            "image": img,
            "tags": tags,
            "short_id": image_id.replace("sha256:", "")[:12],
            "scans": scans,
        },
    )


@app.get("/diff", response_class=HTMLResponse)
async def diff_view(request: Request):
    """Show new and resolved CVEs since the previous scan per image."""
    images = db.get_all_images()
    diff_data = []
    for img in images:
        iid = img["image_id"]
        latest = db.get_latest_scan(iid)
        previous = db.get_previous_scan(iid)
        if not latest:
            continue
        latest_cves = {
            f["cve_id"] for f in db.get_findings_for_scan(latest["scan_id"])
        }
        previous_cves: set[str] = set()
        if previous:
            previous_cves = {
                f["cve_id"] for f in db.get_findings_for_scan(previous["scan_id"])
            }
        new_cves = sorted(latest_cves - previous_cves)
        resolved_cves = sorted(previous_cves - latest_cves)
        if new_cves or resolved_cves:
            diff_data.append(
                {
                    "image_id": iid,
                    "short_id": iid.replace("sha256:", "")[:12],
                    "tags": _tags_display(img["tags"]),
                    "latest_scan": latest["scanned_at"],
                    "previous_scan": previous["scanned_at"] if previous else None,
                    "new_cves": new_cves,
                    "resolved_cves": resolved_cves,
                }
            )
    return templates.TemplateResponse(
        "diff.html",
        {"request": request, "diff_data": diff_data},
    )


@app.post("/scan")
async def trigger_full_scan(background_tasks: BackgroundTasks):
    """Trigger a full scan of all running images. Returns immediately."""
    if _scan_running:
        return JSONResponse({"status": "already_running"}, status_code=202)
    background_tasks.add_task(_run_full_scan)
    return JSONResponse({"status": "started"}, status_code=202)


@app.post("/scan/{image_id}")
async def trigger_single_scan(image_id: str, background_tasks: BackgroundTasks):
    if _scan_running:
        return JSONResponse({"status": "already_running"}, status_code=202)
    background_tasks.add_task(_run_single_scan, image_id)
    return JSONResponse({"status": "started"}, status_code=202)


@app.get("/scan/status")
async def scan_status():
    return {"status": _scan_status, "running": _scan_running}


@app.get("/api/findings")
async def api_findings(
    severity: str | None = None,
    image_id: str | None = None,
    fixable_only: bool = False,
):
    rows = db.get_findings_api(severity=severity, image_id=image_id, fixable_only=fixable_only)
    return rows
