"""APScheduler setup."""

import logging
import os

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

# Module-level scheduler instance
scheduler = AsyncIOScheduler()


def _parse_cron(cron_expr: str) -> CronTrigger:
    """Convert a 5-field cron expression to an APScheduler CronTrigger."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Expected 5-field cron expression, got: {cron_expr!r}")
    minute, hour, day, month, day_of_week = parts
    return CronTrigger(
        minute=minute,
        hour=hour,
        day=day,
        month=month,
        day_of_week=day_of_week,
    )


def setup_scheduler(scan_all_fn) -> None:
    """
    Register the nightly full-scan job.
    *scan_all_fn* is an async callable with no required arguments.
    """
    cron_expr = os.environ.get("SCAN_CRON", "0 3 * * *")
    try:
        trigger = _parse_cron(cron_expr)
    except ValueError as exc:
        logger.warning(
            "Invalid SCAN_CRON %r (%s); falling back to '0 3 * * *'. "
            "Expected format: 'minute hour day month day_of_week' (e.g. '0 3 * * *').",
            cron_expr,
            exc,
        )
        trigger = CronTrigger(hour=3, minute=0)

    scheduler.add_job(
        scan_all_fn,
        trigger=trigger,
        id="nightly_scan",
        replace_existing=True,
    )
    logger.info("Scheduled nightly scan with cron: %s", cron_expr)
    scheduler.start()
    logger.info("Scheduler started")


def shutdown_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
