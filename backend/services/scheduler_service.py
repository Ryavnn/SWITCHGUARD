"""
Scheduler Service
=================
APScheduler integration for recurring scans.
"""

import logging
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from database.db import SessionLocal
from database import models

logger    = logging.getLogger(__name__)
scheduler = AsyncIOScheduler(timezone="UTC")


def start_scheduler():
    """Start APScheduler and reload all active schedules from DB."""
    if not scheduler.running:
        scheduler.start()
        logger.info("APScheduler started.")
        _load_all_schedules()


def _load_all_schedules():
    with SessionLocal() as db:
        active = db.query(models.ScheduledScan).filter_by(is_active=True).all()
        for s in active:
            try:
                _add_job(s.id, s.user_id, s.target, s.scan_type, s.scan_profile, s.cron_expr)
            except Exception as e:
                logger.warning("Could not reload schedule %s: %s", s.id, e)
        logger.info("Loaded %d schedule(s) from DB.", len(active))


def register_schedule(sched: models.ScheduledScan):
    _add_job(sched.id, sched.user_id, sched.target, sched.scan_type, sched.scan_profile, sched.cron_expr)


def remove_schedule(schedule_id: str):
    try:
        scheduler.remove_job(schedule_id)
        logger.info("Removed schedule job %s", schedule_id)
    except Exception:
        pass


def _add_job(schedule_id, user_id, target, scan_type, profile, cron_expr):
    trigger = CronTrigger.from_crontab(cron_expr)

    async def run():
        logger.info("Scheduled scan firing: %s → %s (%s)", scan_type, target, profile)
        from main import _run_scan_task
        await _run_scan_task(
            scan_type=scan_type,
            target=target,
            profile=profile,
            user_id=user_id,
        )
        # Update last_run
        with SessionLocal() as db:
            s = db.query(models.ScheduledScan).filter_by(id=schedule_id).first()
            if s:
                s.last_run = datetime.utcnow()
                db.commit()

    scheduler.add_job(run, trigger=trigger, id=schedule_id, replace_existing=True)
    logger.info("Registered cron job for schedule %s (%s)", schedule_id, cron_expr)
