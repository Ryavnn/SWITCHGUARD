"""
Schedule Routes
===============
CRUD for recurring scan schedules powered by APScheduler.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db import SessionLocal
from database import models
from auth import get_current_user
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import logging

router = APIRouter(prefix="/api/schedules", tags=["schedules"])
logger = logging.getLogger(__name__)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class ScheduleCreate(BaseModel):
    target:       str
    scan_type:    str                  # network | web | nuclei
    scan_profile: str  = "standard"
    cron_expr:    str                  # e.g. "0 2 * * *"


class ScheduleUpdate(BaseModel):
    cron_expr:    Optional[str]  = None
    scan_profile: Optional[str] = None
    is_active:    Optional[bool] = None


@router.get("")
def list_schedules(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    role = user.roles[0].name if user.roles else "User"
    q    = db.query(models.ScheduledScan)
    if role != "Admin":
        q = q.filter_by(user_id=user.id)
    return [
        {
            "id":           s.id,
            "target":       s.target,
            "scan_type":    s.scan_type,
            "scan_profile": s.scan_profile,
            "cron_expr":    s.cron_expr,
            "is_active":    s.is_active,
            "last_run":     s.last_run,
            "next_run":     s.next_run,
        }
        for s in q.all()
    ]


@router.post("")
def create_schedule(
    req: ScheduleCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    sched = models.ScheduledScan(
        user_id=user.id,
        target=req.target,
        scan_type=req.scan_type,
        scan_profile=req.scan_profile,
        cron_expr=req.cron_expr,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    # Register with APScheduler immediately
    try:
        from services.scheduler_service import register_schedule
        register_schedule(sched)
        logger.info("Registered schedule %s for %r", sched.id, sched.target)
    except Exception as e:
        logger.warning("Could not register schedule with APScheduler: %s", e)

    return {"message": "Schedule created", "id": sched.id}


@router.patch("/{schedule_id}")
def update_schedule(
    schedule_id: str,
    req: ScheduleUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    sched = db.query(models.ScheduledScan).filter_by(id=schedule_id).first()
    if not sched:
        raise HTTPException(404, "Schedule not found")
    role = user.roles[0].name if user.roles else "User"
    if role != "Admin" and sched.user_id != user.id:
        raise HTTPException(403, "Not authorized")

    if req.cron_expr    is not None: sched.cron_expr    = req.cron_expr
    if req.scan_profile is not None: sched.scan_profile = req.scan_profile
    if req.is_active    is not None: sched.is_active    = req.is_active
    db.commit()
    return {"message": "Schedule updated"}


@router.delete("/{schedule_id}")
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    sched = db.query(models.ScheduledScan).filter_by(id=schedule_id).first()
    if not sched:
        raise HTTPException(404, "Schedule not found")
    db.delete(sched)
    db.commit()
    try:
        from services.scheduler_service import remove_schedule
        remove_schedule(schedule_id)
    except Exception:
        pass
    return {"message": "Schedule deleted"}
