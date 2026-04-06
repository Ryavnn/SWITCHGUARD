"""
Notification Routes
===================
CRUD for notification channel configurations.
Allows users (and admins) to manage Slack/email/webhook alerts.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db import SessionLocal
from database import models
from auth import get_current_user
from pydantic import BaseModel
from typing import Optional
import logging

router = APIRouter(prefix="/api/notifications", tags=["notifications"])
logger = logging.getLogger(__name__)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class NotifCreate(BaseModel):
    channel: str    # slack | email | webhook | teams
    target:  str    # URL or email
    trigger: str = "scan_complete"   # all | scan_complete | critical_found


class NotifUpdate(BaseModel):
    target:    Optional[str] = None
    trigger:   Optional[str] = None
    is_active: Optional[bool] = None


@router.get("")
def list_notifications(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    role = user.roles[0].name if user.roles else "User"
    # Admins see all; others see their own
    q = db.query(models.NotificationConfig)
    if role != "Admin":
        q = q.filter_by(user_id=user.id)
    configs = q.all()
    return [
        {
            "id":        c.id,
            "channel":   c.channel,
            "target":    c.target,
            "trigger":   c.trigger,
            "is_active": c.is_active,
        }
        for c in configs
    ]


@router.post("")
def create_notification(
    req: NotifCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    cfg = models.NotificationConfig(
        user_id=user.id,
        channel=req.channel,
        target=req.target,
        trigger=req.trigger,
    )
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return {"message": "Notification config created", "id": cfg.id}


@router.patch("/{notif_id}")
def update_notification(
    notif_id: str,
    req: NotifUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    cfg = db.query(models.NotificationConfig).filter_by(id=notif_id).first()
    if not cfg:
        raise HTTPException(404, "Notification config not found")
    role = user.roles[0].name if user.roles else "User"
    if role != "Admin" and cfg.user_id != user.id:
        raise HTTPException(403, "Not authorized")

    if req.target    is not None: cfg.target    = req.target
    if req.trigger   is not None: cfg.trigger   = req.trigger
    if req.is_active is not None: cfg.is_active = req.is_active
    db.commit()
    return {"message": "Updated"}


@router.delete("/{notif_id}")
def delete_notification(
    notif_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    cfg = db.query(models.NotificationConfig).filter_by(id=notif_id).first()
    if not cfg:
        raise HTTPException(404, "Notification config not found")
    db.delete(cfg)
    db.commit()
    return {"message": "Deleted"}


@router.post("/test/{notif_id}")
def test_notification(
    notif_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Send a test notification to verify the channel is working."""
    from services.notification_service import NotificationService
    cfg = db.query(models.NotificationConfig).filter_by(id=notif_id).first()
    if not cfg:
        raise HTTPException(404, "Notification config not found")

    svc     = NotificationService()
    message = "✅ SwitchGuard: Test notification — your channel is correctly configured."
    result  = False

    if cfg.channel == "slack":
        result = svc.send_slack(cfg.target, message)
    elif cfg.channel == "email":
        result = svc.send_email(cfg.target, "SwitchGuard Test", f"<p>{message}</p>")
    elif cfg.channel in ("webhook", "teams"):
        result = svc.send_webhook(cfg.target, {"message": message})

    return {"success": result, "channel": cfg.channel}
