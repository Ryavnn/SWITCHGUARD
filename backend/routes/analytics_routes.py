from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import db, models
from services.predictive_service import PredictiveService
import auth

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/breach-likelihood")
def get_breach_likelihood(
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get the estimated breach likelihood for the current tenant."""
    service = PredictiveService(db)
    return service.calculate_breach_likelihood(current_user.tenant_id)

@router.get("/risk-forecast")
def get_risk_forecast(
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get the risk trend forecast for the next 7 days."""
    service = PredictiveService(db)
    return service.forecast_risk_trend(current_user.tenant_id)

@router.get("/top-threats")
def get_top_threats(
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get the top 5 threats based on remediation score."""
    from services.remediation_service import RemediationService
    service = RemediationService(db)
    queue = service.get_remediation_queue(current_user.tenant_id)
    return queue[:5]
