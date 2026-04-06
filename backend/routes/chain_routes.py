from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import db, models
from services.exploit_graph_service import ExploitGraphService
import auth

router = APIRouter(prefix="/api/analysis/chains", tags=["attack-chains"])

@router.get("/{job_id}")
def get_attack_chains(
    job_id: str,
    db: Session = Depends(db.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Retrieve the heuristic attack path correlation graph for a scan."""
    # Ensure job belongs to user's tenant
    job = db.query(models.ScanJob).filter_by(
        job_id=job_id, tenant_id=current_user.tenant_id
    ).first()
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
        
    service = ExploitGraphService(db)
    graph_data = service.build_graph(job_id)
    
    if not graph_data:
        return {"nodes": [], "links": [], "error": "Graph analysis failed or missing dependencies"}
        
    return graph_data
