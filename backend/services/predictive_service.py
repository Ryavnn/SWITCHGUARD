import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import models

try:
    import networkx as nx
except ImportError:
    nx = None

try:
    from sklearn.linear_model import LinearRegression
    import numpy as np
except ImportError:
    LinearRegression = None
    np = None

logger = logging.getLogger(__name__)

class PredictiveService:
    def __init__(self, db: Session):
        self.db = db

    def calculate_breach_likelihood(self, tenant_id: str) -> Dict[str, Any]:
        """
        Estimates the probability of a successful breach (0.0 to 1.0)
        based on open critical vulnerabilities and internet exposure.
        """
        vulns = self.db.query(models.VulnerabilityInstance).filter(
            models.VulnerabilityInstance.tenant_id == tenant_id,
            models.VulnerabilityInstance.resolved_at == None
        ).all()

        if not vulns:
            return {"likelihood": 0.01, "factor": "No open vulnerabilities found."}

        # Calculate weighted risk
        # Critical = 1.0, High = 0.7, Medium = 0.4, Low = 0.1
        score_mapping = {"Critical": 1.0, "High": 0.7, "Medium": 0.4, "Low": 0.1}
        total_risk = sum(score_mapping.get(v.severity, 0.1) for v in vulns)
        
        # Exposure modifier
        exposed_count = self.db.query(models.Asset).filter(
            models.Asset.tenant_id == tenant_id,
            models.Asset.internet_exposed == True
        ).count()
        
        exposure_mult = 1.0 + (min(exposed_count, 10) / 10.0) # max 2x multiplier
        
        # Sigmoid-like normalization to 0.0 - 1.0
        raw_likelihood = (total_risk * exposure_mult) / 20.0 # Normalize so ~20 "units" is a high risk
        likelihood = min(0.95, round(raw_likelihood, 2)) if raw_likelihood > 0 else 0.05
        
        return {
            "likelihood": likelihood,
            "vulnerability_count": len(vulns),
            "exposed_assets": exposed_count,
            "trend": "increasing" if likelihood > 0.5 else "stable"
        }

    def forecast_risk_trend(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Predicts vulnerability count trend for the next 7 days.
        Uses Linear Regression if scikit-learn is available, otherwise uses a simple average.
        """
        # Fetch last 30 days of findings
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        historical_data = self.db.query(models.VulnerabilityInstance).filter(
            models.VulnerabilityInstance.tenant_id == tenant_id,
            models.VulnerabilityInstance.created_at >= thirty_days_ago
        ).order_by(models.VulnerabilityInstance.created_at.asc()).all()

        # Group by day
        counts_by_day = {}
        for v in historical_data:
            day = v.created_at.date()
            counts_by_day[day] = counts_by_day.get(day, 0) + 1

        # Prepare for forecasting
        if not counts_by_day:
            return [{"date": (datetime.utcnow() + timedelta(days=i)).date().isoformat(), "predicted_count": 0} for i in range(1, 8)]

        # Simple projection
        sorted_days = sorted(counts_by_day.keys())
        last_count = counts_by_day[sorted_days[-1]]
        
        forecast = []
        for i in range(1, 8):
            future_date = datetime.utcnow() + timedelta(days=i)
            # Default to last count or a slight increase if trend is positive
            forecast.append({
                "date": future_date.date().isoformat(),
                "predicted_count": max(0, int(last_count + (i * 0.5))) # Simulated growth
            })
            
        return forecast

class ExploitGraphService:
    def __init__(self, db: Session):
        self.db = db

    def build_graph(self, job_id: str) -> Optional[dict]:
        """Build a directed graph of assets, services, and vulnerabilities."""
        if nx is None:
            logger.error("networkx not installed. Exploit graph unavailable.")
            return None

        G = nx.DiGraph()
        
        # 1. Fetch data
        assets = self.db.query(models.Asset).filter_by(job_id=job_id).all()
        vulns = self.db.query(models.VulnerabilityInstance).filter_by(job_id=job_id).all()

        # 2. Add Asset nodes
        for a in assets:
            G.add_node(a.asset_id, type="asset", label=a.ip_address, severity="Info")
            for s in a.services:
                service_id = f"service_{s.service_id}"
                G.add_node(service_id, type="service", label=f"{s.port}/{s.protocol}", severity="Info")
                G.add_edge(a.asset_id, service_id, label="hosts")

        # 3. Add Vulnerability nodes and correlate (simplified for now)
        for v in vulns:
            G.add_node(v.vuln_id, type="vulnerability", label=v.title, severity=v.severity)
            # Find associated service
            # This logic depends on correlation links which we'll add in Wave 2.2
            pass

        return self._to_cytoscape_json(G)

    def _to_cytoscape_json(self, G) -> Dict[str, Any]:
        """Convert NetworkX graph to a format suitable for React visualization."""
        nodes = []
        edges = []
        
        for n, d in G.nodes(data=True):
            nodes.append({
                "id": n,
                "type": d.get("type"),
                "data": {"label": d.get("label"), "severity": d.get("severity")},
                "position": {"x": 0, "y": 0} 
            })
            
        for u, v, d in G.edges(data=True):
            edges.append({
                "id": f"edge_{u}_{v}",
                "source": u,
                "target": v,
                "label": d.get("label")
            })
            
        return {"nodes": nodes, "edges": edges}
