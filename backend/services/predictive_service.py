import logging
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from database import models

try:
    import networkx as nx
except ImportError:
    nx = None

logger = logging.getLogger(__name__)

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
