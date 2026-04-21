import sys
import os
import uuid

# Add backend to path
sys.path.append(os.getcwd())

from database.db import SessionLocal
from database import models
from services.exploit_graph_service import ExploitGraphService

def verify():
    db = SessionLocal()
    job_id = str(uuid.uuid4())
    
    print(f"Testing Graph Generation for Job: {job_id}")
    
    try:
        # 1. Create Mock Data
        job = models.ScanJob(job_id=job_id, target="192.168.1.1", scan_type="network")
        db.add(job)
        
        asset = models.Asset(job_id=job_id, ip_address="192.168.1.1", hostname="test-host")
        db.add(asset)
        db.flush() # get asset_id
        
        vuln = models.VulnerabilityInstance(
            job_id=job_id, 
            title="Old SSH Version", 
            severity="High",
            url="192.168.1.1" # Matches asset IP
        )
        db.add(vuln)
        db.commit()

        # 2. Run Graph Build
        service = ExploitGraphService(db)
        graph = service.build_graph(job_id)
        
        if not graph:
            print("[FAILURE] Graph generation returned None.")
            return

        nodes = graph.get("nodes", [])
        links = graph.get("links", [])
        
        print(f"Nodes found: {len(nodes)} (Expected: 2 - Asset + Vuln)")
        print(f"Links found: {len(links)} (Expected: 1 - 'affects' relationship)")
        
        asset_node = next((n for n in nodes if n["type"] == "asset"), None)
        vuln_node = next((n for n in nodes if n["type"] == "vulnerability"), None)
        link = next((l for l in links if l["relation"] == "affects"), None)
        
        if asset_node and vuln_node and link:
            print("[SUCCESS] Graph nodes and relations created correctly.")
            print(f"Link: {link['source']} --({link['relation']})--> {link['target']}")
        else:
            print("[FAILURE] Missing nodes or links.")
            if not link: print("Debug: No 'affects' link found.")

    finally:
        # Cleanup
        db.query(models.VulnerabilityInstance).filter_by(job_id=job_id).delete()
        db.query(models.Asset).filter_by(job_id=job_id).delete()
        db.query(models.ScanJob).filter_by(job_id=job_id).delete()
        db.commit()
        db.close()

if __name__ == "__main__":
    verify()
