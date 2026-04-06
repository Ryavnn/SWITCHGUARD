from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Any
from datetime import datetime

# ── Base Config ───────────────────────────────────────────────────────────────
class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

# ── Tenant ───────────────────────────────────────────────────────────────────
class TenantSchema(BaseSchema):
    id: str
    name: str
    slug: str
    plan: str = "free"
    created_at: Optional[datetime] = None

# ── Service ───────────────────────────────────────────────────────────────────
class ServiceSchema(BaseSchema):
    service_id: str
    port: int
    protocol: str
    service_name: Optional[str] = None
    state: Optional[str] = None
    version: Optional[str] = None

# ── Asset ─────────────────────────────────────────────────────────────────────
class AssetSchema(BaseSchema):
    asset_id: str
    ip_address: str
    hostname: Optional[str] = None
    os_detected: Optional[str] = None
    tenant_id: Optional[str] = None
    services: List[ServiceSchema] = []

# ── Vulnerability ─────────────────────────────────────────────────────────────
class VulnSchema(BaseSchema):
    vuln_id: str
    title: str
    description: Optional[str] = None
    severity: str = "Low"
    risk_score: float = 0.0
    evidence: Optional[str] = None
    url: Optional[str] = None
    solution: Optional[str] = None
    
    # Hybrid Fields
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    confidence_score: float = 0.5
    exploit_available: bool = False
    patch_version: Optional[str] = None
    
    # Phase 3 AI Analysis
    ai_summary: Optional[str] = None
    ai_impact: Optional[str] = None
    ai_remediation: Optional[str] = None
    ai_confidence: float = 0.0
    ai_generated_at: Optional[datetime] = None
    
    tenant_id: Optional[str] = None

# ── Scan Job ──────────────────────────────────────────────────────────────────
class JobSchema(BaseSchema):
    job_id: str
    target: str
    status: str
    scan_type: str
    created_at: Optional[datetime] = None
    raw_results: Optional[str] = None
    tenant_id: Optional[str] = None

# ── Unified Details ───────────────────────────────────────────────────────────
class JobDetailResponse(BaseModel):
    job: JobSchema
    assets: List[AssetSchema]
    vulnerabilities: List[VulnSchema]

# ── Correlation ───────────────────────────────────────────────────────────────
class NodeData(BaseModel):
    label: str
    severity: Optional[str] = None

class GraphNode(BaseModel):
    id: str
    type: str # 'asset', 'service', 'vulnerability'
    data: NodeData
    position: dict # {'x': int, 'y': int}

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = None
    animated: bool = True

class CorrelationResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
