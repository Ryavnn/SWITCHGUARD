"""
Database Models — Extended
============================
New fields added:
  ScanJob:              scan_profile, use_ajax
  Asset:                criticality, environment, tags, first_seen, last_seen
  VulnerabilityInstance: epss_score, is_false_positive, severity_override,
                          override_note, override_expires_at, sla_due_date
  New models:           NotificationConfig, ScheduledScan
"""

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Float, Boolean, Table
from sqlalchemy.orm import relationship
from .db import Base
import uuid
from datetime import datetime, timedelta


# ── Association Tables ────────────────────────────────────────────────────────

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id",        String, ForeignKey("roles.id"),       primary_key=True),
    Column("permission_id",  String, ForeignKey("permissions.id"), primary_key=True),
)

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String, ForeignKey("users.id"), primary_key=True),
    Column("role_id",  String, ForeignKey("roles.id"), primary_key=True),
)


# ── RBAC ──────────────────────────────────────────────────────────────────────

class Role(Base):
    __tablename__ = "roles"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    users       = relationship("User", secondary="user_roles", back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")


class Permission(Base):
    __tablename__ = "permissions"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    roles       = relationship("Role", secondary=role_permissions, back_populates="permissions")


# ── Core Models ───────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id              = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name            = Column(String, nullable=False)
    email           = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    created_at      = Column(DateTime, default=datetime.utcnow)
    is_active       = Column(Boolean, default=True)
    mfa_enabled     = Column(Boolean, default=False)
    mfa_secret      = Column(String, nullable=True)   # TOTP secret (store encrypted)
    last_login      = Column(DateTime, nullable=True)
    tenant_id       = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    roles           = relationship("Role", secondary="user_roles", back_populates="users")
    scans           = relationship("ScanJob", back_populates="owner")
    reports         = relationship("Report", back_populates="owner")
    tenant          = relationship("Tenant")


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    job_id       = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id      = Column(String, ForeignKey("users.id"), nullable=True)
    target       = Column(String, nullable=False)
    status       = Column(String, default="pending")
    scan_type    = Column(String, nullable=False)
    # NEW: profile selection and AJAX spider flag
    scan_profile = Column(String, default="standard")
    use_ajax     = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    tenant_id    = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    raw_results  = Column(Text, nullable=True)
    error_detail = Column(Text, nullable=True)   # stores exception traceback on failure
    owner           = relationship("User", back_populates="scans")
    assets          = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("VulnerabilityInstance", back_populates="scan", cascade="all, delete-orphan")
    reports         = relationship("Report", back_populates="scan")


class Asset(Base):
    __tablename__ = "assets"
    asset_id    = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id      = Column(String, ForeignKey("scan_jobs.job_id"))
    user_id     = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    ip_address  = Column(String, nullable=False)
    hostname    = Column(String, nullable=True)
    os_detected = Column(String, nullable=True)
    # NEW: asset enrichment fields
    criticality      = Column(String, default="medium")   # critical|high|medium|low
    environment      = Column(String, default="unknown")  # prod|staging|internal|unknown
    tags             = Column(String, nullable=True)       # JSON array as string
    internet_exposed = Column(Boolean, default=False)
    business_owner   = Column(String, nullable=True)
    first_seen       = Column(DateTime, default=datetime.utcnow)
    last_seen        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    tenant_id        = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    scan             = relationship("ScanJob", back_populates="assets")
    services         = relationship("Service", back_populates="asset", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    service_id   = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id     = Column(String, ForeignKey("assets.asset_id"))
    port         = Column(Integer, nullable=False)
    protocol     = Column(String, default="tcp")
    service_name = Column(String, nullable=True)
    state        = Column(String, nullable=True)
    version      = Column(String, nullable=True)
    asset        = relationship("Asset", back_populates="services")


class VulnerabilityInstance(Base):
    __tablename__ = "vulnerabilities"
    vuln_id       = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id        = Column(String, ForeignKey("scan_jobs.job_id"))
    user_id       = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    title         = Column(String, nullable=False)
    description   = Column(Text, nullable=True)
    severity      = Column(String, default="Low")
    risk_score    = Column(Float, default=0.0)
    evidence      = Column(Text, nullable=True)
    url           = Column(String, nullable=True)
    solution      = Column(String, nullable=True)
    cve_id        = Column(String, nullable=True, index=True)
    cwe_id        = Column(String, nullable=True)
    cvss_score    = Column(Float, nullable=True)
    cvss_vector   = Column(String, nullable=True)
    confidence_score   = Column(Float, default=0.5)
    exploit_available  = Column(Boolean, default=False)
    patch_version      = Column(String, nullable=True)
    # NEW: EPSS score
    epss_score         = Column(Float, nullable=True)
    # NEW: Phase 3 AI Analysis
    ai_summary         = Column(Text, nullable=True)
    ai_impact          = Column(Text, nullable=True)
    ai_remediation     = Column(Text, nullable=True)
    ai_confidence      = Column(Float, default=0.0)
    ai_generated_at    = Column(DateTime, nullable=True)
    # NEW: Threat Intel
    kev_status         = Column(Boolean, default=False)
    metasploit_module  = Column(String, nullable=True)
    exploit_db_id      = Column(String, nullable=True)
    ransomware_related = Column(Boolean, default=False)
    threat_actor_tags  = Column(Text, nullable=True) # JSON array
    # NEW: Remediation Scoring
    priority_score     = Column(Float, default=0.0)
    remediation_rank   = Column(Integer, nullable=True)
    patch_urgency      = Column(String, default="Standard") # Immediate|Urgent|Standard
    assigned_owner     = Column(String, nullable=True)
    tenant_id          = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    # NEW: false-positive and severity override workflow
    is_false_positive  = Column(Boolean, default=False)
    severity_override  = Column(String, nullable=True)
    override_note      = Column(String, nullable=True)
    override_by        = Column(String, nullable=True)  # analyst user_id
    override_expires_at = Column(DateTime, nullable=True)
    # NEW: SLA tracking
    sla_due_date       = Column(DateTime, nullable=True)
    resolved_at        = Column(DateTime, nullable=True)
    sla_breached       = Column(Boolean, default=False)
    scan               = relationship("ScanJob", back_populates="vulnerabilities")
    correlation_links  = relationship("CorrelationLink", back_populates="vulnerability", cascade="all, delete-orphan")


class CorrelationLink(Base):
    __tablename__ = "correlation_links"
    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id         = Column(String, ForeignKey("scan_jobs.job_id"))
    service_id     = Column(String, ForeignKey("services.service_id"))
    vuln_id        = Column(String, ForeignKey("vulnerabilities.vuln_id"))
    confidence     = Column(Float, default=0.5)
    description    = Column(Text, nullable=True)
    service        = relationship("Service")
    vulnerability  = relationship("VulnerabilityInstance", back_populates="correlation_links")


class CVECache(Base):
    __tablename__ = "cve_cache"
    id              = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id          = Column(String, unique=True, index=True)
    description     = Column(Text, nullable=True)
    cvss_score      = Column(Float, nullable=True)
    cvss_vector     = Column(String, nullable=True)
    cwe_id          = Column(String, nullable=True)
    exploit_available = Column(Boolean, default=False)
    epss_score      = Column(Float, nullable=True)
    last_updated    = Column(DateTime, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"
    id               = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id          = Column(String, ForeignKey("users.id"))
    scan_id          = Column(String, ForeignKey("scan_jobs.job_id"))
    asset_id         = Column(String, ForeignKey("assets.asset_id"), nullable=True)
    # file_type: csv | pdf | json | pdf_executive
    file_type        = Column(String, nullable=False)
    file_path        = Column(String, nullable=False)
    generated_at     = Column(DateTime, default=datetime.utcnow)
    tenant_id        = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    severity_summary = Column(String, nullable=True)
    risk_score       = Column(Float, default=0.0)
    owner            = relationship("User", back_populates="reports")
    scan             = relationship("ScanJob", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    action     = Column(String, nullable=False)
    target_id  = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    details    = Column(Text, nullable=True)   # NEW: JSON details field
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    tenant_id  = Column(String, ForeignKey("tenants.id"), nullable=True, index=True)


class Tenant(Base):
    __tablename__ = "tenants"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name          = Column(String, unique=True, nullable=False)
    slug          = Column(String, unique=True, index=True)
    plan          = Column(String, default="free") # free|pro|enterprise
    branding_json = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)


class TenantAPIToken(Base):
    __tablename__ = "tenant_api_tokens"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id     = Column(String, ForeignKey("tenants.id"))
    token_hash    = Column(String, index=True)
    label         = Column(String)
    created_at    = Column(DateTime, default=datetime.utcnow)
    last_used     = Column(DateTime, nullable=True)


class SuppressionRule(Base):
    __tablename__ = "suppression_rules"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id     = Column(String, ForeignKey("tenants.id"))
    pattern       = Column(String, nullable=False)
    match_field   = Column(String, default="title") # title|cve_id|url
    scope         = Column(String, default="global") # global|host|service
    expires_at    = Column(DateTime, nullable=True)
    created_by    = Column(String)
    created_at    = Column(DateTime, default=datetime.utcnow)


class AttackChain(Base):
    __tablename__ = "attack_chains"
    id                   = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id               = Column(String, ForeignKey("scan_jobs.job_id"))
    tenant_id            = Column(String, ForeignKey("tenants.id"))
    chain_risk_score     = Column(Float, default=0.0)
    path_nodes           = Column(Text, nullable=True) # JSON nodes/edges
    exploit_path_summary = Column(Text, nullable=True)
    blast_radius         = Column(String) # High|Medium|Low
    lateral_movement_score = Column(Float, default=0.0)
    created_at           = Column(DateTime, default=datetime.utcnow)


class RemediationComment(Base):
    __tablename__ = "remediation_comments"
    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    vuln_id       = Column(String, ForeignKey("vulnerabilities.vuln_id"))
    user_id       = Column(String, ForeignKey("users.id"))
    tenant_id     = Column(String, ForeignKey("tenants.id"))
    comment       = Column(Text, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow)


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key         = Column(String, primary_key=True)
    value       = Column(String, nullable=False)
    description = Column(String, nullable=True)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ── NEW: Notification Configuration ──────────────────────────────────────────

class NotificationConfig(Base):
    """Stores per-user notification channel configurations."""
    __tablename__ = "notification_configs"
    id        = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id   = Column(String, ForeignKey("users.id"), nullable=True)
    channel   = Column(String, nullable=False)   # slack | email | webhook | teams
    target    = Column(String, nullable=False)    # webhook URL or email address
    # trigger: all | scan_complete | critical_found
    trigger   = Column(String, default="scan_complete")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ── NEW: Scheduled Scans ──────────────────────────────────────────────────────

class ScheduledScan(Base):
    """Stores recurring scan schedules managed by APScheduler."""
    __tablename__ = "scheduled_scans"
    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id     = Column(String, ForeignKey("users.id"), nullable=True)
    target      = Column(String, nullable=False)
    scan_type   = Column(String, nullable=False)   # network | web | nuclei
    scan_profile = Column(String, default="standard")
    # cron_expr: a cron string like "0 2 * * *" (2am daily)
    cron_expr   = Column(String, nullable=False)
    is_active   = Column(Boolean, default=True)
    last_run    = Column(DateTime, nullable=True)
    next_run    = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)