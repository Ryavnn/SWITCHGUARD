from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Float, Boolean, Table
from sqlalchemy.orm import relationship
from .db import Base
import uuid
from datetime import datetime


# ── Association Tables for RBAC ───────────────────────────────────────────────

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", String, ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", String, ForeignKey("permissions.id"), primary_key=True),
)

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String, ForeignKey("users.id"), primary_key=True),
    Column("role_id", String, ForeignKey("roles.id"), primary_key=True),
)



# ── RBAC Models ───────────────────────────────────────────────────────────────

class Role(Base):
    __tablename__ = "roles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, nullable=False)  # Admin, Analyst, User
    description = Column(String, nullable=True)

    # Relationships
    users = relationship("User", secondary="user_roles", back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, nullable=False)  # e.g., 'scan:run', 'user:manage'
    description = Column(String, nullable=True)

    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")


# ── Core Models ───────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)  # Suspend accounts
    mfa_enabled = Column(Boolean, default=False)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    scans = relationship("ScanJob", back_populates="owner")
    reports = relationship("Report", back_populates="owner")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    job_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)  # SaaS Ownership
    target = Column(String, nullable=False)
    status = Column(String, default="pending")
    scan_type = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    raw_results = Column(Text, nullable=True)

    # Relationships
    owner = relationship("User", back_populates="scans")
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("VulnerabilityInstance", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan")


class Asset(Base):
    __tablename__ = "assets"

    asset_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String, ForeignKey("scan_jobs.job_id"))
    user_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)  # Isolated filtering
    ip_address = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    os_detected = Column(String, nullable=True)

    # Relationships
    scan = relationship("ScanJob", back_populates="assets")
    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"

    service_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id = Column(String, ForeignKey("assets.asset_id"))
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    service_name = Column(String, nullable=True)
    state = Column(String, nullable=True)
    version = Column(String, nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="services")


class VulnerabilityInstance(Base):
    __tablename__ = "vulnerabilities"

    vuln_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String, ForeignKey("scan_jobs.job_id"))
    user_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)  # Dashboard isolation
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="Low")
    risk_score = Column(Float, default=0.0)
    evidence = Column(Text, nullable=True)
    url = Column(String, nullable=True)
    solution = Column(String, nullable=True)

    # Relationships
    scan = relationship("ScanJob", back_populates="vulnerabilities")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    scan_id = Column(String, ForeignKey("scan_jobs.job_id"))
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=True)
    file_type = Column(String, nullable=False)  # csv or pdf
    file_path = Column(String, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    severity_summary = Column(String, nullable=True)  # JSON string
    risk_score = Column(Float, default=0.0)

    # Relationships
    owner = relationship("User", back_populates="reports")
    scan = relationship("ScanJob", back_populates="reports")

# ── Admin & SOC Models ────────────────────────────────────────────────────────

class AuditLog(Base):
    """Tracks administrative and sensitive user actions."""
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String, nullable=False)  # e.g., 'scan_launch', 'user_suspend'
    target_id = Column(String, nullable=True) # ID of modified resource
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

class SystemSetting(Base):
    """Stores platform-wide configuration dynamically."""
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True)
    value = Column(String, nullable=False) # JSON or string
    description = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
