"""SQLAlchemy 2 models — v2 with triage, confidence, scope, exploit mapping."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime,
    Text, ForeignKey, JSON, Float, Boolean
)
from sqlalchemy.orm import DeclarativeBase, relationship, Session
from config import DB_URL

engine = create_engine(DB_URL, echo=False, pool_pre_ping=True, future=True)

class Base(DeclarativeBase):
    pass

class Target(Base):
    __tablename__ = "targets"
    id          = Column(Integer, primary_key=True)
    input       = Column(String(512), nullable=False)
    target_type = Column(String(32))
    scope_config = Column(JSON, nullable=True)   # includes/excludes
    created_at  = Column(DateTime, default=datetime.utcnow)
    scans       = relationship("Scan", back_populates="target")

class Scan(Base):
    __tablename__ = "scans"
    id          = Column(Integer, primary_key=True)
    target_id   = Column(Integer, ForeignKey("targets.id"))
    status      = Column(String(32), default="pending")
    stages_run  = Column(JSON, default=list)
    started_at  = Column(DateTime)
    finished_at = Column(DateTime)
    created_at  = Column(DateTime, default=datetime.utcnow)
    target      = relationship("Target", back_populates="scans")
    findings    = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    assets      = relationship("Asset",   back_populates="scan", cascade="all, delete-orphan")
    snapshots   = relationship("ScanSnapshot", back_populates="scan", cascade="all, delete-orphan")

class Asset(Base):
    __tablename__ = "assets"
    id          = Column(Integer, primary_key=True)
    scan_id     = Column(Integer, ForeignKey("scans.id"))
    asset_type  = Column(String(32))
    value       = Column(String(1024))
    port        = Column(Integer, nullable=True)
    protocol    = Column(String(16), nullable=True)
    service     = Column(String(128), nullable=True)
    banner      = Column(Text, nullable=True)
    screenshot_path = Column(String(512), nullable=True)   # NEW
    tech_stack  = Column(JSON, default=list)               # NEW
    source_tool = Column(String(64))
    created_at  = Column(DateTime, default=datetime.utcnow)
    scan        = relationship("Scan", back_populates="assets")

class Finding(Base):
    __tablename__ = "findings"
    id               = Column(Integer, primary_key=True)
    scan_id          = Column(Integer, ForeignKey("scans.id"))
    tool             = Column(String(64))
    finding_type     = Column(String(64))
    title            = Column(String(512))
    severity         = Column(String(32), default="info")
    description      = Column(Text)
    host             = Column(String(256))
    port             = Column(Integer, nullable=True)
    url              = Column(String(1024), nullable=True)
    cve_ids          = Column(JSON, default=list)
    cvss_score       = Column(Float, nullable=True)
    epss_score       = Column(Float, nullable=True)
    mitre_tactics    = Column(JSON, default=list)
    raw_output       = Column(Text)
    fingerprint_hash = Column(String(64), index=True)
    remediation      = Column(Text, nullable=True)
    references       = Column(JSON, default=list)
    # ── New columns ───────────────────────────────────────────
    confidence_score = Column(Integer, default=50)         # 0-100
    triage_status    = Column(String(32), default="unreviewed")  # unreviewed|confirmed|false_positive|accepted_risk
    is_suppressed    = Column(Boolean, default=False)
    exploit_available = Column(Boolean, default=False)     # has public PoC/exploit
    exploit_links    = Column(JSON, default=list)          # ExploitDB/GitHub links
    in_cisa_kev      = Column(Boolean, default=False)      # CISA Known Exploited
    metasploit_module = Column(String(256), nullable=True)
    created_at       = Column(DateTime, default=datetime.utcnow)
    scan             = relationship("Scan", back_populates="findings")

class ScanSnapshot(Base):
    __tablename__ = "scan_snapshots"
    id            = Column(Integer, primary_key=True)
    scan_id       = Column(Integer, ForeignKey("scans.id"))
    snapshot_json = Column(JSON)
    created_at    = Column(DateTime, default=datetime.utcnow)
    scan          = relationship("Scan", back_populates="snapshots")

# Suppression rules table
class SuppressionRule(Base):
    __tablename__ = "suppression_rules"
    id           = Column(Integer, primary_key=True)
    tool         = Column(String(64), nullable=True)
    finding_type = Column(String(64), nullable=True)
    title_pattern = Column(String(256), nullable=True)   # substring match
    reason       = Column(String(256))
    created_at   = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(engine)

def get_session() -> Session:
    return Session(engine)
