"""Pydantic unified finding and asset models."""
from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"
    unknown  = "unknown"


class NormalizedFinding(BaseModel):
    scan_id:          int
    tool:             str
    finding_type:     str
    title:            str
    severity:         Severity = Severity.info
    description:      str      = ""
    host:             str      = ""
    port:             Optional[int]   = None
    url:              Optional[str]   = None
    cve_ids:          list[str]       = Field(default_factory=list)
    cvss_score:       Optional[float] = None
    epss_score:       Optional[float] = None
    mitre_tactics:    list[str]       = Field(default_factory=list)
    raw_output:       str             = ""
    fingerprint_hash: str             = ""
    remediation:      Optional[str]   = None
    references:       list[str]       = Field(default_factory=list)


class NormalizedAsset(BaseModel):
    scan_id:     int
    asset_type:  str             # subdomain | ip | port | url | email
    value:       str
    port:        Optional[int]   = None
    protocol:    Optional[str]   = None
    service:     Optional[str]   = None
    banner:      Optional[str]   = None
    source_tool: str             = ""
