"""Parse nuclei JSON-line output."""
from __future__ import annotations
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash

SEV_MAP = {
    "critical": Severity.critical,
    "high":     Severity.high,
    "medium":   Severity.medium,
    "low":      Severity.low,
    "info":     Severity.info,
    "unknown":  Severity.unknown,
}


def parse_nuclei(data: dict, scan_id: int):
    """Convert one nuclei JSON result dict into a NormalizedFinding."""
    if not data:
        return None

    info     = data.get("info", {})
    sev_str  = info.get("severity", "info").lower()
    severity = SEV_MAP.get(sev_str, Severity.info)

    host = data.get("host", "")
    url  = data.get("matched-at", data.get("matched", ""))
    cves = info.get("classification", {}).get("cve-id", [])
    if isinstance(cves, str):
        cves = [cves]

    return NormalizedFinding(
        scan_id=scan_id,
        tool="nuclei",
        finding_type=data.get("type", "nuclei_finding"),
        title=info.get("name", data.get("template-id", "nuclei finding")),
        severity=severity,
        host=host,
        url=url if url != host else None,
        description=info.get("description", ""),
        cve_ids=cves,
        remediation=info.get("remediation", ""),
        references=info.get("reference", []) or [],
        raw_output=str(data)[:3000],
        fingerprint_hash=make_hash("nuclei", host, data.get("template-id", ""), url),
    )
