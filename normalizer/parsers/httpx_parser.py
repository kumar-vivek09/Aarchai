"""Parse httpx JSON output."""
from __future__ import annotations
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


def parse_httpx(data: dict, host: str, scan_id: int):
    findings = []
    assets   = []

    url    = data.get("url", "")
    status = data.get("status-code", 0)
    title  = data.get("title", "")
    techs  = data.get("tech", []) or []

    assets.append({
        "type": "url", "value": url,
        "service": f"HTTP {status}",
        "source_tool": "httpx"
    })

    # Technology fingerprint as finding
    if techs:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="httpx",
            finding_type="tech_fingerprint",
            title=f"Tech stack: {', '.join(techs[:6])}",
            severity=Severity.info,
            host=host, url=url,
            description=f"URL: {url}\nStatus: {status}\nTitle: {title}\nTechnologies: {', '.join(techs)}",
            raw_output=str(data),
            fingerprint_hash=make_hash("httpx", host, url, ",".join(sorted(techs))),
        ))

    # Interesting status codes
    if status in (401, 403):
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="httpx",
            finding_type="restricted_resource",
            title=f"HTTP {status} on {url}",
            severity=Severity.low,
            host=host, url=url,
            description=f"Resource at {url} returned HTTP {status} ({title}). May indicate protected content.",
            raw_output=str(data),
            fingerprint_hash=make_hash("httpx_status", host, url, str(status)),
        ))

    return findings, assets
