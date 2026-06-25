"""Dalfox XSS scanner plugin — Stage 4."""
STAGE     = 4
TOOL_NAME = "dalfox"

from stages.base import run_tool, tool_available
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


async def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None):
    if not tool_available("dalfox"):
        return [], []

    from core.db import Asset
    urls = [a.value for a in session.query(Asset).filter(
        Asset.scan_id == scan_id, Asset.asset_type == "url"
    ).all()]
    if not urls:
        urls = [f"http://{target.host}"]

    findings = []
    for url in urls[:5]:
        r = run_tool(["dalfox", "url", url, "--silence", "--format", "json"], timeout=120)
        if r.success and r.stdout:
            import json
            for line in r.stdout.splitlines():
                try:
                    d = json.loads(line)
                    findings.append(NormalizedFinding(
                        scan_id=scan_id, tool="dalfox",
                        finding_type="xss",
                        title=f"XSS: {d.get('param','?')} on {url}",
                        severity=Severity.high,
                        host=target.host, url=url,
                        description=str(d),
                        remediation="Encode all user-supplied output. Use Content-Security-Policy headers.",
                        raw_output=str(d),
                        fingerprint_hash=make_hash("dalfox", target.host, url, d.get("param","")),
                    ))
                    jm.log_finding("high", f"XSS at {url}")
                except Exception:
                    pass
    return findings, []
