"""Stage 4 — Vulnerability Detection with improved nuclei integration."""
from __future__ import annotations
import json
import concurrent.futures
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from stages.base import run_tool, tool_available
import os


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None):
    findings = []
    host = target.host

    from core.db import Asset
    live_ports = session.query(Asset).filter(
        Asset.scan_id == scan_id,
        Asset.asset_type.in_(["port", "url"])
    ).all()
    urls = [f"http://{a.value}:{a.port}" if a.asset_type == "port" else a.value
            for a in live_ports if a.value]
    if not urls:
        urls = [f"http://{host}", f"https://{host}"]

    jm.log_stage("stage4_vulns", f"{len(urls)} targets")

    # Run nuclei + SSL audit in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        nf = ex.submit(_run_nuclei,    urls, host, scan_id, jm, fast, auth)
        sf = ex.submit(_run_ssl_audit, host, scan_id, jm)

    findings.extend(nf.result())
    findings.extend(sf.result())

    if not fast:
        sqli_f = _run_sqlmap(urls[:3], host, scan_id, jm, auth)
        findings.extend(sqli_f)

    if _is_wordpress(host, auth):
        wp_f = _run_wpscan(urls[0], host, scan_id, jm)
        findings.extend(wp_f)

    # Run registered plugins for stage 4
    from plugins.loader import get_plugins
    for plugin in get_plugins(4):
        try:
            import asyncio
            pf, _ = asyncio.run(plugin["run"](target, scan_id, session, jm, fast, out_dir, auth))
            findings.extend(pf)
        except Exception as e:
            jm.log_warn(f"Plugin {plugin['name']} error: {e}")

    return findings, []


def _run_nuclei(urls, host, scan_id, jm, fast, auth=None):
    findings = []
    if not tool_available("nuclei"):
        jm.log_warn("nuclei not found — skipping")
        return findings

    from config import DB_URL  # just to verify config loads
    import os

    # Auto-update templates (unless fast mode)
    if not fast:
        jm.log_info("nuclei: updating templates...")
        run_tool(["nuclei", "-update-templates", "-silent"], timeout=120)

    # Config from env
    min_sev    = os.getenv("NUCLEI_MIN_SEVERITY", "low")
    tags       = os.getenv("NUCLEI_TAGS", "cve,misconfig,exposure,rce,sqli,xss,lfi,ssrf")
    custom_dir = os.getenv("NUCLEI_TEMPLATES_DIR", "")

    if fast:
        min_sev = "high"
        tags    = "cve,rce"

    # Write targets to temp file (better than stdin for large lists)
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("
".join(urls))
        targets_file = tf.name

    cmd = [
        "nuclei", "-list", targets_file,
        "-json", "-silent",
        "-severity", f"{min_sev},medium,high,critical" if min_sev not in ("high","critical") else "high,critical",
        "-tags", tags,
    ]

    # Custom templates dir
    if custom_dir and Path(custom_dir).exists():
        cmd += ["-t", custom_dir]

    # Auth headers
    if auth:
        for flag in auth.nuclei_flags():
            cmd.append(flag)

    r = run_tool(cmd, timeout=600)
    Path(targets_file).unlink(missing_ok=True)

    from normalizer.parsers.nuclei_parser import parse_nuclei
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
            f = parse_nuclei(d, scan_id)
            if f:
                findings.append(f)
                jm.log_finding(f.severity.value, f.title)
        except Exception:
            pass
    jm.log_ok(f"nuclei: {len(findings)} findings")
    return findings


def _run_ssl_audit(host, scan_id, jm):
    findings = []
    jm.log_info("Running: sslscan")
    r = run_tool(["sslscan", "--xml=/tmp/sslscan.xml", f"{host}:443"], timeout=90)
    if Path("/tmp/sslscan.xml").exists():
        from normalizer.parsers.sslscan_parser import parse_sslscan
        findings.extend(parse_sslscan("/tmp/sslscan.xml", host, scan_id))

    jm.log_info("Running: testssl.sh")
    r = run_tool(
        ["testssl.sh", "--jsonfile=/tmp/testssl.json", "--severity", "LOW", "--quiet", host],
        timeout=180
    )
    if Path("/tmp/testssl.json").exists():
        try:
            data = json.loads(Path("/tmp/testssl.json").read_text())
            sev_map = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"info","OK":"info"}
            for item in data:
                sev = sev_map.get(item.get("severity","INFO"), "info")
                if sev in ("critical","high","medium"):
                    findings.append(NormalizedFinding(
                        scan_id=scan_id, tool="testssl.sh",
                        finding_type="ssl_issue",
                        title=f"SSL: {item.get('id','')}: {item.get('finding','')}",
                        severity=Severity(sev),
                        host=host, port=443,
                        description=item.get("finding",""),
                        raw_output=str(item),
                        fingerprint_hash=make_hash("testssl", host, item.get("id","")),
                    ))
        except Exception:
            pass
    jm.log_ok(f"SSL audit: {len(findings)} issues")
    return findings


def _run_sqlmap(urls, host, scan_id, jm, auth=None):
    findings = []
    if not tool_available("sqlmap"):
        return findings
    jm.log_info("Running: sqlmap")
    for url in urls[:2]:
        cmd = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
               "--forms", "--output-dir=/tmp/sqlmap_out", "--quiet"]
        if auth:
            cmd += auth.sqlmap_flags()
        r = run_tool(cmd, timeout=180)
        if "is vulnerable" in r.stdout.lower() or "injection" in r.stdout.lower():
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="sqlmap",
                finding_type="sql_injection",
                title=f"SQL Injection at {url}",
                severity=Severity.high,
                host=host, url=url,
                description="sqlmap confirmed SQL injection.",
                remediation="Use parameterised queries / prepared statements.",
                raw_output=r.stdout[:2000],
                fingerprint_hash=make_hash("sqlmap", host, url),
            ))
            jm.log_finding("high", f"SQLi at {url}")
    return findings


def _is_wordpress(host, auth=None):
    try:
        import requests
        kw = {"timeout": 10, "allow_redirects": True}
        if auth:
            kw.update(auth.requests_kwargs())
        r = requests.get(f"http://{host}/wp-login.php", **kw)
        return "WordPress" in r.text or "wp-" in r.text
    except Exception:
        return False


def _run_wpscan(url, host, scan_id, jm):
    findings = []
    if not tool_available("wpscan"):
        return findings
    jm.log_info("Running: wpscan")
    r = run_tool(
        ["wpscan","--url",url,"--format","json","--no-banner","--output","/tmp/wpscan.json"],
        timeout=240
    )
    if Path("/tmp/wpscan.json").exists():
        try:
            data = json.loads(Path("/tmp/wpscan.json").read_text())
            for vuln in data.get("vulnerabilities",[]):
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="wpscan",
                    finding_type="wordpress_vulnerability",
                    title=vuln.get("title","WordPress vulnerability"),
                    severity=Severity.medium,
                    host=host, url=url,
                    cve_ids=vuln.get("references",{}).get("cve",[]),
                    description=str(vuln),
                    raw_output=str(vuln),
                    fingerprint_hash=make_hash("wpscan", host, vuln.get("title","")),
                ))
        except Exception:
            pass
    jm.log_ok(f"wpscan: {len(findings)} findings")
    return findings
