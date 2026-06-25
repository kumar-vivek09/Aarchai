"""Stage 3 — Web Surface Mapping: crawl, fingerprint, directory enum."""
from __future__ import annotations
import json
import concurrent.futures
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from stages.base import run_tool, tool_available


def run(
    target,
    scan_id,
    session,
    jm,
    fast=False,
    out_dir=None,
    auth=None,
    scope=None,
):
    findings = []
    assets   = []
    host     = target.host

    # Build URL list to scan
    urls = _build_url_list(host, session, scan_id)
    jm.log_stage("stage3_web", f"{len(urls)} URLs to probe")

    # httpx — probe all URLs, get tech/status
    jm.log_info("Running: httpx")
    httpx_f, httpx_a = _run_httpx(urls, host, scan_id, jm)
    findings.extend(httpx_f); assets.extend(httpx_a)

    # whatweb — technology fingerprinting
    jm.log_info("Running: whatweb")
    ww_f = _run_whatweb(urls[:10], host, scan_id, jm)
    findings.extend(ww_f)

    # wafw00f — WAF detection
    jm.log_info("Running: wafw00f")
    waf_f = _run_wafw00f(urls[:1], host, scan_id, jm)
    findings.extend(waf_f)

    # gobuster / ffuf — directory enumeration
    if not fast:
        jm.log_info("Running: gobuster/ffuf dir enum")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            gf = ex.submit(_run_gobuster_dir, urls[0] if urls else f"http://{host}", host, scan_id, jm)
            nf = ex.submit(_run_nikto, urls[0] if urls else f"http://{host}", host, scan_id, jm, fast)
        findings.extend(gf.result())
        findings.extend(nf.result())
    else:
        dir_f = _run_gobuster_dir(urls[0] if urls else f"http://{host}", host, scan_id, jm)
        findings.extend(dir_f)

    return findings, assets


def _build_url_list(host, session, scan_id):
    from core.db import Asset
    urls = [f"http://{host}", f"https://{host}"]
    # Add URLs from discovered open web ports
    db_assets = session.query(Asset).filter(
        Asset.scan_id == scan_id,
        Asset.asset_type == "port",
        Asset.port.in_([80, 443, 8080, 8443, 8000, 8888, 3000, 5000])
    ).all()
    for a in db_assets:
        scheme = "https" if a.port in (443, 8443) else "http"
        urls.append(f"{scheme}://{a.value}:{a.port}")
    return list(dict.fromkeys(urls))  # dedup preserving order


def _run_httpx(urls, host, scan_id, jm):
    findings = []
    assets   = []
    stdin_data = "\n".join(urls)
    r = run_tool(
        ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code",
         "-content-length", "-follow-redirects"],
        input_data=stdin_data, timeout=120
    )
    from normalizer.parsers.httpx_parser import parse_httpx
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
            f_list, a_list = parse_httpx(d, host, scan_id)
            findings.extend(f_list); assets.extend(a_list)
        except Exception:
            pass
    jm.log_ok(f"httpx: {len(assets)} live URLs")
    return findings, assets


def _run_whatweb(urls, host, scan_id, jm):
    findings = []
    if not tool_available("whatweb"):
        return findings
    for url in urls[:3]:
        r = run_tool(["whatweb", "--log-json=/tmp/whatweb.json", url], timeout=60)
        ww_json = Path("/tmp/whatweb.json")
        if ww_json.exists():
            from normalizer.parsers.whatweb_parser import parse_whatweb
            try:
                data = json.loads(ww_json.read_text() or "[]")
                findings.extend(parse_whatweb(data, host, scan_id))
            except Exception:
                pass
    jm.log_ok(f"whatweb: {len(findings)} tech fingerprints")
    return findings


def _run_wafw00f(urls, host, scan_id, jm):
    findings = []
    if not tool_available("wafw00f"):
        return findings
    for url in urls[:1]:
        r = run_tool(["wafw00f", url, "-o", "/tmp/waf.json", "-f", "json"], timeout=60)
        waf_json = Path("/tmp/waf.json")
        if waf_json.exists():
            try:
                data = json.loads(waf_json.read_text())
                for item in (data if isinstance(data, list) else [data]):
                    waf_name = item.get("firewall") or item.get("detected") or ""
                    if waf_name and waf_name.lower() not in ("none", ""):
                        from normalizer.schema import NormalizedFinding, Severity
                        from normalizer.dedup import make_hash
                        findings.append(NormalizedFinding(
                            scan_id=scan_id, tool="wafw00f",
                            finding_type="waf_detected",
                            title=f"WAF Detected: {waf_name}",
                            severity=Severity.info,
                            host=host,
                            description=f"A Web Application Firewall ({waf_name}) was detected in front of {url}.",
                            raw_output=str(data),
                            fingerprint_hash=make_hash("wafw00f", host, waf_name),
                        ))
            except Exception:
                pass
    jm.log_ok(f"wafw00f: {len(findings)} WAF results")
    return findings


def _run_gobuster_dir(url, host, scan_id, jm):
    findings = []
    wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    if not Path(wordlist).exists():
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not Path(wordlist).exists():
        return findings
    r = run_tool(
        ["gobuster", "dir", "-u", url, "-w", wordlist, "-q",
         "--no-error", "-o", "/tmp/gobuster_dir.txt"],
        timeout=300
    )
    from normalizer.parsers.gobuster_parser import parse_gobuster_dir
    findings = parse_gobuster_dir(r.stdout + Path("/tmp/gobuster_dir.txt").read_text()
                                  if Path("/tmp/gobuster_dir.txt").exists() else r.stdout,
                                  host, scan_id)
    jm.log_ok(f"gobuster dir: {len(findings)} paths found")
    return findings


def _run_nikto(url, host, scan_id, jm, fast):
    findings = []
    if not tool_available("nikto"):
        return findings
    max_time = "60" if fast else "180"
    r = run_tool(["nikto", "-host", url, "-maxtime", max_time, "-Format", "json",
                  "-output", "/tmp/nikto.json", "-nointeractive"], timeout=200)
    if Path("/tmp/nikto.json").exists():
        try:
            data = json.loads(Path("/tmp/nikto.json").read_text())
            from normalizer.schema import NormalizedFinding, Severity
            from normalizer.dedup import make_hash
            for vuln in data.get("vulnerabilities", []):
                sev = "medium" if "OSVDB" in str(vuln) else "info"
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="nikto",
                    finding_type="web_vulnerability",
                    title=vuln.get("msg", "Nikto finding")[:200],
                    severity=Severity(sev),
                    host=host, url=url,
                    description=vuln.get("msg", ""),
                    references=[vuln.get("references", "")],
                    raw_output=str(vuln),
                    fingerprint_hash=make_hash("nikto", host, vuln.get("id", vuln.get("msg","")[:50])),
                ))
        except Exception:
            pass
    jm.log_ok(f"nikto: {len(findings)} findings")
    return findings
