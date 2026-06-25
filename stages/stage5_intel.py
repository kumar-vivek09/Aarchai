"""Stage 5 — Intelligence: CVE/NVD, EPSS, MITRE, VirusTotal, Exploit Mapping."""
from __future__ import annotations
import asyncio
from config import NVD_API_KEY, VIRUSTOTAL_API_KEY
from utils.rate_limiter import nvd_get, virustotal_get
from utils.exploit_mapper import enrich_finding_exploits


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    from core.db import Finding
    jm.log_stage("stage5_intel", "CVE enrichment + exploit mapping + VirusTotal")

    findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
    enriched  = 0
    kev_count = 0

    for f in findings:
        cve_ids = f.cve_ids or []

        # NVD enrichment
        for cve_id in cve_ids[:5]:
            try:
                _enrich_nvd(f, cve_id, jm)
                enriched += 1
            except Exception as e:
                jm.log_warn(f"NVD {cve_id}: {e}")

        # EPSS
        if cve_ids:
            try:
                _enrich_epss(f, cve_ids[:1])
            except Exception:
                pass

        # MITRE ATT&CK
        f.mitre_tactics = _map_mitre(f.finding_type or "", f.title or "")

        # Exploit mapping (CISA KEV + ExploitDB + GitHub PoC)
        if cve_ids and not fast:
            try:
                result = enrich_finding_exploits(f, jm)
                if result["in_kev"]:
                    kev_count += 1
                if result["exploit_available"]:
                    # Bump severity of exploitable findings
                    if f.severity == "medium":
                        f.severity = "high"
                    elif f.severity == "low":
                        f.severity = "medium"
                    jm.log_warn(f"Exploit available for {cve_ids[0]}: {result['exploitdb'][:1]}")
            except Exception as e:
                jm.log_warn(f"Exploit map: {e}")

        # Update confidence with new data
        from utils.confidence import score as conf_score
        f.confidence_score = conf_score(
            f.tool, f.finding_type, f.severity,
            has_cve=bool(f.cve_ids), cvss=f.cvss_score, in_kev=f.in_cisa_kev
        )
        session.commit()

    # VirusTotal
    if VIRUSTOTAL_API_KEY and not fast:
        try:
            _enrich_virustotal(target.host, scan_id, session, jm)
        except Exception as e:
            jm.log_warn(f"VirusTotal: {e}")

    jm.log_ok(f"Intel: {enriched} CVEs enriched, {kev_count} in CISA KEV, exploit links added")
    return [], []


def _enrich_nvd(finding, cve_id: str, jm):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    data = nvd_get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers=headers
    )
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return
    cve_data = vulns[0].get("cve", {})
    for entry in cve_data.get("metrics", {}).get("cvssMetricV31", []):
        score = entry.get("cvssData", {}).get("baseScore")
        if score:
            finding.cvss_score = float(score)
            break
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            finding.description = (finding.description or "") + f"[NVD] {desc['value']}"
            break


def _enrich_epss(finding, cve_ids: list):
    import requests
    resp = requests.get(
        f"https://api.first.org/data/v1/epss?cve={','.join(cve_ids)}",
        timeout=10
    )
    if resp.ok:
        data = resp.json().get("data", [])
        if data:
            finding.epss_score = float(data[0].get("epss", 0))


def _map_mitre(finding_type: str, title: str) -> list:
    mapping = {
        "sql_injection":           ["T1190 Exploit Public-Facing Application"],
        "xss":                     ["T1190 Exploit Public-Facing Application"],
        "rce":                     ["T1190 Exploit Public-Facing Application", "T1059 Command Execution"],
        "open_port":               ["T1046 Network Service Discovery"],
        "ssl_issue":               ["T1557 Adversary-in-the-Middle"],
        "secret_in_git":           ["T1552.001 Credentials in Files"],
        "secret_in_js":            ["T1552.001 Credentials in Files"],
        "env_exposed":             ["T1552.001 Credentials in Files"],
        "git_exposed":             ["T1552.001 Credentials in Files"],
        "default_credential":      ["T1078 Valid Accounts", "T1110.001 Password Guessing"],
        "backup_exposed":          ["T1552.001 Credentials in Files", "T1083 File Discovery"],
        "weak_ssl_protocol":       ["T1557 Adversary-in-the-Middle"],
        "weak_cipher":             ["T1557 Adversary-in-the-Middle"],
        "directory_found":         ["T1083 File and Directory Discovery"],
        "malicious_reputation":    ["T1566 Phishing"],
        "wordpress_vulnerability": ["T1190 Exploit Public-Facing Application"],
    }
    tactics = []
    for key, val in mapping.items():
        if key in finding_type.lower():
            tactics.extend(val)
    return list(set(tactics))


def _enrich_virustotal(host: str, scan_id: int, session, jm):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = virustotal_get(
        f"https://www.virustotal.com/api/v3/domains/{host}",
        headers=headers
    )
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    if malicious > 0:
        from normalizer.schema import NormalizedFinding, Severity
        from normalizer.dedup import make_hash
        from core.db import Finding as DBFinding
        f = DBFinding(
            scan_id=scan_id, tool="virustotal",
            finding_type="malicious_reputation",
            title=f"VirusTotal: {host} flagged by {malicious} engines",
            severity="high" if malicious > 3 else "medium",
            host=host,
            description=f"Flagged by {malicious} security vendors.",
            fingerprint_hash=make_hash("virustotal", host, str(malicious)),
            raw_output=str(stats),
        )
        session.add(f); session.commit()
        jm.log_finding("high" if malicious > 3 else "medium", f.title)
