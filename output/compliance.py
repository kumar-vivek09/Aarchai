"""Compliance report generation — OWASP Top 10, PCI-DSS, ISO 27001, NIST CSF."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime

# ── OWASP Top 10 2021 mapping ────────────────────────────────────────────
OWASP_TOP10 = {
    "A01": ("Broken Access Control",          ["directory_found", "cors_misconfiguration", "api_spec_exposed", "actuator_exposed"]),
    "A02": ("Cryptographic Failures",          ["ssl_issue", "weak_ssl_protocol", "weak_cipher", "private_key_exposed", "secret_in_js", "env_exposed"]),
    "A03": ("Injection",                       ["sql_injection", "xss", "rce", "command_injection", "graphql_introspection"]),
    "A04": ("Insecure Design",                 ["default_credential", "weak_ssl_protocol"]),
    "A05": ("Security Misconfiguration",       ["phpinfo_exposed", "git_exposed", "backup_exposed", "sensitive_file_exposed", "cloud_metadata_exposed", "smb_null_session"]),
    "A06": ("Vulnerable & Outdated Components",["wordpress_vulnerability", "web_vulnerability"]),
    "A07": ("Identification & Authentication Failures", ["default_credential", "jwt_vulnerability", "password_spray_opportunity", "asrep_roasting", "ad_anonymous_ldap"]),
    "A08": ("Software & Data Integrity Failures", ["git_exposed", "secret_in_git", "backup_exposed"]),
    "A09": ("Security Logging & Monitoring Failures", ["default_credential", "smb_signing_disabled"]),
    "A10": ("Server-Side Request Forgery",    ["cloud_metadata_exposed"]),
}

# ── PCI-DSS v4.0 mapping ─────────────────────────────────────────────────
PCI_DSS = {
    "6.3": ("Protect web-facing applications", ["xss", "sql_injection", "rce", "web_vulnerability", "api_spec_exposed"]),
    "6.4": ("Protect all system components",   ["wordpress_vulnerability", "ssl_issue", "weak_ssl_protocol"]),
    "7.2": ("Access control systems",          ["default_credential", "cors_misconfiguration", "actuator_exposed"]),
    "8.3": ("Authentication",                  ["default_credential", "jwt_vulnerability", "ad_anonymous_ldap"]),
    "3.5": ("Protection of stored cardholder data", ["backup_exposed", "git_exposed", "env_exposed", "secret_in_js"]),
    "4.2": ("Strong cryptography in transit",  ["ssl_issue", "weak_cipher", "weak_ssl_protocol"]),
    "10.3":("Protect audit logs",              ["smb_null_session"]),
    "11.3":("External + internal penetration testing", ["open_port", "smb_signing_disabled", "cloud_metadata_exposed"]),
}

# ── ISO 27001:2022 mapping ────────────────────────────────────────────────
ISO_27001 = {
    "A.8.8":  ("Management of technical vulnerabilities", ["wordpress_vulnerability", "web_vulnerability", "ssl_issue"]),
    "A.8.9":  ("Configuration management",               ["phpinfo_exposed", "git_exposed", "default_credential", "smb_null_session"]),
    "A.8.24": ("Use of cryptography",                    ["ssl_issue", "weak_cipher", "weak_ssl_protocol", "private_key_exposed"]),
    "A.8.28": ("Secure coding",                          ["xss", "sql_injection", "rce", "secret_in_js"]),
    "A.5.15": ("Access control",                         ["default_credential", "ad_anonymous_ldap", "cors_misconfiguration"]),
    "A.8.12": ("Data leakage prevention",                ["backup_exposed", "env_exposed", "git_exposed", "s3_bucket_found"]),
    "A.8.20": ("Networks security",                      ["open_port", "smb_signing_disabled", "cloud_metadata_exposed"]),
    "A.8.21": ("Security of network services",           ["weak_ssl_protocol", "ssl_issue"]),
    "A.5.28": ("Collection of evidence",                 ["smb_null_session"]),
}

# ── NIST CSF 2.0 mapping ─────────────────────────────────────────────────
NIST_CSF = {
    "ID.AM": ("Asset Management",       ["asn_discovery", "open_port", "s3_bucket_found", "azure_blob_exposed"]),
    "PR.AA": ("Identity Management",    ["default_credential", "jwt_vulnerability", "ad_anonymous_ldap", "asrep_roasting"]),
    "PR.DS": ("Data Security",          ["backup_exposed", "env_exposed", "private_key_exposed", "s3_bucket_found", "credential_breach"]),
    "PR.PS": ("Platform Security",      ["phpinfo_exposed", "git_exposed", "weak_ssl_protocol", "default_credential"]),
    "DE.CM": ("Monitoring",             ["cloud_metadata_exposed", "smb_signing_disabled"]),
    "RS.CO": ("Incident Response",      ["malicious_reputation", "credential_breach"]),
    "ID.RA": ("Risk Assessment",        ["xss", "sql_injection", "rce", "asrep_roasting", "subdomain_takeover"]),
    "PR.IR": ("Technology Resilience",  ["smb_null_session", "cert_expiry", "waf_bypass"]),
}


def generate_compliance_report(findings: list, scan_id: int, target, framework: str, out_dir: Path) -> Path:
    """Generate a compliance gap analysis report for the given framework."""
    framework = framework.lower()

    if framework == "owasp":
        mapping = OWASP_TOP10
        title = "OWASP Top 10 2021 — Gap Analysis"
        color = "#e03e2d"
    elif framework == "pci":
        mapping = PCI_DSS
        title = "PCI-DSS v4.0 — Compliance Gap Analysis"
        color = "#1a6b9a"
    elif framework == "iso27001":
        mapping = ISO_27001
        title = "ISO 27001:2022 — Annex A Control Assessment"
        color = "#2d7d46"
    elif framework == "nist":
        mapping = NIST_CSF
        title = "NIST CSF 2.0 — Cybersecurity Framework Assessment"
        color = "#7c3aed"
    else:
        raise ValueError(f"Unknown framework: {framework}")

    # Map findings to controls
    finding_types = {f.finding_type or "" for f in findings}
    severities = {}
    for f in findings:
        key = f.finding_type or ""
        if key not in severities or _sev_rank(f.severity) > _sev_rank(severities[key]):
            severities[key] = f.severity

    control_results = {}
    for control_id, (control_name, affected_types) in mapping.items():
        affected = [t for t in affected_types if t in finding_types]
        max_sev = max((_sev_rank(severities.get(t, "info")) for t in affected), default=0)
        status = "FAIL" if affected else "PASS"
        control_results[control_id] = {
            "name": control_name,
            "status": status,
            "findings": affected,
            "severity": _rank_to_sev(max_sev),
        }

    pass_count = sum(1 for v in control_results.values() if v["status"] == "PASS")
    fail_count = sum(1 for v in control_results.values() if v["status"] == "FAIL")
    score = int(pass_count / len(control_results) * 100) if control_results else 100

    html = _render_compliance_html(title, color, framework, control_results,
                                   pass_count, fail_count, score, scan_id, target)
    out_path = out_dir / f"compliance_{framework}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(str(sev).lower(), 0)

def _rank_to_sev(rank: int) -> str:
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(rank, "info")


def _render_compliance_html(title, color, framework, controls, passed, failed, score, scan_id, target) -> str:
    score_color = "#22c55e" if score >= 70 else "#f59e0b" if score >= 50 else "#ef4444"
    rows = ""
    for cid, info in controls.items():
        st_color = "#22c55e" if info["status"] == "PASS" else "#ef4444"
        rows += f"""
        <tr>
          <td style="font-family:monospace;font-weight:600">{cid}</td>
          <td>{info["name"]}</td>
          <td><span style="color:{st_color};font-weight:700">{info["status"]}</span></td>
          <td style="color:var(--sev-{info['severity']})">{info["severity"].upper()}</td>
          <td style="font-size:12px;font-family:monospace">{", ".join(info["findings"][:4]) or "—"}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>{title}</title>
<style>
  @import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap");
  :root{{--bg:#0a0c10;--surface:#0f1117;--card:#13161e;--border:#1e2535;--text:#e2e8f0;--muted:#7a8499;
    --sev-critical:#ef4444;--sev-high:#f97316;--sev-medium:#f59e0b;--sev-low:#3b82f6;--sev-info:#64748b}}
  body{{font-family:"Inter",sans-serif;background:var(--bg);color:var(--text);margin:0;padding:24px}}
  h1{{font-size:22px;margin-bottom:4px;color:{color}}}
  .meta{{color:var(--muted);font-size:12px;margin-bottom:28px}}
  .scorecard{{display:flex;gap:16px;margin-bottom:28px}}
  .sc{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px;flex:1;text-align:center}}
  .sc-num{{font-family:"JetBrains Mono",monospace;font-size:32px;font-weight:700}}
  .sc-lbl{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}}
  th{{background:var(--surface);padding:12px 14px;text-align:left;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}}
  td{{padding:11px 14px;border-bottom:1px solid var(--border);font-size:13px}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:rgba(255,255,255,.02)}}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">Target: {getattr(target, "value", str(target))} &bull; Scan #{scan_id} &bull; {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
<div class="scorecard">
  <div class="sc"><div class="sc-num" style="color:{score_color}">{score}%</div><div class="sc-lbl">Compliance Score</div></div>
  <div class="sc"><div class="sc-num" style="color:#22c55e">{passed}</div><div class="sc-lbl">Controls Passed</div></div>
  <div class="sc"><div class="sc-num" style="color:#ef4444">{failed}</div><div class="sc-lbl">Controls Failed</div></div>
</div>
<table>
  <thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Risk Level</th><th>Triggered By</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</body></html>"""
