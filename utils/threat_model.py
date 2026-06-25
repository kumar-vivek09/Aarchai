"""STRIDE threat model generator based on discovered tech stack + findings."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime

# STRIDE categories
STRIDE = {
    "Spoofing":              "An attacker impersonates another entity",
    "Tampering":             "An attacker modifies data or code",
    "Repudiation":           "An attacker denies performing an action",
    "Information Disclosure":"An attacker gains access to protected data",
    "Denial of Service":     "An attacker disrupts service availability",
    "Elevation of Privilege":"An attacker gains unauthorized permissions",
}

# Finding type → STRIDE threats
FINDING_TO_STRIDE = {
    "xss":                  ["Spoofing", "Tampering", "Information Disclosure"],
    "sql_injection":        ["Tampering", "Information Disclosure", "Elevation of Privilege"],
    "rce":                  ["Tampering", "Elevation of Privilege"],
    "command_injection":    ["Tampering", "Elevation of Privilege"],
    "cors_misconfiguration":["Information Disclosure", "Spoofing"],
    "jwt_vulnerability":    ["Spoofing", "Elevation of Privilege"],
    "default_credential":   ["Spoofing", "Elevation of Privilege"],
    "asrep_roasting":       ["Spoofing", "Elevation of Privilege"],
    "ad_anonymous_ldap":    ["Information Disclosure"],
    "smb_null_session":     ["Information Disclosure", "Spoofing"],
    "smb_signing_disabled": ["Spoofing", "Tampering", "Repudiation"],
    "ssl_issue":            ["Information Disclosure", "Spoofing"],
    "weak_ssl_protocol":    ["Information Disclosure", "Spoofing"],
    "env_exposed":          ["Information Disclosure"],
    "git_exposed":          ["Information Disclosure", "Tampering"],
    "backup_exposed":       ["Information Disclosure"],
    "s3_bucket_found":      ["Information Disclosure"],
    "cloud_metadata_exposed":["Information Disclosure", "Elevation of Privilege"],
    "subdomain_takeover":   ["Spoofing"],
    "credential_breach":    ["Spoofing", "Information Disclosure"],
    "graphql_introspection":["Information Disclosure"],
    "graphql_batching":     ["Denial of Service"],
    "open_port":            ["Information Disclosure"],
    "api_spec_exposed":     ["Information Disclosure"],
    "hidden_parameters":    ["Tampering"],
    "waf_bypass":           ["Tampering"],
    "cert_expiry":          ["Denial of Service", "Spoofing"],
    "wildcard_cert":        ["Spoofing"],
    "malicious_reputation": ["Denial of Service"],
}

# Tech stack → additional threats
TECH_THREATS = {
    "WordPress": ["Elevation of Privilege via plugin vulnerabilities", "Denial of Service via XML-RPC"],
    "React":     ["Information Disclosure via source maps", "Tampering via DOM-based XSS"],
    "Angular":   ["Tampering via template injection"],
    "Express":   ["Information Disclosure via X-Powered-By header"],
    "Django":    ["Information Disclosure via debug mode"],
    "Laravel":   ["Information Disclosure via debug mode", "Tampering via mass assignment"],
    "jQuery":    ["Tampering via prototype pollution"],
}


def generate_stride_model(findings, assets, target, scan_id, out_dir: Path = None) -> dict:
    """Generate a STRIDE threat model and return structured data + HTML report."""
    # Aggregate threats
    stride_map = {k: [] for k in STRIDE}

    for f in findings:
        ftype = getattr(f, "finding_type", "") or ""
        threats = FINDING_TO_STRIDE.get(ftype, [])
        for threat in threats:
            if threat in stride_map:
                stride_map[threat].append({
                    "finding": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "info"),
                    "ftype": ftype,
                })

    # Tech stack threats
    tech_assets = [a for a in assets if getattr(a, "tech_stack", None)]
    tech_found = []
    for a in tech_assets:
        tech_found.extend(getattr(a, "tech_stack", []) or [])

    additional_threats = []
    for tech in set(tech_found):
        for threat_desc in TECH_THREATS.get(tech, []):
            stride_category = threat_desc.split(" via")[0].split(" ")[0]
            if stride_category in stride_map:
                additional_threats.append({"tech": tech, "threat": threat_desc, "stride": stride_category})

    result = {
        "target": str(getattr(target, "value", target)),
        "scan_id": scan_id,
        "generated_at": datetime.utcnow().isoformat(),
        "tech_stack": list(set(tech_found)),
        "stride": {k: v for k, v in stride_map.items()},
        "additional_threats": additional_threats,
        "risk_summary": {
            k: max((_sev_rank(t["severity"]) for t in v), default=0)
            for k, v in stride_map.items()
        },
    }

    if out_dir:
        html = _render_stride_html(result)
        out_path = out_dir / "threat_model_stride.html"
        out_path.write_text(html, encoding="utf-8")
        (out_dir / "threat_model_stride.json").write_text(
            json.dumps(result, indent=2, default=str), encoding="utf-8"
        )

    return result


def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(str(sev).lower(), 0)

def _rank_color(rank: int) -> str:
    return {4: "#ef4444", 3: "#f97316", 2: "#f59e0b", 1: "#3b82f6", 0: "#64748b"}.get(rank, "#64748b")


def _render_stride_html(data: dict) -> str:
    cards = ""
    for stride_cat, desc in STRIDE.items():
        threats = data["stride"].get(stride_cat, [])
        risk = data["risk_summary"].get(stride_cat, 0)
        color = _rank_color(risk)
        threat_rows = "".join(
            f'<div style="font-size:11.5px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04)">'
            f'<span style="color:{_rank_color(_sev_rank(t["severity"]))}">[{t["severity"].upper()}]</span> {t["finding"]}'
            f'</div>' for t in threats[:8]
        ) or '<div style="color:#3d4661;font-size:11px">No threats identified</div>'

        cards += f"""
        <div style="background:#13161e;border:1px solid #1e2535;border-radius:10px;padding:18px;border-left:3px solid {color}">
          <div style="font-size:15px;font-weight:600;color:{color};margin-bottom:4px">{stride_cat}</div>
          <div style="font-size:11px;color:#7a8499;margin-bottom:12px">{desc}</div>
          <div style="font-size:10px;font-weight:600;color:#3d4661;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px">
            {len(threats)} threat(s) identified
          </div>
          {threat_rows}
        </div>"""

    tech_badges = "".join(
        f'<span style="background:rgba(20,184,166,.08);border:1px solid rgba(20,184,166,.2);'
        f'border-radius:5px;padding:3px 10px;font-size:11px;color:#14b8a6;font-family:monospace">{t}</span> '
        for t in (data.get("tech_stack") or [])[:20]
    ) or '<span style="color:#3d4661">Not detected</span>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>STRIDE Threat Model</title>
<style>
@import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap");
body{{font-family:"Inter",sans-serif;background:#0a0c10;color:#e2e8f0;margin:0;padding:28px}}
h1{{font-size:22px;background:linear-gradient(135deg,#e2e8f0,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:4px}}
.meta{{color:#7a8499;font-size:12px;margin-bottom:24px}}
.grid{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:24px}}
@media(max-width:900px){{.grid{{grid-template-columns:1fr 1fr}}}}
</style>
</head>
<body>
<h1>STRIDE Threat Model</h1>
<div class="meta">Target: {data["target"]} &bull; Scan #{data["scan_id"]} &bull; {data["generated_at"][:16]} UTC</div>
<div style="background:#13161e;border:1px solid #1e2535;border-radius:10px;padding:18px;margin-bottom:20px">
  <div style="font-size:11px;color:#7a8499;text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px;font-weight:600">Detected Technology Stack</div>
  {tech_badges}
</div>
<div class="grid">{cards}</div>
</body></html>"""
