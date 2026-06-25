"""Rule-based confidence scoring for findings (0-100)."""
from __future__ import annotations

# Tool reliability scores (higher = more trustworthy)
TOOL_CONFIDENCE = {
    "nmap":       85,
    "nuclei":     80,
    "testssl.sh": 90,
    "sslscan":    85,
    "sqlmap":     90,   # sqlmap confirms before reporting
    "wpscan":     80,
    "dalfox":     85,
    "whois":      95,
    "shodan":     75,
    "virustotal": 80,
    "crt.sh":     90,
    "httpx":      90,
    "whatweb":    75,
    "wafw00f":    70,
    "gobuster":   70,
    "nikto":      55,   # nikto has high FP rate
    "theHarvester": 70,
    "amass-passive": 80,
    "gitleaks":   85,
    "trufflehog": 85,
}

# Finding type adjustments
TYPE_ADJUSTMENT = {
    "sql_injection":           +15,
    "xss":                     +10,
    "rce":                     +15,
    "ssl_issue":               +10,
    "weak_ssl_protocol":       +10,
    "weak_cipher":             +5,
    "open_port":               +5,
    "directory_found":         -10,  # many FPs
    "web_vulnerability":       -5,   # nikto FPs
    "tech_fingerprint":        0,
    "whois_info":              +5,
    "secret_exposed":          +20,
    "default_credential":      +20,
    "git_exposed":             +25,
    "env_exposed":             +25,
    "malicious_reputation":    +5,
    "wordpress_vulnerability": +5,
}

# Severity adjustments (critical findings need to be verified)
SEV_ADJUSTMENT = {
    "critical": -5,   # penalise slightly — encourage verification
    "high":     0,
    "medium":   +5,
    "low":      +10,
    "info":     +10,
}

# Boost if CVE + CVSS score present
CVE_BOOST    = +10
HIGH_CVSS    = +10   # CVSS >= 8.0
CISA_KEV_BOOST = +15


def score(tool: str, finding_type: str, severity: str,
          has_cve: bool = False, cvss: float = None,
          in_kev: bool = False) -> int:
    base  = TOOL_CONFIDENCE.get(tool, 60)
    base += TYPE_ADJUSTMENT.get(finding_type, 0)
    base += SEV_ADJUSTMENT.get(severity, 0)
    if has_cve:
        base += CVE_BOOST
    if cvss and cvss >= 8.0:
        base += HIGH_CVSS
    if in_kev:
        base += CISA_KEV_BOOST
    return max(0, min(100, base))


def apply_suppression_rules(findings: list, session) -> list:
    """Mark findings as suppressed if they match any suppression rule."""
    from core.db import SuppressionRule
    rules = session.query(SuppressionRule).all()
    for f in findings:
        for rule in rules:
            if rule.tool and rule.tool != f.tool:
                continue
            if rule.finding_type and rule.finding_type != f.finding_type:
                continue
            if rule.title_pattern and rule.title_pattern.lower() not in (f.title or "").lower():
                continue
            f.is_suppressed = True
            break
    return findings
