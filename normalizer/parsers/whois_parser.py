"""Parse whois text output."""
from __future__ import annotations
import re
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


def parse_whois(raw: str, host: str, scan_id: int):
    findings = []
    if not raw:
        return findings

    info = {}
    for line in raw.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if val and key in ("registrar", "creation date", "expiry date",
                           "registrant", "name server", "dnssec"):
            info.setdefault(key, val)

    if info:
        desc = "\n".join(f"{k}: {v}" for k, v in info.items())
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="whois",
            finding_type="whois_info",
            title=f"WHOIS: {host} registered with {info.get('registrar', 'unknown')}",
            severity=Severity.info,
            host=host,
            description=desc,
            raw_output=raw[:3000],
            fingerprint_hash=make_hash("whois", host),
        ))

    # Check for expiring domain (within 30 days)
    expiry = info.get("expiry date", "")
    if expiry:
        try:
            from datetime import datetime, timezone
            exp_date = None
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
                try:
                    exp_date = datetime.strptime(expiry[:20], fmt)
                    break
                except ValueError:
                    continue
            if exp_date:
                exp_date = exp_date.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (exp_date - now).days
                if days_left < 30:
                    findings.append(NormalizedFinding(
                        scan_id=scan_id, tool="whois",
                        finding_type="domain_expiry",
                        title=f"Domain expiring soon: {days_left} days left",
                        severity=Severity.high if days_left < 7 else Severity.medium,
                        host=host,
                        description=f"Domain {host} expires on {expiry} ({days_left} days).",
                        remediation="Renew the domain immediately to prevent hijacking.",
                        raw_output=expiry,
                        fingerprint_hash=make_hash("whois_expiry", host, expiry),
                    ))
        except Exception:
            pass

    return findings
