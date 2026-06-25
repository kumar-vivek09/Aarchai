"""Fingerprint-based deduplication for findings."""
import hashlib


def make_hash(*parts: str) -> str:
    """Create a stable fingerprint from key identifying parts."""
    raw = "|".join(str(p).lower().strip() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def dedup_findings(findings: list) -> list:
    """Remove duplicate findings by fingerprint hash."""
    seen = set()
    out  = []
    for f in findings:
        fh = f.fingerprint_hash or make_hash(f.tool, f.host, f.title)
        if fh not in seen:
            seen.add(fh)
            out.append(f)
    return out
