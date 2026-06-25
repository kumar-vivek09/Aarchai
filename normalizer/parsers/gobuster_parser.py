"""Parse gobuster dir output."""
from __future__ import annotations
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash

SENSITIVE_PATHS = {
    "/.git", "/.env", "/admin", "/backup", "/config",
    "/wp-admin", "/phpmyadmin", "/.htaccess", "/server-status",
    "/actuator", "/api/v1", "/.DS_Store", "/robots.txt",
}


def parse_gobuster_dir(raw_output: str, host: str, scan_id: int):
    findings = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "Status:" not in line:
            continue
        # Format: /path (Status: 200) [Size: 1234]
        parts = line.split()
        if not parts:
            continue
        path   = parts[0]
        status = ""
        for p in parts:
            if p.startswith("200") or p.startswith("301") or p.startswith("403"):
                status = p.rstrip(")")
                break

        sensitive = any(path.lower().startswith(s) for s in SENSITIVE_PATHS)
        sev = Severity.medium if sensitive else Severity.info

        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="gobuster",
            finding_type="directory_found",
            title=f"{'[SENSITIVE] ' if sensitive else ''}Found path: {path} [{status}]",
            severity=sev,
            host=host, url=f"http://{host}{path}",
            description=f"HTTP {status} at {path}{'  — potentially sensitive path!' if sensitive else ''}",
            raw_output=line,
            fingerprint_hash=make_hash("gobuster", host, path),
        ))
    return findings
