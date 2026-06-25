"""Parse whatweb JSON output."""
from __future__ import annotations
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


def parse_whatweb(data: list, host: str, scan_id: int):
    findings = []
    for entry in (data if isinstance(data, list) else [data]):
        url    = entry.get("target", entry.get("uri", host))
        plugins = entry.get("plugins", {})
        if not plugins:
            continue
        tech_list = []
        for name, info in plugins.items():
            ver = info.get("version", [])
            ver_str = f" {ver[0]}" if ver else ""
            tech_list.append(f"{name}{ver_str}")

        if tech_list:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="whatweb",
                finding_type="tech_fingerprint",
                title=f"Fingerprint: {', '.join(tech_list[:8])}",
                severity=Severity.info,
                host=host, url=url,
                description=f"WhatWeb identified the following technologies at {url}:\n" + "\n".join(tech_list),
                raw_output=str(entry)[:2000],
                fingerprint_hash=make_hash("whatweb", host, url, ",".join(sorted(tech_list))),
            ))
    return findings
