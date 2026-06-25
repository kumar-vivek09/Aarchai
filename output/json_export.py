"""Export findings as JSON and CSV."""
from __future__ import annotations
import json
import csv
from pathlib import Path


def export_json_csv(findings: list, assets: list, scan_id: int, out_dir: Path):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    data = {
        "scan_id": scan_id,
        "findings": [_finding_to_dict(f) for f in findings],
        "assets":   assets,
    }
    (out_dir / "findings.json").write_text(
        json.dumps(data, indent=2, default=str), encoding="utf-8"
    )

    # CSV
    if findings:
        csv_path = out_dir / "findings.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "severity", "tool", "finding_type", "title",
                "host", "port", "url", "cve_ids", "cvss_score",
                "description", "remediation"
            ])
            writer.writeheader()
            for f in findings:
                writer.writerow(_finding_to_csv_row(f))


def _finding_to_dict(f) -> dict:
    return {
        "tool":             f.tool,
        "finding_type":     f.finding_type,
        "title":            f.title,
        "severity":         f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        "host":             f.host,
        "port":             f.port,
        "url":              f.url,
        "cve_ids":          f.cve_ids or [],
        "cvss_score":       f.cvss_score,
        "epss_score":       f.epss_score,
        "mitre_tactics":    f.mitre_tactics or [],
        "description":      f.description,
        "remediation":      f.remediation,
        "references":       f.references or [],
        "fingerprint_hash": f.fingerprint_hash,
    }


def _finding_to_csv_row(f) -> dict:
    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    return {
        "severity":     sev,
        "tool":         f.tool,
        "finding_type": f.finding_type,
        "title":        f.title,
        "host":         f.host or "",
        "port":         f.port or "",
        "url":          f.url or "",
        "cve_ids":      ",".join(f.cve_ids or []),
        "cvss_score":   f.cvss_score or "",
        "description":  (f.description or "")[:300],
        "remediation":  (f.remediation or "")[:200],
    }
