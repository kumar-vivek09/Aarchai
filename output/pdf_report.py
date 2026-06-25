"""Generate PDF report using WeasyPrint."""
from __future__ import annotations
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from config import TEMPLATES_DIR
from output.html_dashboard import generate_dashboard


def generate_pdf(findings: list, assets: list, scan_id: int, target, out_dir: Path):
    out_dir = Path(out_dir)

    # Render HTML first
    from jinja2 import Environment, FileSystemLoader
    env  = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=False)
    tmpl = env.get_template("report.html")

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    findings_data = []
    for f in sorted(findings,
                    key=lambda x: ["critical","high","medium","low","info","unknown"].index(
                        x.severity.value if hasattr(x.severity,"value") else "info")):
        findings_data.append({
            "severity":     f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "tool":         f.tool,
            "finding_type": f.finding_type,
            "title":        f.title,
            "host":         f.host or "",
            "port":         f.port or "",
            "url":          f.url or "",
            "cve_ids":      f.cve_ids or [],
            "cvss_score":   f.cvss_score,
            "description":  f.description or "",
            "remediation":  f.remediation or "",
        })

    html_str = tmpl.render(
        scan_id=scan_id,
        target=target.value,
        target_type=target.type,
        findings=findings_data,
        assets=assets,
        sev_counts=sev_counts,
        total_findings=len(findings),
        total_assets=len(assets),
    )

    html_path = out_dir / "report.html"
    html_path.write_text(html_str, encoding="utf-8")

    # Convert to PDF
    from weasyprint import HTML as WP_HTML
    WP_HTML(string=html_str, base_url=str(out_dir)).write_pdf(str(out_dir / "report.pdf"))
