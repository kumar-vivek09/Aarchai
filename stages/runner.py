"""Pipeline orchestrator v2 — all stages 0-13."""
from __future__ import annotations
import importlib
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.rule import Rule
from plugins.loader import load_plugins

console = Console()

STAGE_MAP = {
    "0":  "stages.stage0_scope",
    "1":  "stages.stage1_passive",
    "2":  "stages.stage2_active",
    "3":  "stages.stage3_web",
    "3b": "stages.stage3b_fingerprint",
    "4":  "stages.stage4_vulns",
    "4b": "stages.stage4b_secrets",
    "5":  "stages.stage5_intel",
    "6":  "stages.stage6_report",
    "7":  "stages.stage7_attacker",
    "8":  "stages.stage8_osint",
    "9":  "stages.stage9_cloud",
    "10": "stages.stage10_api",
    "11": "stages.stage11_network",
    "12": "stages.stage12_ad",
    "13": "stages.stage13_advanced",
    # Aliases
    "passive":     "stages.stage1_passive",
    "active":      "stages.stage2_active",
    "web":         "stages.stage3_web",
    "fingerprint": "stages.stage3b_fingerprint",
    "vulns":       "stages.stage4_vulns",
    "secrets":     "stages.stage4b_secrets",
    "intel":       "stages.stage5_intel",
    "report":      "stages.stage6_report",
    "attacker":    "stages.stage7_attacker",
    "osint":       "stages.stage8_osint",
    "cloud":       "stages.stage9_cloud",
    "api":         "stages.stage10_api",
    "network":     "stages.stage11_network",
    "ad":          "stages.stage12_ad",
    "advanced":    "stages.stage13_advanced",
}

ALL_STAGES = ["0","1","2","3","3b","4","4b","5","6","7","8","9","10","11","12","13"]

STAGE_LABELS = {
    "0": "Scope Validation", "1": "Passive Recon", "2": "Active Recon",
    "3": "Web Scan", "3b": "Fingerprinting", "4": "Vulnerability Scan",
    "4b": "Secret Detection", "5": "Intelligence", "6": "Report Generation",
    "7": "Red Team AI", "8": "OSINT", "9": "Cloud Discovery",
    "10": "API Security", "11": "Network Topology", "12": "AD/Kerberos",
    "13": "Advanced Tests",
}


def resolve_stages(stages_arg: str) -> list[str]:
    if stages_arg.lower() == "all":
        return ALL_STAGES
    return [s.strip() for s in stages_arg.split(",")]


def run_pipeline(target, scan_id, session, jm, stages_arg, output_dir,
                 fast, no_passive, scope=None, auth=None):
    from utils.confidence import apply_suppression_rules
    load_plugins()

    stages = resolve_stages(stages_arg)
    if no_passive and "1" in stages:
        stages.remove("1")

    out_path = Path(output_dir) / f"scan_{scan_id}"
    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / "screenshots").mkdir(exist_ok=True)

    jm.update_status("running")
    console.print(Rule(f"[bold]Aarchai Scan #{scan_id}[/]", style="cyan"))
    console.print(f"Target: [cyan]{target.value}[/] ({target.type})")
    console.print(f"Stages: {', '.join(STAGE_LABELS.get(s, s) for s in stages)}")
    console.print(f"Output: {out_path}")


    all_findings, all_assets = [], []

    for stage_num in stages:
        mod_name = STAGE_MAP.get(stage_num)
        if not mod_name:
            jm.log_warn(f"Unknown stage: {stage_num}")
            continue
        try:
            mod = importlib.import_module(mod_name)
        except ImportError as e:
            jm.log_error(f"Cannot import {mod_name}: {e}")
            continue

        label = STAGE_LABELS.get(stage_num, mod_name.split(".")[-1])
        console.print(Rule(f"[bold cyan]{label}[/]", style="dim"))

        try:
            findings, assets = mod.run(
                target, scan_id, session, jm,
                fast=fast, out_dir=out_path, auth=auth, scope=scope
            )
            # Confidence scoring
            from utils.confidence import score as conf_score
            for f in findings:
                f._confidence = conf_score(
                    f.tool, f.finding_type,
                    f.severity.value if hasattr(f.severity, "value") else f.severity,
                    has_cve=bool(f.cve_ids), cvss=f.cvss_score,
                )

            all_findings.extend(findings)
            all_assets.extend(assets)
            _save_to_db(session, scan_id, findings, assets)
            jm.log_stage(label, f"{len(findings)} findings | {len(assets)} assets")

        except Exception as exc:
            jm.log_error(f"Stage {label}: {exc}")
            import traceback; traceback.print_exc()

    # Suppression
    from core.db import Finding as DBFinding
    db_findings = session.query(DBFinding).filter(DBFinding.scan_id == scan_id).all()
    apply_suppression_rules(db_findings, session)
    session.commit()

    # Diff
    from diff_engine.snapshot import save_snapshot
    from diff_engine.diff import compute_diff_for_scan
    save_snapshot(session, scan_id, all_findings)
    compute_diff_for_scan(session, scan_id, jm)

    # Exploit chain + threat model (auto if stage 6 ran)
    if "6" in stages:
        _generate_outputs(scan_id, target, all_findings, all_assets, session, out_path, jm)
        # Auto exploit chain
        try:
            from utils.exploit_chain import build_exploit_chain
            db_f = session.query(DBFinding).filter(DBFinding.scan_id == scan_id).all()
            from core.db import Asset
            db_a = session.query(Asset).filter(Asset.scan_id == scan_id).all()
            build_exploit_chain(db_f, db_a, target, scan_id, out_path)
            jm.log_ok("Exploit chain analysis generated")
        except Exception as e:
            jm.log_warn(f"Exploit chain: {e}")
        # Auto threat model
        try:
            from utils.threat_model import generate_stride_model
            from core.db import Asset
            db_f = session.query(DBFinding).filter(DBFinding.scan_id == scan_id).all()
            db_a = session.query(Asset).filter(Asset.scan_id == scan_id).all()
            generate_stride_model(db_f, db_a, target, scan_id, out_path)
            jm.log_ok("STRIDE threat model generated")
        except Exception as e:
            jm.log_warn(f"Threat model: {e}")
    else:
        _generate_outputs(scan_id, target, all_findings, all_assets, session, out_path, jm)

    jm.update_status("done")
    console.print(Rule("[bold green]Scan Complete[/]", style="green"))
    console.print(f"[green]Findings: {len(all_findings)} | Assets: {len(all_assets)}[/]")
    console.print(f"[green]Reports:  {out_path}[/]")


def _save_to_db(session, scan_id, findings, assets):
    from core.db import Asset, Finding as DBFinding
    for a in assets:
        session.add(Asset(
            scan_id=scan_id, asset_type=a.get("type",""), value=a.get("value",""),
            port=a.get("port"), protocol=a.get("protocol"), service=a.get("service"),
            banner=a.get("banner"), screenshot_path=a.get("screenshot_path"),
            tech_stack=a.get("tech_stack",[]), source_tool=a.get("source_tool",""),
        ))
    for f in findings:
        session.add(DBFinding(
            scan_id=scan_id, tool=f.tool, finding_type=f.finding_type,
            title=f.title, severity=f.severity.value if hasattr(f.severity,"value") else f.severity,
            description=f.description, host=f.host, port=f.port, url=f.url,
            cve_ids=f.cve_ids, cvss_score=f.cvss_score, epss_score=f.epss_score,
            mitre_tactics=f.mitre_tactics, raw_output=f.raw_output,
            fingerprint_hash=f.fingerprint_hash, remediation=f.remediation,
            references=f.references, confidence_score=getattr(f, "_confidence", 50),
        ))
    session.commit()


def _generate_outputs(scan_id, target, findings, assets, session, out_path, jm):
    from output.json_export    import export_json_csv
    from output.html_dashboard import generate_dashboard
    from output.pdf_report     import generate_pdf
    export_json_csv(findings, assets, scan_id, out_path);  jm.log_ok("JSON/CSV exported")
    generate_dashboard(findings, assets, scan_id, target, out_path); jm.log_ok("HTML dashboard")
    try:
        generate_pdf(findings, assets, scan_id, target, out_path); jm.log_ok("PDF report")
    except Exception as e:
        jm.log_warn(f"PDF: {e}")
