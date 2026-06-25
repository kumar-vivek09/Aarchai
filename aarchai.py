#!/usr/bin/env python3
"""Aarchai — Automated Recon Framework CLI v2"""
import sys
import click
from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER = """[bold cyan]  ██████╗[/][bold white]██████╗ [/][bold cyan] ██████╗ ██╗  ██╗ █████╗ ██╗[/]
[bold cyan]  ██╔══██╗[/][bold white]██╔══██╗[/][bold cyan]██╔════╝ ██║  ██║██╔══██╗██║[/]
[bold cyan]  ███████║[/][bold white]███████╔╝[/][bold cyan]██║      ███████║███████║██║[/]
[bold cyan]  ██╔══██║[/][bold white]██╔══██╗[/][bold cyan]██║      ██╔══██║██╔══██║██║[/]
[bold cyan]  ██║  ██║[/][bold white]██║  ██║[/][bold cyan]╚██████╗ ██║  ██║██║  ██║██║[/]
[bold cyan]  ╚═╝  ╚═╝[/][bold white]╚═╝  ╚═╝[/][bold cyan] ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝[/]
[dim]  Automated Reconnaissance Framework · v2.0[/]"""


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Aarchai — Automated Reconnaissance Framework v2

  Tip: run [bold]python3 menu.py[/] for the interactive menu."""
    if ctx.invoked_subcommand is None:
        console.print(Panel(BANNER, border_style="cyan", padding=(0, 2)))
        console.print("
  Run [bold cyan]python3 menu.py[/] for the interactive menu
  or [bold cyan]python3 aarchai.py --help[/] for all commands.
")


@cli.command()
@click.option("--target",     "-t", required=True)
@click.option("--stages",     "-s", default="all")
@click.option("--output-dir", "-o", default="./reports")
@click.option("--auth",       "-a", default=None)
@click.option("--scope-file", default=None)
@click.option("--include",    multiple=True)
@click.option("--exclude",    multiple=True)
@click.option("--no-passive", is_flag=True)
@click.option("--fast",       is_flag=True)
@click.option("--ad-domain",  default=None, help="Active Directory domain name")
def scan(target, stages, output_dir, auth, scope_file, include, exclude, no_passive, fast, ad_domain):
    """Run a recon scan against a target."""
    from core.db import init_db, get_session, Target as TModel, Scan
    from core.target import parse_target
    from core.job_manager import JobManager
    from stages.runner import run_pipeline
    from utils.scope import ScopeConfig
    from utils.auth import load_auth
    from datetime import datetime

    console.print(Panel(BANNER, border_style="cyan", padding=(0,2)))

    scope = None
    if scope_file:
        scope = ScopeConfig.from_file(scope_file)
    elif include or exclude:
        scope = ScopeConfig(includes=list(include), excludes=list(exclude))

    auth_profile = load_auth(auth)
    init_db()
    parsed = parse_target(target)
    session = get_session()

    db_target = TModel(input=target, target_type=parsed.type,
                       scope_config=scope.to_dict() if scope else None)
    session.add(db_target); session.commit()

    scan_rec = Scan(target_id=db_target.id, status="pending", started_at=datetime.utcnow())
    session.add(scan_rec); session.commit()

    jm = JobManager(session, scan_rec.id)
    try:
        run_pipeline(parsed, scan_rec.id, session, jm, stages, output_dir,
                     fast, no_passive, scope=scope, auth=auth_profile)
    except ValueError as e:
        console.print(f"[red bold]{e}[/]"); sys.exit(1)
    except KeyboardInterrupt:
        jm.update_status("cancelled"); console.print("
[yellow]Scan cancelled.[/]"); sys.exit(0)
    except Exception as exc:
        jm.update_status("failed"); console.print(f"[red]{exc}[/]")
        import traceback; traceback.print_exc(); sys.exit(1)
    finally:
        session.close()


@cli.command()
def init():
    """Initialise the database."""
    from core.db import init_db
    init_db()
    console.print("[bold green]Database initialised.[/]")


@cli.command()
def db():
    """Run Alembic database migrations (upgrade head)."""
    import subprocess
    result = subprocess.run(["alembic", "upgrade", "head"])
    if result.returncode == 0:
        console.print("[bold green]Database migrated successfully.[/]")
    else:
        console.print("[red]Migration failed.[/]")


@cli.command("list")
def list_scans():
    """List recent scans."""
    from core.db import get_session, Scan, Target
    from rich.table import Table
    session = get_session()
    rows = (session.query(Scan, Target).join(Target, Scan.target_id == Target.id)
            .order_by(Scan.id.desc()).limit(20).all())
    tbl = Table(title="Recent Scans", show_lines=True)
    tbl.add_column("ID",       style="cyan",  justify="right")
    tbl.add_column("Target")
    tbl.add_column("Status",   style="green")
    tbl.add_column("Started")
    tbl.add_column("Critical", style="red",    justify="right")
    tbl.add_column("High",     style="yellow", justify="right")
    tbl.add_column("Total",    justify="right")
    for sc, tgt in rows:
        crit  = len([f for f in sc.findings if f.severity == "critical"])
        high  = len([f for f in sc.findings if f.severity == "high"])
        tbl.add_row(str(sc.id), tgt.input, sc.status, str(sc.started_at)[:16],
                    str(crit), str(high), str(len(sc.findings)))
    console.print(tbl)
    session.close()


@cli.command()
@click.argument("scan_id",    type=int)
@click.argument("finding_id", type=int)
@click.option("--status", type=click.Choice(["confirmed","false_positive","accepted_risk"]), required=True)
def triage(scan_id, finding_id, status):
    """Triage a finding."""
    from core.db import get_session, Finding
    session = get_session()
    f = session.query(Finding).filter(Finding.id==finding_id, Finding.scan_id==scan_id).first()
    if not f: console.print("[red]Not found[/]"); return
    f.triage_status = status
    if status == "false_positive": f.is_suppressed = True
    session.commit(); console.print(f"[green]Finding #{finding_id} → {status}[/]")
    session.close()


@cli.command()
@click.option("--tool", default=None)
@click.option("--finding-type", default=None)
@click.option("--title", default=None)
@click.option("--reason", default="manual")
def suppress(tool, finding_type, title, reason):
    """Add a suppression rule."""
    from core.db import get_session, SuppressionRule, init_db
    init_db()
    session = get_session()
    session.add(SuppressionRule(tool=tool, finding_type=finding_type, title_pattern=title, reason=reason))
    session.commit()
    console.print(f"[green]Suppression rule added[/]")
    session.close()


@cli.command()
@click.option("--scan-id", type=int, required=True)
@click.option("--framework", type=click.Choice(["owasp","pci","iso27001","nist"]), default="owasp")
@click.option("--output-dir", "-o", default="./reports")
def compliance(scan_id, framework, output_dir):
    """Generate a compliance report for a scan."""
    from core.db import get_session, Finding, Scan, Target
    from output.compliance import generate_compliance_report
    from pathlib import Path
    session = get_session()
    findings = session.query(Finding).filter(Finding.scan_id==scan_id).all()
    scan = session.get(Scan, scan_id)
    target = session.get(Target, scan.target_id) if scan else None
    out_dir = Path(output_dir) / f"scan_{scan_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = generate_compliance_report(findings, scan_id, target, framework, out_dir)
    session.close()
    console.print(f"[bold green]Report: {out}[/]")


@cli.command("exploit-chain")
@click.option("--scan-id", type=int, required=True)
@click.option("--output-dir", "-o", default="./reports")
def exploit_chain(scan_id, output_dir):
    """Build exploit chain analysis for a scan."""
    from core.db import get_session, Finding, Asset, Scan, Target
    from utils.exploit_chain import build_exploit_chain
    from pathlib import Path
    session = get_session()
    findings = session.query(Finding).filter(Finding.scan_id==scan_id).all()
    assets   = session.query(Asset).filter(Asset.scan_id==scan_id).all()
    scan = session.get(Scan, scan_id)
    target = session.get(Target, scan.target_id) if scan else None
    out_dir = Path(output_dir) / f"scan_{scan_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    analysis, _ = build_exploit_chain(findings, assets, target, scan_id, out_dir)
    session.close()
    console.print(analysis[:2000])
    console.print(f"
[green]Full report: {out_dir}/exploit_chain.txt[/]")


@cli.command("threat-model")
@click.option("--scan-id", type=int, required=True)
@click.option("--output-dir", "-o", default="./reports")
def threat_model(scan_id, output_dir):
    """Generate STRIDE threat model for a scan."""
    from core.db import get_session, Finding, Asset, Scan, Target
    from utils.threat_model import generate_stride_model
    from pathlib import Path
    session = get_session()
    findings = session.query(Finding).filter(Finding.scan_id==scan_id).all()
    assets   = session.query(Asset).filter(Asset.scan_id==scan_id).all()
    scan = session.get(Scan, scan_id)
    target = session.get(Target, scan.target_id) if scan else None
    out_dir = Path(output_dir) / f"scan_{scan_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    result = generate_stride_model(findings, assets, target, scan_id, out_dir)
    session.close()
    console.print(f"[green]STRIDE model: {out_dir}/threat_model_stride.html[/]")
    for cat, threats in result["stride"].items():
        if threats:
            console.print(f"  [cyan]{cat}[/]: {len(threats)} threat(s)")


@cli.command()
def web():
    """Start the Web UI."""
    import uvicorn
    console.print("[bold cyan]Starting Web UI → http://localhost:8000[/]")
    uvicorn.run("web.app:app", host="0.0.0.0", port=8000, reload=False, log_level="warning")


if __name__ == "__main__":
    cli()
