"""Scheduled / continuous monitoring — cron-based scan runner."""
from __future__ import annotations
import json
import sys
from pathlib import Path
from datetime import datetime

import click
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from rich.console import Console

console = Console()
WATCHLIST = Path(__file__).parent / "watchlist.json"


def load_watchlist() -> list[dict]:
    if WATCHLIST.exists():
        return json.loads(WATCHLIST.read_text())
    return []


def save_watchlist(data: list[dict]):
    WATCHLIST.write_text(json.dumps(data, indent=2))


def _run_scan(target_input: str, stages: str = "all"):
    """Execute a scan job (called by scheduler)."""
    console.print(f"[cyan][scheduler] Starting scheduled scan: {target_input}[/]")
    from core.db import init_db, get_session, Target as TModel, Scan
    from core.target import parse_target
    from core.job_manager import JobManager
    from stages.runner import run_pipeline

    init_db()
    session = get_session()
    parsed  = parse_target(target_input)

    db_target = TModel(input=target_input, target_type=parsed.type)
    session.add(db_target)
    session.commit()

    scan_rec = Scan(
        target_id  = db_target.id,
        status     = "pending",
        started_at = datetime.utcnow(),
    )
    session.add(scan_rec)
    session.commit()

    jm = JobManager(session, scan_rec.id)
    try:
        run_pipeline(parsed, scan_rec.id, session, jm, stages, "./reports", False, False)
        # Notify on new critical/high
        _notify_if_needed(session, scan_rec.id, target_input)
    except Exception as e:
        jm.update_status("failed")
        console.print(f"[red][scheduler] Scan failed: {e}[/]")
    finally:
        session.close()


def _notify_if_needed(session, scan_id: int, target: str):
    from diff_engine.snapshot import load_snapshot, get_previous_scan_id
    from utils.notifier import notify_new_findings
    prev_id = get_previous_scan_id(session, scan_id)
    if not prev_id:
        return
    current  = {s["fingerprint_hash"]: s for s in load_snapshot(session, scan_id)}
    previous = {s["fingerprint_hash"]: s for s in load_snapshot(session, prev_id)}
    new_hashes = set(current) - set(previous)
    new_findings = [current[h] for h in new_hashes]
    if new_findings:
        notify_new_findings(target, scan_id, new_findings)


@click.group()
def scheduler_cli():
    """Aarchai scheduled monitoring."""
    pass


@scheduler_cli.command()
@click.option("--target", "-t", required=True)
@click.option("--cron", "-c", default="0 2 * * *", help="Cron expression (default: daily 2am)")
@click.option("--stages", "-s", default="all")
def add(target, cron, stages):
    """Add a target to the monitoring watchlist."""
    wl = load_watchlist()
    entry = {"target": target, "cron": cron, "stages": stages}
    wl.append(entry)
    save_watchlist(wl)
    console.print(f"[green]Added:[/] {target} — cron: {cron}")


@scheduler_cli.command("list")
def list_targets():
    """List monitored targets."""
    from rich.table import Table
    wl = load_watchlist()
    tbl = Table(title="Watchlist")
    tbl.add_column("Target"); tbl.add_column("Cron"); tbl.add_column("Stages")
    for e in wl:
        tbl.add_row(e["target"], e["cron"], e["stages"])
    console.print(tbl)


@scheduler_cli.command()
def start():
    """Start the scheduler daemon."""
    wl = load_watchlist()
    if not wl:
        console.print("[yellow]Watchlist is empty. Add targets first.[/]")
        return
    sched = BlockingScheduler()
    for entry in wl:
        sched.add_job(
            _run_scan,
            CronTrigger.from_crontab(entry["cron"]),
            args=[entry["target"], entry.get("stages", "all")],
            id=entry["target"],
        )
        console.print(f"[cyan]Scheduled:[/] {entry['target']} — {entry['cron']}")
    console.print("[green]Scheduler running. Ctrl+C to stop.[/]")
    try:
        sched.start()
    except KeyboardInterrupt:
        console.print("[yellow]Scheduler stopped.[/]")


if __name__ == "__main__":
    scheduler_cli()
