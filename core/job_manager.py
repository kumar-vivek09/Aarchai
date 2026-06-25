"""Manages scan job lifecycle and progress reporting."""
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from core.db import Scan

console = Console()

class JobManager:
    def __init__(self, session, scan_id: int):
        self.session  = session
        self.scan_id  = scan_id
        self._current_stage = ""

    def _scan(self) -> Scan:
        return self.session.get(Scan, self.scan_id)

    def update_status(self, status: str):
        scan = self._scan()
        scan.status = status
        if status == "running" and scan.started_at is None:
            scan.started_at = datetime.utcnow()
        if status in ("done", "failed", "cancelled"):
            scan.finished_at = datetime.utcnow()
        self.session.commit()

    def log_stage(self, stage_name: str, msg: str = ""):
        scan = self._scan()
        stages = list(scan.stages_run or [])
        if stage_name not in stages:
            stages.append(stage_name)
            scan.stages_run = stages
            self.session.commit()
        label = f"[bold cyan][{stage_name}][/] {msg}" if msg else f"[bold cyan][{stage_name}][/]"
        console.print(label)

    def log_info(self, msg: str):
        console.print(f"  [dim]{msg}[/]")

    def log_ok(self, msg: str):
        console.print(f"  [green]✓[/] {msg}")

    def log_warn(self, msg: str):
        console.print(f"  [yellow]![/] {msg}")

    def log_error(self, msg: str):
        console.print(f"  [red]✗[/] {msg}")

    def log_finding(self, severity: str, title: str):
        colour = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(severity, "white")
        console.print(f"  [{colour}][{severity.upper()}][/] {title}")
