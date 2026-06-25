"""Delta comparison between scans."""
from __future__ import annotations
from diff_engine.snapshot import load_snapshot, get_previous_scan_id
from rich.console import Console
from rich.table import Table

console = Console()


def compute_diff_for_scan(session, scan_id: int, jm):
    prev_id = get_previous_scan_id(session, scan_id)
    if not prev_id:
        jm.log_info("No previous scan — nothing to diff")
        return

    current_snaps = {s["fingerprint_hash"]: s for s in load_snapshot(session, scan_id)}
    previous_snaps = {s["fingerprint_hash"]: s for s in load_snapshot(session, prev_id)}

    new_hashes      = set(current_snaps) - set(previous_snaps)
    resolved_hashes = set(previous_snaps) - set(current_snaps)
    persisted       = set(current_snaps) & set(previous_snaps)

    jm.log_ok(
        f"Diff vs scan #{prev_id}: "
        f"[green]+{len(new_hashes)} new[/] / "
        f"[red]-{len(resolved_hashes)} resolved[/] / "
        f"{len(persisted)} unchanged"
    )


def print_diff(session, scan_id: int):
    prev_id = get_previous_scan_id(session, scan_id)
    if not prev_id:
        console.print("[yellow]No previous scan to diff against.[/]")
        return

    current_snaps  = {s["fingerprint_hash"]: s for s in load_snapshot(session, scan_id)}
    previous_snaps = {s["fingerprint_hash"]: s for s in load_snapshot(session, prev_id)}

    new_hashes      = set(current_snaps) - set(previous_snaps)
    resolved_hashes = set(previous_snaps) - set(current_snaps)

    console.print(f"\n[bold]Diff: Scan #{scan_id} vs #{prev_id}[/]\n")

    if new_hashes:
        tbl = Table(title=f"[green]NEW Findings (+{len(new_hashes)})[/]", show_lines=True)
        tbl.add_column("Severity"); tbl.add_column("Tool"); tbl.add_column("Title")
        for h in new_hashes:
            s = current_snaps[h]
            tbl.add_row(s["severity"], s["tool"], s["title"])
        console.print(tbl)

    if resolved_hashes:
        tbl = Table(title=f"[red]RESOLVED Findings (-{len(resolved_hashes)})[/]", show_lines=True)
        tbl.add_column("Severity"); tbl.add_column("Tool"); tbl.add_column("Title")
        for h in resolved_hashes:
            s = previous_snaps[h]
            tbl.add_row(s["severity"], s["tool"], s["title"])
        console.print(tbl)

    if not new_hashes and not resolved_hashes:
        console.print("[green]No changes between scans.[/]")
