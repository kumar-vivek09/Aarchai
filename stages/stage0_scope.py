"""Stage 0 — Scope validation: confirm target is in scope before scanning."""
from __future__ import annotations
from utils.scope import ScopeConfig, print_scope
from rich.console import Console

console = Console()


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    jm.log_stage("stage0_scope", "Validating scope")

    if scope is None:
        jm.log_info("No scope restrictions defined — all targets in scope")
        return [], []

    if not scope.is_in_scope(target.host):
        raise ValueError(
            f"Target {target.host} is OUT OF SCOPE!
"
            f"Includes: {scope.includes}
Excludes: {scope.excludes}"
        )

    print_scope(scope, console)
    jm.log_ok(f"{target.host} is in scope")
    return [], []
