#!/usr/bin/env python3
"""
Aarchai Interactive Menu — run this for a guided experience.
  python3 menu.py
"""
import sys
import os
import subprocess
import pathlib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.live import Live
from rich.spinner import Spinner
from datetime import datetime

console = Console()

# ── Banner ────────────────────────────────────────────────────────────────
BANNER = """\
   [bold cyan]  ██████╗[/] [bold white]██████╗[/]  [bold cyan] ██████╗ ██╗  ██╗ █████╗ ██╗[/]
   [bold cyan] ██╔══██╗[/][bold white]██╔══██╗[/] [bold cyan]██╔════╝ ██║  ██║██╔══██╗██║[/]
   [bold cyan] ███████║[/][bold white]███████╔╝[/] [bold cyan]██║      ███████║███████║██║[/]
   [bold cyan] ██╔══██║[/][bold white]██╔══██╗[/] [bold cyan]██║      ██╔══██║██╔══██║██║[/]
   [bold cyan] ██║  ██║[/][bold white]██║  ██║[/] [bold cyan]╚██████╗ ██║  ██║██║  ██║██║[/]
   [bold cyan] ╚═╝  ╚═╝[/][bold white]╚═╝  ╚═╝[/] [bold cyan] ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝[/]
   [dim]  Automated Reconnaissance Framework · Kali Linux · v2.0[/]"""

MENU_ITEMS = [
    # (number, emoji, title, description, category)
    ("1",  "🌐", "Full Scan",              "Complete 10-stage pipeline — passive→active→web→vulns→intel→report→attacker", "scan"),
    ("2",  "⚡", "Quick Scan",             "Fast mode — top tools only, ~10 minutes",                                    "scan"),
    ("3",  "👁",  "Passive Only",           "No direct contact — OSINT, crt.sh, Shodan, whois",                          "scan"),
    ("4",  "🕸",  "Web App Scan",           "Web surface + fingerprinting + vulnerabilities + secrets",                   "scan"),
    ("5",  "🌩",  "Cloud Scan",             "AWS/Azure/GCP bucket enum + metadata + cloud-specific vulns",                "scan"),
    ("6",  "🔌", "API Security Scan",      "REST/GraphQL testing, swagger discovery, JWT attacks, arjun",                "scan"),
    ("7",  "🗺",  "Network Topology",       "Internal CIDR mapping — routers, VLANs, topology diagram",                  "scan"),
    ("8",  "🕵",  "OSINT Module",           "Employees, breaches, dark web, ASN/BGP, social media footprint",            "scan"),
    ("9",  "🏰", "AD / Kerberos Scan",     "Active Directory — bloodhound, kerbrute, AS-REP roasting, DCSync",          "scan"),
    ("──", "",   "",                        "",                                                                           "sep"),
    ("10", "📋", "View Recent Scans",       "List scans with severity counts",                                            "manage"),
    ("11", "✅", "Triage Findings",         "Review, confirm, or dismiss findings for a scan",                            "manage"),
    ("12", "📊", "Compliance Report",       "Generate OWASP / PCI-DSS / ISO 27001 / NIST report",                        "manage"),
    ("13", "🔔", "Monitor Target",          "Schedule recurring scans + Slack/email alerts on new findings",              "manage"),
    ("14", "🖥",  "Open Web Dashboard",     "Start web UI at http://localhost:8000",                                      "manage"),
    ("15", "🔗", "Exploit Chain Builder",  "AI analysis: find chained attack paths across findings",                     "manage"),
    ("16", "🗡",  "Threat Model (STRIDE)",  "Generate STRIDE threat model from discovered tech stack",                    "manage"),
    ("17", "🔑", "Settings / API Keys",    "Configure API keys, LLM provider, alerts",                                   "manage"),
    ("18", "🆙", "Database Migrate",       "Apply DB schema updates (alembic upgrade head)",                             "manage"),
    ("──", "",   "",                        "",                                                                           "sep"),
    ("0",  "🚪", "Exit",                   "",                                                                            "exit"),
]


def print_banner():
    console.print()
    console.print(Align.center(BANNER))
    console.print()


def print_menu():
    console.print(Rule("[bold]Main Menu[/]", style="dim"))
    console.print()
    for num, emoji, title, desc, cat in MENU_ITEMS:
        if cat == "sep":
            console.print()
            continue
        if cat == "exit":
            console.print(f"  [dim][[bold]0[/]]  {emoji}  Exit[/]")
            continue
        color = {"scan": "cyan", "manage": "blue", "exit": "dim"}.get(cat, "white")
        num_str = f"[bold {color}][{num:>2}][/]"
        title_str = f"[bold white]{emoji}  {title}[/]"
        desc_str = f"[dim]{desc}[/]" if desc else ""
        console.print(f"  {num_str}  {title_str}")
        if desc:
            console.print(f"         [dim]{desc}[/]")
    console.print()


def ask_target(prompt="Target (domain / IP / CIDR / URL)"):
    return Prompt.ask(f"  [cyan]{prompt}[/]").strip()


def ask_optional(prompt, default=""):
    val = Prompt.ask(f"  [dim]{prompt}[/]", default=default).strip()
    return val or default


def run_aarchai(args: list, title: str = ""):
    """Run aarchai.py with given args and stream output."""
    console.print()
    console.print(Rule(f"[bold cyan]{title or ' '.join(args[:3])}[/]", style="cyan"))
    cmd = [sys.executable, "aarchai.py"] + args
    try:
        proc = subprocess.run(cmd, cwd=str(BASE_DIR))
        if proc.returncode == 0:
            console.print(f"\n[bold green]✓ Done[/]")
        else:
            console.print(f"\n[bold red]✗ Finished with errors (exit {proc.returncode})[/]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")


def run_cmd(args: list, title: str = ""):
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/]", style="cyan"))
    try:
        subprocess.run(args, cwd=str(BASE_DIR))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")


BASE_DIR = pathlib.Path(__file__).parent


# ════════════════════════════════════════════════════════════
# OPTION HANDLERS
# ════════════════════════════════════════════════════════════

def handle_1():
    """Full scan."""
    target = ask_target()
    if not target: return
    exclude = ask_optional("Exclude patterns (comma-separated, optional)", "")
    auth    = ask_optional("Auth profile name (optional)", "")
    fast    = Confirm.ask("  [dim]Fast mode?[/]", default=False)
    args = ["scan", "--target", target, "--stages", "all"]
    if exclude:
        for ex in exclude.split(","):
            args += ["--exclude", ex.strip()]
    if auth: args += ["--auth", auth]
    if fast: args.append("--fast")
    run_aarchai(args, f"Full Scan → {target}")


def handle_2():
    """Quick scan."""
    target = ask_target()
    if not target: return
    run_aarchai(["scan", "--target", target, "--stages", "1,2,3,4,5,6", "--fast"],
                f"Quick Scan → {target}")


def handle_3():
    """Passive only."""
    target = ask_target()
    if not target: return
    run_aarchai(["scan", "--target", target, "--stages", "1,8"], f"Passive OSINT → {target}")


def handle_4():
    """Web app scan."""
    target = ask_target()
    if not target: return
    auth = ask_optional("Auth profile name (optional)")
    args = ["scan", "--target", target, "--stages", "2,3,3b,4,4b,5,6"]
    if auth: args += ["--auth", auth]
    run_aarchai(args, f"Web App Scan → {target}")


def handle_5():
    """Cloud scan."""
    target = ask_target()
    if not target: return
    run_aarchai(["scan", "--target", target, "--stages", "1,9"], f"Cloud Scan → {target}")


def handle_6():
    """API security scan."""
    target = ask_target("API base URL or domain")
    if not target: return
    auth = ask_optional("Auth profile name (for authenticated API testing)")
    args = ["scan", "--target", target, "--stages", "10"]
    if auth: args += ["--auth", auth]
    run_aarchai(args, f"API Security → {target}")


def handle_7():
    """Network topology."""
    target = ask_target("CIDR range (e.g. 192.168.1.0/24)")
    if not target: return
    run_aarchai(["scan", "--target", target, "--stages", "11,2,5,6"],
                f"Network Map → {target}")


def handle_8():
    """OSINT."""
    target = ask_target("Company domain or name")
    if not target: return
    run_aarchai(["scan", "--target", target, "--stages", "8"], f"OSINT → {target}")


def handle_9():
    """AD / Kerberos."""
    target = ask_target("Domain controller IP or AD domain")
    if not target: return
    domain = ask_optional("AD domain name (e.g. CORP.LOCAL)")
    args = ["scan", "--target", target, "--stages", "12"]
    if domain: args += ["--ad-domain", domain]
    run_aarchai(args, f"AD Scan → {target}")


def handle_10():
    """List scans."""
    run_aarchai(["list"], "Recent Scans")


def handle_11():
    """Triage findings."""
    scan_id = Prompt.ask("  [cyan]Scan ID to triage[/]").strip()
    if not scan_id: return
    console.print()
    # Show findings
    run_aarchai(["list"], "")
    console.print()
    finding_id = Prompt.ask("  [cyan]Finding ID[/]").strip()
    if not finding_id: return
    status = Prompt.ask(
        "  [cyan]Status[/]",
        choices=["confirmed", "false_positive", "accepted_risk"],
        default="confirmed"
    )
    run_aarchai(["triage", scan_id, finding_id, "--status", status],
                f"Triage finding #{finding_id}")


def handle_12():
    """Compliance report."""
    scan_id = Prompt.ask("  [cyan]Scan ID[/]").strip()
    if not scan_id: return
    framework = Prompt.ask(
        "  [cyan]Framework[/]",
        choices=["owasp", "pci", "iso27001", "nist"],
        default="owasp"
    )
    run_aarchai(["compliance", "--scan-id", scan_id, "--framework", framework],
                f"{framework.upper()} Compliance Report")


def handle_13():
    """Schedule monitoring."""
    target = ask_target()
    if not target: return
    cron   = ask_optional("Cron schedule (default: daily 2am)", "0 2 * * *")
    run_cmd([sys.executable, "scheduler.py", "add", "--target", target, "--cron", cron],
            f"Schedule: {target} @ {cron}")
    if Confirm.ask("  [dim]Start scheduler now?[/]", default=False):
        run_cmd([sys.executable, "scheduler.py", "start"], "Scheduler")


def handle_14():
    """Web dashboard."""
    console.print("\n  [bold cyan]Starting Web UI at http://localhost:8000[/]")
    console.print("  [dim]Press Ctrl+C to stop[/]\n")
    run_cmd([sys.executable, "web/run.py"], "Web Dashboard")


def handle_15():
    """Exploit chain builder."""
    scan_id = Prompt.ask("  [cyan]Scan ID[/]").strip()
    if not scan_id: return
    run_aarchai(["exploit-chain", "--scan-id", scan_id], "Exploit Chain Analysis")


def handle_16():
    """Threat model."""
    scan_id = Prompt.ask("  [cyan]Scan ID[/]").strip()
    if not scan_id: return
    run_aarchai(["threat-model", "--scan-id", scan_id], "STRIDE Threat Model")


def handle_17():
    """Settings."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        import shutil
        ex = BASE_DIR / ".env.example"
        if ex.exists():
            shutil.copy(ex, env_path)
            console.print("  [green]Created .env from .env.example[/]")

    console.print()
    console.print(Panel(
        "[bold]Edit [cyan].env[/] to configure:[/]\n\n"
        "  [white]SHODAN_API_KEY[/]       → shodan.io (free)\n"
        "  [white]VIRUSTOTAL_API_KEY[/]   → virustotal.com (free)\n"
        "  [white]NVD_API_KEY[/]          → nvd.nist.gov (free)\n"
        "  [white]LLM_PROVIDER[/]         → stub | ollama | openai\n"
        "  [white]OLLAMA_MODEL[/]         → llama3 (default)\n"
        "  [white]OPENAI_API_KEY[/]       → sk-...\n"
        "  [white]SLACK_WEBHOOK_URL[/]    → for alerts\n"
        "  [white]AARCHAI_DB_URL[/]       → postgresql://...\n",
        title="⚙  Settings",
        border_style="dim",
    ))
    if Confirm.ask("  [dim]Open .env in nano?[/]", default=True):
        subprocess.run(["nano", str(env_path)])


def handle_18():
    """DB migrate."""
    console.print("\n  [cyan]Running: alembic upgrade head[/]")
    subprocess.run(["alembic", "upgrade", "head"], cwd=str(BASE_DIR))


HANDLERS = {
    "1": handle_1, "2": handle_2, "3": handle_3, "4": handle_4,
    "5": handle_5, "6": handle_6, "7": handle_7, "8": handle_8,
    "9": handle_9, "10": handle_10, "11": handle_11, "12": handle_12,
    "13": handle_13, "14": handle_14, "15": handle_15, "16": handle_16,
    "17": handle_17, "18": handle_18,
}


def main():
    import pathlib as pl
    global BASE_DIR
    BASE_DIR = pl.Path(__file__).parent

    os.chdir(str(BASE_DIR))

    try:
        from dotenv import load_dotenv
        load_dotenv(BASE_DIR / ".env")
    except Exception:
        pass

    while True:
        console.clear()
        print_banner()
        print_menu()

        choice = Prompt.ask("  [bold cyan]Enter option[/]", default="").strip()

        if choice == "0" or choice.lower() in ("exit", "quit", "q"):
            console.print("\n[dim]Goodbye.[/]\n")
            break

        handler = HANDLERS.get(choice)
        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                console.print("\n[yellow]Cancelled.[/]")
            console.print()
            Prompt.ask("  [dim]Press Enter to return to menu[/]", default="")
        else:
            console.print(f"\n  [red]Invalid option: {choice}[/]")
            import time; time.sleep(1)


if __name__ == "__main__":
    main()
