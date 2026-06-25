"""Stage 2 — Active Recon: subdomain enum + port scan, fully async."""
from __future__ import annotations
import asyncio
import json
import tempfile
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir, auth, scope))


async def _run_async(target, scan_id, session, jm, fast, out_dir, auth, scope):
    host = target.host
    jm.log_stage("stage2_active", f"[PARALLEL] {host}")

    # Subdomain enum + port scan in true parallel
    sub_task  = asyncio.create_task(_subdomain_enum(host, scan_id, jm, fast, scope))
    port_task = asyncio.create_task(_port_scan(host, scan_id, jm, fast, out_dir))

    (sub_f, sub_a), (port_f, port_a) = await asyncio.gather(sub_task, port_task)

    findings = sub_f + port_f
    assets   = sub_a + port_a

    # Load plugins async
    from plugins.loader import get_plugins
    plugin_tasks = []
    for plugin in get_plugins(2):
        plugin_tasks.append(asyncio.create_task(
            _run_plugin(plugin, target, scan_id, session, jm, fast, out_dir, auth)
        ))
    if plugin_tasks:
        plugin_results = await asyncio.gather(*plugin_tasks, return_exceptions=True)
        for res in plugin_results:
            if not isinstance(res, Exception):
                pf, pa = res
                findings.extend(pf); assets.extend(pa)

    jm.log_ok(f"Stage 2 done: {len(findings)} findings, {len(assets)} assets")
    return findings, assets


async def _subdomain_enum(host, scan_id, jm, fast, scope):
    jm.log_info("subfinder + gobuster DNS [parallel] →")
    tasks = [
        asyncio.create_task(_subfinder(host, scan_id, jm)),
    ]
    if not fast:
        tasks.append(asyncio.create_task(_gobuster_dns(host, scan_id, jm)))
        tasks.append(asyncio.create_task(_fierce(host, scan_id, jm)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings, assets = [], []
    for r in results:
        if not isinstance(r, Exception):
            f, a = r
            findings.extend(f); assets.extend(a)

    # Scope filter
    if scope:
        assets = scope.filter_assets(assets)
    return findings, assets


async def _subfinder(host, scan_id, jm):
    r = await run_async(["subfinder", "-d", host, "-silent", "-json"], timeout=90)
    assets = []
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
            sub = d.get("host", "")
            if sub:
                assets.append({"type": "subdomain", "value": sub, "source_tool": "subfinder"})
        except Exception:
            pass
    jm.log_ok(f"subfinder: {len(assets)} subdomains")
    return [], assets


async def _gobuster_dns(host, scan_id, jm):
    wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if not Path(wordlist).exists():
        wordlist = "/usr/share/wordlists/dnsmap.txt"
    if not Path(wordlist).exists():
        return [], []
    r = await run_async(
        ["gobuster", "dns", "-d", host, "-w", wordlist, "-q", "--no-error"],
        timeout=150
    )
    assets = []
    for line in r.stdout.splitlines():
        if "Found:" in line:
            sub = line.split("Found:")[-1].strip()
            assets.append({"type": "subdomain", "value": sub, "source_tool": "gobuster-dns"})
    return [], assets


async def _fierce(host, scan_id, jm):
    r = await run_async(["fierce", "--domain", host], timeout=90)
    assets = []
    if r.success:
        for line in r.stdout.splitlines():
            if "Found:" in line or "Subdomain:" in line:
                parts = line.strip().split()
                if parts:
                    sub = parts[-1].rstrip(".")
                    if host in sub:
                        assets.append({"type": "subdomain", "value": sub, "source_tool": "fierce"})
    return [], assets


async def _port_scan(host, scan_id, jm, fast, out_dir):
    jm.log_info("nmap →")
    nmap_out = f"/tmp/nmap_{host.replace('.','_').replace('/','_')}.xml"
    cmd = (["nmap", "-F", "-sV", "--open", "-oX", nmap_out, host] if fast else
           ["nmap", "-sV", "-sC", "--open", "-p-", "--min-rate", "2000", "-oX", nmap_out, host])
    r = await run_async(cmd, timeout=300)
    findings, assets = [], []
    if Path(nmap_out).exists():
        from normalizer.parsers.nmap_parser import parse_nmap_xml
        f, a = parse_nmap_xml(nmap_out, scan_id)
        findings.extend(f); assets.extend(a)
        jm.log_ok(f"nmap: {len(a)} ports, {len(f)} findings")
    return findings, assets


async def _run_plugin(plugin, target, scan_id, session, jm, fast, out_dir, auth):
    try:
        return await plugin["run"](target, scan_id, session, jm, fast, out_dir, auth)
    except Exception as e:
        jm.log_warn(f"Plugin {plugin['name']}: {e}")
        return [], []
