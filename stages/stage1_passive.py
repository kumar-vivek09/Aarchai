"""Stage 1 — Passive Recon: ALL tools run in parallel via asyncio.gather()."""
from __future__ import annotations
import asyncio
import json
import tempfile
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available
from config import SHODAN_API_KEY


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    """Sync entry point — runs the async pipeline."""
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir, auth, scope))


async def _run_async(target, scan_id, session, jm, fast, out_dir, auth, scope):
    host = target.host
    jm.log_stage("stage1_passive", f"[PARALLEL] {host}")

    # Build list of coroutines to run simultaneously
    coros = [
        _whois(host, scan_id, jm),
        _crtsh(host, scan_id, jm),
        _amass_passive(host, scan_id, jm, fast),
        _dnsx_resolve(host, scan_id, jm),
    ]
    if not fast:
        coros += [
            _theharvester(host, scan_id, jm),
            _shodan(host, scan_id, jm),
        ]

    # Run ALL tools simultaneously
    results = await asyncio.gather(*coros, return_exceptions=True)

    findings, assets = [], []
    for r in results:
        if isinstance(r, Exception):
            jm.log_warn(f"Passive tool error: {r}")
            continue
        f, a = r
        findings.extend(f)
        assets.extend(a)

    # Apply scope filter
    if scope:
        before = len(assets)
        assets = scope.filter_assets(assets)
        jm.log_info(f"Scope: kept {len(assets)}/{before} assets")

    jm.log_ok(f"Stage 1 done: {len(findings)} findings, {len(assets)} assets")
    return findings, assets


# ── Individual async tool functions ──────────────────────────────────────
async def _whois(host, scan_id, jm):
    jm.log_info("whois →")
    r = await run_async(["whois", host], timeout=30)
    if r.success:
        from normalizer.parsers.whois_parser import parse_whois
        return parse_whois(r.stdout, host, scan_id), []
    return [], []


async def _crtsh(host, scan_id, jm):
    jm.log_info("crt.sh →")
    assets = []
    try:
        import aiohttp
        async with aiohttp.ClientSession() as sess:
            async with sess.get(
                f"https://crt.sh/?q=%.{host}&output=json",
                timeout=aiohttp.ClientTimeout(total=25)
            ) as resp:
                if resp.status == 200:
                    certs = json.loads(await resp.text())
                    seen = set()
                    for c in certs:
                        for name in c.get("name_value", "").splitlines():
                            name = name.strip().lstrip("*.")
                            if name and host in name and name not in seen:
                                seen.add(name)
                                assets.append({"type": "subdomain", "value": name, "source_tool": "crt.sh"})
        jm.log_ok(f"crt.sh: {len(assets)} subdomains")
    except Exception as e:
        jm.log_warn(f"crt.sh: {e}")
    return [], assets


async def _amass_passive(host, scan_id, jm, fast):
    jm.log_info("amass (passive) →")
    r = await run_async(["amass", "enum", "-passive", "-d", host], timeout=120)
    assets = []
    if r.success:
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and host in line:
                assets.append({"type": "subdomain", "value": line, "source_tool": "amass-passive"})
    jm.log_ok(f"amass: {len(assets)} subdomains")
    return [], assets


async def _dnsx_resolve(host, scan_id, jm):
    jm.log_info("dnsx →")
    if not tool_available("dnsx"):
        return [], []
    r = await run_async(["dnsx", "-d", host, "-silent", "-a", "-resp"], timeout=60)
    assets = []
    for line in r.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            ip = parts[-1].strip("[]")
            assets.append({"type": "ip", "value": ip, "source_tool": "dnsx"})
    return [], assets


async def _theharvester(host, scan_id, jm):
    jm.log_info("theHarvester →")
    assets = []
    with tempfile.TemporaryDirectory() as td:
        out_file = Path(td) / "harvester"
        r = await run_async(
            ["theHarvester", "-d", host, "-b", "bing,google,crtsh", "-f", str(out_file)],
            timeout=90
        )
        json_file = out_file.with_suffix(".json")
        if json_file.exists():
            try:
                data = json.loads(json_file.read_text())
                for email in data.get("emails", []):
                    assets.append({"type": "email", "value": email, "source_tool": "theHarvester"})
                for sub in data.get("hosts", []):
                    assets.append({"type": "subdomain", "value": sub, "source_tool": "theHarvester"})
            except Exception:
                pass
    jm.log_ok(f"theHarvester: {len(assets)} assets")
    return [], assets


async def _shodan(host, scan_id, jm):
    if not SHODAN_API_KEY:
        return [], []
    jm.log_info("Shodan →")
    findings, assets = [], []
    try:
        import shodan as shodan_lib
        from utils.rate_limiter import shodan_search
        api = shodan_lib.Shodan(SHODAN_API_KEY)
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, lambda: shodan_search(api, f"hostname:{host}"))
        for item in results.get("matches", []):
            ip = item.get("ip_str", "")
            port = item.get("port")
            if ip:
                assets.append({"type": "ip", "value": ip, "port": port, "source_tool": "shodan"})
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="shodan",
                    finding_type="open_port",
                    title=f"Shodan: {ip}:{port}",
                    severity=Severity.info,
                    host=ip, port=port,
                    description=item.get("data", "")[:500],
                    raw_output=str(item)[:1000],
                    fingerprint_hash=make_hash("shodan", ip, str(port)),
                ))
        jm.log_ok(f"Shodan: {len(results.get('matches', []))} results")
    except Exception as e:
        jm.log_warn(f"Shodan: {e}")
    return findings, assets
