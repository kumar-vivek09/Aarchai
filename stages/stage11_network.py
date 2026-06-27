"""Stage 11 — Network Topology: CIDR discovery, arp-scan, traceroute, network diagram."""
from __future__ import annotations
import asyncio
import json
import re
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir))


async def _run_async(target, scan_id, session, jm, fast, out_dir):
    host = target.host
    jm.log_stage("stage11_network", f"Network topology mapping: {host}")

    tasks = [
        asyncio.create_task(_arp_scan(host, scan_id, jm)),
        asyncio.create_task(_traceroute(host, scan_id, jm)),
        asyncio.create_task(_ping_sweep(host, scan_id, jm, fast)),
        asyncio.create_task(_vlan_discovery(host, scan_id, jm)),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings, assets = [], []
    for r in results:
        if not isinstance(r, Exception):
            f, a = r; findings.extend(f); assets.extend(a)
        else:
            jm.log_warn(f"Network topo error: {r}")

    # Generate topology diagram
    if assets and out_dir:
        _generate_topology_diagram(assets, scan_id, out_dir, jm)

    jm.log_ok(f"Network: {len(findings)} findings, {len(assets)} hosts")
    return findings, assets


async def _arp_scan(host, scan_id, jm):
    """ARP scan to discover live hosts on the local network."""
    if not tool_available("arp-scan"):
        jm.log_warn("arp-scan not installed: apt install arp-scan")
        return [], []
    jm.log_info("arp-scan →")
    # Determine interface
    r = await run_async(["arp-scan", "--localnet", "--interface=eth0", "--ignoredups"], timeout=60)
    if not r.success:
        r = await run_async(["arp-scan", host if "/" in host else f"{host}/24", "--ignoredups"], timeout=60)
    findings, assets = [], []
    # Parse ARP output: "192.168.1.1   aa:bb:cc:dd:ee:ff   Vendor"
    pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-f:]{17})\s+(.*)")
    hosts_found = []
    for line in r.stdout.splitlines():
        m = pattern.match(line.strip())
        if m:
            ip, mac, vendor = m.groups()
            hosts_found.append({"ip": ip, "mac": mac, "vendor": vendor.strip()})
            assets.append({"type": "ip", "value": ip, "service": f"MAC:{mac} {vendor}", "source_tool": "arp-scan"})

    if hosts_found:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="arp-scan",
            finding_type="live_hosts_discovered",
            title=f"ARP scan: {len(hosts_found)} live host(s) on local network",
            severity=Severity.info,
            host=host,
            description="Live hosts:" + "".join(f"{h['ip']} ({h['mac']}) — {h['vendor']}" for h in hosts_found[:30]),
            raw_output=r.stdout[:3000],
            fingerprint_hash=make_hash("arp_scan", host, str(len(hosts_found))),
        ))
        jm.log_ok(f"arp-scan: {len(hosts_found)} hosts")
    return findings, assets


async def _traceroute(host, scan_id, jm):
    """Traceroute to map network path and identify intermediate hops."""
    jm.log_info("traceroute →")
    r = await run_async(["traceroute", "-n", "-m", "20", host], timeout=60)
    if not r.success:
        r = await run_async(["tracepath", "-n", host], timeout=60)
    findings, assets = [], []
    hops = []
    for line in r.stdout.splitlines():
        # Match: " 3  10.0.0.1  2.345 ms"
        m = re.search(r"(\d+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if m:
            hop_num, hop_ip = m.groups()
            if hop_ip != "*":
                hops.append({"hop": int(hop_num), "ip": hop_ip})
                assets.append({"type": "router", "value": hop_ip, "source_tool": "traceroute",
                               "service": f"Router hop #{hop_num}"})
    if hops:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="traceroute",
            finding_type="network_path",
            title=f"Network path to {host}: {len(hops)} hops",
            severity=Severity.info,
            host=host,
            description="Network routing path:" + "".join(f"Hop {h['hop']}: {h['ip']}" for h in hops),
            raw_output=r.stdout[:2000],
            fingerprint_hash=make_hash("traceroute", host),
        ))
    return findings, assets


async def _ping_sweep(host, scan_id, jm, fast):
    """Fast ICMP ping sweep over a CIDR range."""
    if "/" not in host:
        return [], []
    jm.log_info(f"Ping sweep: {host} →")
    rate = "5000" if fast else "2000"
    r = await run_async(
        ["nmap", "-sn", "-T4", "--min-rate", rate, "--open", host, "-oG", "-"],
        timeout=300
    )
    assets = []
    for line in r.stdout.splitlines():
        m = re.search(r"Host:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if m:
            ip = m.group(1)
            assets.append({"type": "ip", "value": ip, "source_tool": "nmap-ping"})
    jm.log_ok(f"Ping sweep: {len(assets)} live hosts in {host}")
    return [], assets


async def _vlan_discovery(host, scan_id, jm):
    """Attempt basic VLAN/subnet discovery via common gateway patterns."""
    findings, assets = [], []
    # Check for common internal subnets from the target's perspective
    if "/" in host:
        # Already a CIDR, skip
        return [], []
    # Look for router discovery via nmap router scan
    r = await run_async(
        ["nmap", "-sV", "-p", "22,23,80,443,8080", "--script", "default",
         "-oG", "-", "--open", f"{host}/24"],
        timeout=120
    )
    # Parse out any routers/switches based on banner/service
    for line in r.stdout.splitlines():
        if any(x in line.lower() for x in ("cisco", "juniper", "mikrotik", "router", "switch", "firewall")):
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if m:
                ip = m.group(1)
                assets.append({"type": "network_device", "value": ip, "source_tool": "nmap",
                               "service": "Router/Switch"})
    return findings, assets


def _generate_topology_diagram(assets, scan_id, out_dir, jm):
    """Generate a D3.js network topology HTML diagram."""
    try:
        import json as json_mod
        nodes = []
        for i, a in enumerate(assets[:100]):
            atype = a.get("type", "ip")
            color = {"ip": "#3b82f6", "router": "#ef4444", "network_device": "#f97316",
                     "subdomain": "#14b8a6", "cidr": "#6366f1"}.get(atype, "#64748b")
            nodes.append({"id": i, "label": a.get("value","")[:30], "type": atype, "color": color})

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Network Topology — Scan #{scan_id}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>body{{background:#0a0c10;margin:0}}svg{{width:100vw;height:100vh}}</style>
</head><body>
<svg id="svg"><g id="g"></g></svg>
<script>
const nodes = {json_mod.dumps(nodes)};
const links = [];
// Connect all to first node (root)
for(let i=1;i<nodes.length;i++) links.push({{source:0, target:i}});
const svg = d3.select("#svg");
const g   = svg.append("g");
svg.call(d3.zoom().on("zoom", e => g.attr("transform", e.transform)));
const W = window.innerWidth, H = window.innerHeight;
const sim = d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d=>d.id).distance(80))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(W/2, H/2));
const link = g.selectAll("line").data(links).join("line")
  .attr("stroke","rgba(255,255,255,.1)").attr("stroke-width",1);
const node = g.selectAll("g.n").data(nodes).join("g").attr("class","n").call(d3.drag()
  .on("start",(e,d)=>{{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}})
  .on("drag",(e,d)=>{{d.fx=e.x;d.fy=e.y;}})
  .on("end",(e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}));
node.append("circle").attr("r",10).attr("fill",d=>d.color).attr("fill-opacity",.8);
node.append("text").attr("dx",13).attr("dy","0.35em")
  .style("fill","#94a3b8").style("font","10px JetBrains Mono,monospace").text(d=>d.label);
sim.on("tick",()=>{{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
}});
</script></body></html>"""

        out = Path(out_dir) / "network_topology.html"
        out.write_text(html, encoding="utf-8")
        jm.log_ok(f"Network topology diagram: {out}")
    except Exception as e:
        jm.log_warn(f"Topology diagram: {e}")
