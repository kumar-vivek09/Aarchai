"""Naabu fast port scanner plugin — Stage 2."""
STAGE     = 2
TOOL_NAME = "naabu"

import json
from stages.base import run_tool, tool_available
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


async def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None):
    if not tool_available("naabu"):
        return [], []

    jm.log_info("Plugin: naabu fast port scan")
    r = run_tool(
        ["naabu", "-host", target.host, "-json", "-silent",
         "-top-ports", "100" if fast else "1000"],
        timeout=120
    )
    assets = []
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
            assets.append({
                "type": "port", "value": d.get("ip", target.host),
                "port": d.get("port"), "protocol": "tcp",
                "source_tool": "naabu"
            })
        except Exception:
            pass
    jm.log_ok(f"naabu: {len(assets)} ports")
    return [], assets
