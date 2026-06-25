"""Extra API routes: triage, suppression, attack graph data."""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class TriageRequest(BaseModel):
    status: str   # confirmed | false_positive | accepted_risk


@router.post("/api/scan/{scan_id}/findings/{finding_id}/triage")
async def triage_finding(scan_id: int, finding_id: int, req: TriageRequest):
    from core.db import get_session, Finding
    session = get_session()
    f = session.query(Finding).filter(Finding.id == finding_id, Finding.scan_id == scan_id).first()
    if not f:
        return {"error": "not found"}
    f.triage_status = req.status
    if req.status == "false_positive":
        f.is_suppressed = True
    session.commit()
    session.close()
    return {"ok": True, "finding_id": finding_id, "status": req.status}


@router.get("/api/scan/{scan_id}/graph")
async def get_attack_graph(scan_id: int):
    """Return nodes + edges for D3.js force-directed attack graph."""
    from core.db import get_session, Finding, Asset
    session = get_session()

    findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
    assets   = session.query(Asset).filter(Asset.scan_id == scan_id).all()

    nodes, edges, node_ids = [], [], set()

    def add_node(nid, label, ntype, severity="info", extra=None):
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({"id": nid, "label": label, "type": ntype,
                          "severity": severity, **(extra or {})})

    def add_edge(src, tgt, label=""):
        edges.append({"source": src, "target": tgt, "label": label})

    # Target node
    from core.db import Scan, Target
    scan = session.get(Scan, scan_id)
    tgt  = session.get(Target, scan.target_id) if scan else None
    root_id = f"target_{scan_id}"
    add_node(root_id, tgt.input if tgt else "target", "target", "info")

    # Subdomain nodes
    for a in assets:
        if a.asset_type == "subdomain":
            nid = f"sub_{a.id}"
            add_node(nid, a.value[:40], "subdomain", "info")
            add_edge(root_id, nid, "subdomain of")
        elif a.asset_type == "ip":
            nid = f"ip_{a.id}"
            add_node(nid, a.value, "ip", "info")
            add_edge(root_id, nid, "resolves to")
        elif a.asset_type == "port":
            nid = f"port_{a.id}"
            label = f"{a.value}:{a.port}/{a.protocol or 'tcp'}"
            add_node(nid, label, "port", "info", {"service": a.service or ""})
            parent = f"ip_{a.id}" if f"ip_{a.id}" in node_ids else root_id
            add_edge(parent, nid, "open port")

    # Finding nodes — link to host
    for f in findings:
        if f.is_suppressed:
            continue
        nid = f"finding_{f.id}"
        sev = f.severity
        add_node(nid, f.title[:50], "finding", sev, {
            "tool": f.tool,
            "cve":  (f.cve_ids or [])[:1],
            "exploit": f.exploit_available,
            "kev":     f.in_cisa_kev,
        })
        # Link finding to its host node
        host_nid = None
        for a in assets:
            if a.asset_type in ("ip","subdomain") and a.value == f.host:
                host_nid = f"{'ip' if a.asset_type=='ip' else 'sub'}_{a.id}"
                break
        add_edge(host_nid or root_id, nid, f.finding_type or "finding")

        # Link CVEs
        for cve in (f.cve_ids or []):
            cve_nid = f"cve_{cve}"
            add_node(cve_nid, cve, "cve", "high" if (f.cvss_score or 0) >= 7 else "medium",
                     {"cvss": f.cvss_score, "exploit": f.exploit_available, "kev": f.in_cisa_kev})
            add_edge(nid, cve_nid, "CVE")

            # Link exploit if available
            if f.exploit_links:
                ex_nid = f"exploit_{cve}"
                add_node(ex_nid, f"Exploit for {cve}", "exploit", "critical")
                add_edge(cve_nid, ex_nid, "PoC/exploit")

    session.close()
    return {"nodes": nodes, "edges": edges, "stats": {
        "nodes": len(nodes), "edges": len(edges)
    }}


@router.get("/api/scan/{scan_id}/attacker")
async def get_attacker_analysis(scan_id: int):
    """Return the AI attacker perspective report."""
    from pathlib import Path
    p = Path(f"./reports/scan_{scan_id}/attacker_perspective.txt")
    if p.exists():
        return {"text": p.read_text(encoding="utf-8")}
    return {"text": "Attacker analysis not yet generated. Run with stage 7 enabled."}
