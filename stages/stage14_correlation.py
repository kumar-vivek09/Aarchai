"""Stage 14 — Correlation Engine (Synthesis and Intel)"""
from __future__ import annotations
import json
from pathlib import Path
import networkx as nx

def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    from core.db import Finding as DBFinding, Asset
    from utils.exploit_chain import build_exploit_chain
    from utils.threat_model import generate_stride_model
    from utils.exploit_mapper import enrich_finding_exploits

    jm.log_stage("stage14_correlation", f"Correlating data for {target.value}")

    # 1. Fetch raw data
    db_findings = session.query(DBFinding).filter(DBFinding.scan_id == scan_id).all()
    db_assets = session.query(Asset).filter(Asset.scan_id == scan_id).all()

    if not db_findings and not db_assets:
        jm.log_warn("No data to correlate.")
        return [], []

    # 2. Cross-Tool Deduplication & Tool Merging
    jm.log_info("Deduplicating findings across tools...")
    dedup_map = {}
    
    for f in db_findings:
        # Create a dedup key based on host, port, and either primary CVE or finding_type
        cve_key = f.cve_ids[0] if f.cve_ids else f.finding_type
        key = f"{f.host}_{f.port}_{cve_key}"
        
        if key not in dedup_map:
            dedup_map[key] = f
            # Initialize a custom list to track detecting tools
            f._detected_by = {f.tool} if f.tool else set()
        else:
            primary = dedup_map[key]
            # Merge tool source
            if f.tool:
                primary._detected_by.add(f.tool)
            # If this duplicate has a higher original confidence, swap them logically (or just bump confidence)
            if f.confidence_score > primary.confidence_score:
                primary.confidence_score = f.confidence_score
            # Suppress the duplicate
            f.is_suppressed = True

    # 3. Evidence Aggregator & Threat Intelligence Correlator (NVD, EPSS, ExploitDB)
    jm.log_info("Aggregating evidence & querying threat intelligence...")
    for f in db_findings:
        if f.is_suppressed:
            continue
            
        # Threat intel query
        intel = enrich_finding_exploits(f, jm)

        # Correlated Confidence Logic
        base_confidence = getattr(f, "confidence_score", 50)
        bonus = 0
        reasons = []
        
        if intel.get("in_kev"):
            bonus += 30
            reasons.append("CISA KEV (+30)")
        elif intel.get("exploit_available"):
            bonus += 15
            reasons.append("Public Exploit (+15)")

        if f.cvss_score and float(f.cvss_score) >= 7.0:
             bonus += 10
             reasons.append(f"CVSS {f.cvss_score} (+10)")
             
        if f.epss_score and float(f.epss_score) >= 0.5:
             bonus += 15
             reasons.append(f"EPSS {f.epss_score} (+15)")
             
        # Merge the detected_by list into the raw output so it persists in the report
        if hasattr(f, "_detected_by") and len(f._detected_by) > 1:
             tools_list = list(f._detected_by)
             bonus += 10
             reasons.append(f"Multiple Tools ({len(tools_list)}) (+10)")
             merge_data = json.dumps({"detected_by": tools_list})
             f.raw_output = f.raw_output + f"\n[Correlation] {merge_data}" if f.raw_output else merge_data

        # Explicit hard clamp at 100
        correlated_conf = min(100, base_confidence + bonus)
        f.correlated_confidence = correlated_conf  
        f._intel = intel 
        
        if bonus > 0:
            jm.log_info(f"Boosted confidence for '{f.title[:30]}...': {base_confidence} -> {correlated_conf} | Reasons: {', '.join(reasons)}")

    session.commit()

    # 4. Asset Graph & Relationship Builder
    # ARCHITECTURE NOTE: The database remains the primary source of truth.
    # NetworkX is used entirely in-memory here to compute relationships and 
    # export the graph, but it is NOT used as primary storage.
    jm.log_info("Building Asset Graph...")
    G = nx.DiGraph()
    target_node = f"target_{target.value}"
    G.add_node(target_node, type="target", label=target.value)

    # Add Assets
    for a in db_assets:
        asset_id = f"asset_{a.id}"
        val = str(a.value)
        G.add_node(asset_id, type="asset", asset_type=a.asset_type, value=val)
        G.add_edge(target_node, asset_id, relation="owns")

    # Add Findings (Vulnerabilities)
    for f in db_findings:
        if f.is_suppressed:
            continue
            
        finding_id = f"vuln_{f.id}"
        G.add_node(finding_id, type="vulnerability", title=f.title, severity=f.severity, confidence=f.correlated_confidence)
        
        # Map finding to asset based on host/url
        mapped = False
        for a in db_assets:
            if (f.url and str(a.value) in f.url) or (f.host and str(a.value) in f.host):
                 G.add_edge(f"asset_{a.id}", finding_id, relation="has_vulnerability")
                 mapped = True
        
        if not mapped:
             G.add_edge(target_node, finding_id, relation="has_vulnerability")

    if out_dir:
        graph_path = Path(out_dir) / "correlation_graph.json"
        data = nx.node_link_data(G)
        graph_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        jm.log_ok(f"Asset Graph exported to {graph_path.name}")


    # 5. Attack Path Generator (Integrates Exploit Chain builder logic)
    jm.log_info("Generating Attack Paths...")
    try:
        if out_dir:
             build_exploit_chain(db_findings, db_assets, target, scan_id, out_dir, session)
             jm.log_ok("Attack paths & exploit chains generated and saved to database")
    except Exception as e:
        jm.log_warn(f"Attack path generation failed: {e}")

    # 6. MITRE Mapper & STRIDE Threat Model
    jm.log_info("Mapping MITRE tactics & generating STRIDE model...")
    try:
        if out_dir:
            generate_stride_model(db_findings, db_assets, target, scan_id, out_dir)
            jm.log_ok("STRIDE threat model generated")
    except Exception as e:
        jm.log_warn(f"Threat model generation failed: {e}")


    jm.log_ok("Correlation Engine completed successfully.")
    
    return [], []
