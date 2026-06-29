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

    # 2. Evidence Aggregator & Threat Intelligence Correlator (NVD, EPSS, ExploitDB)
    # Note: Initial confidence was calculated in runner.py based on raw outputs.
    # Here, we calculate a new "correlated_confidence" based on aggregated context.
    jm.log_info("Aggregating evidence & querying threat intelligence...")
    for f in db_findings:
        # Threat intel query
        intel = enrich_finding_exploits(f)

        # Correlated Confidence Logic
        # Start with the original confidence score assigned by the runner
        base_confidence = getattr(f, "confidence_score", 50)
        bonus = 0
        
        # Increase confidence if it is actively exploited (CISA KEV) or has public exploits
        if intel.get("in_kev"):
            bonus += 30
        elif intel.get("exploit_available"):
            bonus += 15

        # If CVSS is Critical/High (implying NVD mapping exists and is severe), bump confidence
        if f.cvss_score and float(f.cvss_score) >= 7.0:
             bonus += 10
             
        # If EPSS is high (probability of exploitation in the wild is high)
        if f.epss_score and float(f.epss_score) >= 0.5:
             bonus += 15

        correlated_conf = min(100, base_confidence + bonus)
        f.correlated_confidence = correlated_conf  # Update DB object with new correlated confidence
        f._intel = intel # Attach for graph

    session.commit()

    # 3. Asset Graph & Relationship Builder
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
        
        # If asset is a service/port, link it to its host
        if a.asset_type == "port" and hasattr(target, "host"):
             # basic linking for demonstration; a robust engine would parse the IP out
             pass

    # Add Findings (Vulnerabilities)
    for f in db_findings:
        finding_id = f"vuln_{f.id}"
        G.add_node(finding_id, type="vulnerability", title=f.title, severity=f.severity, confidence=f.confidence_score)
        
        # Map finding to asset based on host/url
        mapped = False
        for a in db_assets:
            if (f.url and str(a.value) in f.url) or (f.host and str(a.value) in f.host):
                 G.add_edge(f"asset_{a.id}", finding_id, relation="has_vulnerability")
                 mapped = True
        
        # Fallback if no specific asset matched
        if not mapped:
             G.add_edge(target_node, finding_id, relation="has_vulnerability")

    if out_dir:
        graph_path = Path(out_dir) / "correlation_graph.json"
        data = nx.node_link_data(G)
        graph_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        jm.log_ok(f"Asset Graph exported to {graph_path.name}")


    # 4. Attack Path Generator (Integrates Exploit Chain builder logic)
    jm.log_info("Generating Attack Paths...")
    try:
        if out_dir:
             build_exploit_chain(db_findings, db_assets, target, scan_id, out_dir)
             jm.log_ok("Attack paths & exploit chains generated")
    except Exception as e:
        jm.log_warn(f"Attack path generation failed: {e}")

    # 5. MITRE Mapper & STRIDE Threat Model
    jm.log_info("Mapping MITRE tactics & generating STRIDE model...")
    try:
        if out_dir:
            generate_stride_model(db_findings, db_assets, target, scan_id, out_dir)
            jm.log_ok("STRIDE threat model generated")
    except Exception as e:
        jm.log_warn(f"Threat model generation failed: {e}")


    jm.log_ok("Correlation Engine completed successfully.")
    
    # Return empty because this stage modifies the database/writes output directly, 
    # it does not "discover" new raw findings in the same way standard stages do.
    return [], []
