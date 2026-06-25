"""Save and load scan snapshots for delta comparison."""
from __future__ import annotations
import json
from core.db import ScanSnapshot, Finding


def save_snapshot(session, scan_id: int, findings: list):
    """Save all findings as a JSON snapshot."""
    snapshot_data = []
    for f in findings:
        snapshot_data.append({
            "fingerprint_hash": f.fingerprint_hash,
            "tool":          f.tool,
            "finding_type":  f.finding_type,
            "title":         f.title,
            "severity":      f.severity.value if hasattr(f.severity, "value") else f.severity,
            "host":          f.host,
            "port":          f.port,
            "url":           f.url,
        })
    snap = ScanSnapshot(scan_id=scan_id, snapshot_json=snapshot_data)
    session.add(snap)
    session.commit()
    return snap


def load_snapshot(session, scan_id: int) -> list[dict]:
    """Load the snapshot for a given scan."""
    snap = session.query(ScanSnapshot).filter(
        ScanSnapshot.scan_id == scan_id
    ).order_by(ScanSnapshot.id.desc()).first()
    return snap.snapshot_json if snap else []


def get_previous_scan_id(session, scan_id: int) -> int | None:
    """Find the previous scan on the same target."""
    from core.db import Scan
    current = session.get(Scan, scan_id)
    if not current:
        return None
    prev = (session.query(Scan)
            .filter(Scan.target_id == current.target_id, Scan.id < scan_id)
            .order_by(Scan.id.desc())
            .first())
    return prev.id if prev else None
