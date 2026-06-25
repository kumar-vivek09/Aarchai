"""Aarchai Web UI — FastAPI + WebSocket real-time dashboard v2."""
from __future__ import annotations
import asyncio
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Aarchai Web UI v2")

# Extra routes
from web.api_extra import router as extra_router
app.include_router(extra_router)

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, scan_id: str, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.setdefault(scan_id, []).append(ws)

    async def disconnect(self, scan_id: str, ws: WebSocket):
        async with self._lock:
            conns = self._connections.get(scan_id, [])
            if ws in conns:
                conns.remove(ws)

    async def broadcast(self, scan_id: str, event: dict):
        msg = json.dumps(event)
        for ws in list(self._connections.get(scan_id, [])):
            try:
                await ws.send_text(msg)
            except Exception:
                pass


manager = ConnectionManager()


def emit_event(scan_id: str, event_type: str, data: dict):
    event = {"scan_id": scan_id, "type": event_type, "ts": datetime.utcnow().isoformat(), **data}
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(scan_id, event), loop)
    except Exception:
        pass


class ScanRequest(BaseModel):
    target:     str
    stages:     str  = "all"
    fast:       bool = False
    no_passive: bool = False
    auth:       Optional[str] = None
    scope_includes: list[str] = []
    scope_excludes: list[str] = []


@app.get("/", response_class=HTMLResponse)
async def index():
    return (static_dir / "index.html").read_text(encoding="utf-8")


@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    from core.db import init_db, get_session, Target as TModel, Scan
    from core.target import parse_target
    from utils.scope import ScopeConfig
    from utils.auth import load_auth

    init_db()
    parsed = parse_target(req.target)
    session = get_session()

    scope = None
    if req.scope_includes or req.scope_excludes:
        scope = ScopeConfig(includes=req.scope_includes, excludes=req.scope_excludes)

    db_target = TModel(input=req.target, target_type=parsed.type,
                       scope_config=scope.to_dict() if scope else None)
    session.add(db_target); session.commit()

    scan_rec = Scan(target_id=db_target.id, status="pending", started_at=datetime.utcnow())
    session.add(scan_rec); session.commit()
    scan_id = scan_rec.id

    auth_profile = load_auth(req.auth)
    background_tasks.add_task(_run_scan_bg, scan_id, parsed, req, session, scope, auth_profile)
    return {"scan_id": scan_id, "status": "started", "target": req.target}


async def _run_scan_bg(scan_id, parsed, req, session, scope, auth_profile):
    from stages.runner import run_pipeline

    jm = WebJobManager(session, scan_id, str(scan_id))
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        lambda: run_pipeline(parsed, scan_id, session, jm,
                              req.stages, "./reports", req.fast, req.no_passive,
                              scope=scope, auth=auth_profile)
    )


@app.get("/api/scans")
async def list_scans():
    from core.db import get_session, Scan, Target
    session = get_session()
    rows = (session.query(Scan, Target)
            .join(Target, Scan.target_id == Target.id)
            .order_by(Scan.id.desc()).limit(20).all())
    result = []
    for sc, tgt in rows:
        crit = len([f for f in sc.findings if f.severity == "critical"])
        high = len([f for f in sc.findings if f.severity == "high"])
        result.append({
            "id": sc.id, "target": tgt.input, "status": sc.status,
            "started_at": str(sc.started_at or ""),
            "findings": len(sc.findings), "assets": len(sc.assets),
            "critical": crit, "high": high,
        })
    session.close()
    return result


@app.get("/api/scan/{scan_id}/findings")
async def get_findings(scan_id: int, include_suppressed: bool = False):
    from core.db import get_session, Finding
    session = get_session()
    q = session.query(Finding).filter(Finding.scan_id == scan_id)
    if not include_suppressed:
        q = q.filter(Finding.is_suppressed == False)
    findings = q.all()
    result = [_finding_dict(f) for f in findings]
    session.close()
    return result


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: int, fmt: str = "html"):
    path = Path(f"./reports/scan_{scan_id}")
    files = {"pdf": "report.pdf", "json": "findings.json", "csv": "findings.csv",
             "html": "dashboard.html", "attacker": "attacker_perspective.txt"}
    f = path / files.get(fmt, "dashboard.html")
    if f.exists():
        return FileResponse(str(f))
    return {"error": "Report not found", "path": str(f)}


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(scan_id, websocket)


def _finding_dict(f) -> dict:
    return {
        "id": f.id, "tool": f.tool, "finding_type": f.finding_type,
        "title": f.title, "severity": f.severity, "host": f.host,
        "port": f.port, "url": f.url, "cve_ids": f.cve_ids or [],
        "cvss_score": f.cvss_score, "epss_score": f.epss_score,
        "description": f.description or "", "remediation": f.remediation or "",
        "confidence_score": f.confidence_score, "triage_status": f.triage_status,
        "is_suppressed": f.is_suppressed, "exploit_available": f.exploit_available,
        "exploit_links": f.exploit_links or [], "in_cisa_kev": f.in_cisa_kev,
        "metasploit_module": f.metasploit_module, "mitre_tactics": f.mitre_tactics or [],
    }


class WebJobManager:
    def __init__(self, session, scan_id, ws_id):
        from core.job_manager import JobManager
        self._jm = JobManager(session, scan_id)
        self._ws_id = ws_id

    def _emit(self, t, **kw):
        emit_event(self._ws_id, t, kw)

    def update_status(self, s):
        self._jm.update_status(s); self._emit("scan_status", status=s)
    def log_stage(self, s, m=""):
        self._jm.log_stage(s, m); self._emit("stage_start", stage=s, msg=m)
    def log_info(self, m):
        self._jm.log_info(m); self._emit("tool_log", level="info", msg=m)
    def log_ok(self, m):
        self._jm.log_ok(m); self._emit("tool_log", level="ok", msg=m)
    def log_warn(self, m):
        self._jm.log_warn(m); self._emit("tool_log", level="warn", msg=m)
    def log_error(self, m):
        self._jm.log_error(m); self._emit("tool_log", level="error", msg=m)
    def log_finding(self, sev, title):
        self._jm.log_finding(sev, title); self._emit("finding", severity=sev, title=title)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.app:app", host="0.0.0.0", port=8000, reload=False)
