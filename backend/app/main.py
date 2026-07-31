import os
import uuid
import tempfile
from datetime import datetime, timezone
from pydantic import BaseModel
from fastapi import FastAPI, BackgroundTasks, HTTPException, Response
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.scanner.security_orchestrator import run_full_scan
from app.reporting.data import build_report_context
from app.reporting.pdf_report import build_pdf_report
from app.reporting.html_report import render_html_report

app = FastAPI(
    title="BOLAHawk API Security Scanner",
    description="Backend API and Scanning Engine for auditing REST APIs",
    version="1.0.0"
)

# Enable CORS for local dashboard development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store
_scans = {}

class ScanRequest(BaseModel):
    target_url: str = None

async def run_scan_task(scan_id: str, target_url: str):
    try:
        res = await run_full_scan(target_url)
        _scans[scan_id]["status"] = "completed"
        _scans[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
        _scans[scan_id]["result"] = res
    except Exception as e:
        _scans[scan_id]["status"] = "failed"
        _scans[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()
        _scans[scan_id]["error"] = str(e)

@app.get("/health", status_code=200)
async def health_check():
    return {"status": "ok"}

@app.post("/api/scans", status_code=201)
async def start_scan_endpoint(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    _scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "started_at": started_at,
        "finished_at": None,
        "result": None,
        "error": None
    }
    background_tasks.add_task(run_scan_task, scan_id, req.target_url)
    return {"scan_id": scan_id, "status": "running"}

@app.get("/api/scans")
async def list_scans():
    sorted_scans = sorted(
        _scans.values(),
        key=lambda s: s["started_at"] or "",
        reverse=True
    )
    return list(sorted_scans)

@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/api/scans/{scan_id}/report.pdf")
async def get_pdf_report(scan_id: str, background_tasks: BackgroundTasks):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan is not completed yet")
    
    context = build_report_context(scan)
    fd, tmp_path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    
    build_pdf_report(context, tmp_path)
    background_tasks.add_task(os.remove, tmp_path)
    return FileResponse(tmp_path, media_type="application/pdf", filename=f"scan_report_{scan_id}.pdf")

@app.get("/api/scans/{scan_id}/report.html")
async def get_html_report(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan is not completed yet")
    
    context = build_report_context(scan)
    html_content = render_html_report(context)
    return HTMLResponse(content=html_content, media_type="text/html")
