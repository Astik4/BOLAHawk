import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from app.scanner.security_orchestrator import run_full_scan
from app.reporting.data import build_report_context
from app.reporting.html_report import render_html_report
from app.reporting.pdf_report import build_pdf_report

app = FastAPI(
    title="BOLAHawk",
    description="Backend API and Scanning Engine for auditing REST APIs",
    version="1.0.0"
)

# CORS origins are read from the ALLOWED_ORIGINS env var (comma-separated).
# Defaults to the Vite dev-server origin for local development.
# For production, set ALLOWED_ORIGINS to your actual frontend domain(s).
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
_allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# In-memory scan store. Fine for a single-operator local tool; swap for a
# real DB/queue if this ever needs to survive a restart or run concurrent
# scans safely.
_scans: dict[str, dict] = {}
_scan_counter = 0


class ScanRequest(BaseModel):
    target_url: Optional[str] = None


@app.get("/health", status_code=200)
async def health_check():
    return {"status": "ok"}


@app.post("/api/scans", status_code=202)
async def start_scan(req: ScanRequest = ScanRequest()):
    """Kicks off a full Phase 4+5 scan against the target and returns a scan_id
    immediately. Poll GET /api/scans/{scan_id} for status/results."""
    scan_id = str(uuid.uuid4())
    global _scan_counter
    _scan_counter += 1
    _scans[scan_id] = {
        "scan_id": scan_id,
        "scan_number": _scan_counter,
        "target_url": req.target_url or "http://127.0.0.1:5000",
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "result": None,
        "error": None,
    }

    async def _run():
        try:
            result = await run_full_scan(req.target_url)
            _scans[scan_id]["result"] = result
            _scans[scan_id]["status"] = "completed"
        except Exception as e:
            _scans[scan_id]["status"] = "failed"
            _scans[scan_id]["error"] = str(e)
        finally:
            _scans[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

    asyncio.create_task(_run())
    return {"scan_id": scan_id, "status": "running"}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans")
async def list_scans():
    """Most recent first — the dashboard's history view."""
    return sorted(_scans.values(), key=lambda s: s["started_at"], reverse=True)


def _get_completed_scan(scan_id: str) -> dict:
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is '{scan['status']}', not ready for a report yet")
    return scan


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
async def get_report_html(scan_id: str):
    scan = _get_completed_scan(scan_id)
    context = build_report_context(scan)
    return render_html_report(context)


@app.get("/api/scans/{scan_id}/report.pdf")
async def get_report_pdf(scan_id: str):
    scan = _get_completed_scan(scan_id)
    context = build_report_context(scan)
    output_path = os.path.join(tempfile.gettempdir(), f"security-report-{scan_id}.pdf")
    build_pdf_report(context, output_path)
    return FileResponse(
        output_path, media_type="application/pdf",
        filename=f"security-report-{scan_id[:8]}.pdf",
    )
