from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app.main import app, _scans
import pytest

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_scans():
    _scans.clear()

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

@patch("app.main.run_full_scan", new_callable=AsyncMock)
def test_create_and_query_scan(mock_run_scan):
    # Mock return value of run_full_scan
    mock_run_scan.return_value = {
        "scan_results": [],
        "bola_probe_results": [],
        "findings": [],
        "summary": {"total_findings": 0, "by_severity": {}, "highest_score": 0.0}
    }
    
    # 1. Start a scan
    response = client.post("/api/scans", json={})
    assert response.status_code == 201
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "running"
    
    scan_id = data["scan_id"]
    
    # 2. Get details (should be running or completed, since it's background task)
    response = client.get(f"/api/scans/{scan_id}")
    assert response.status_code == 200
    details = response.json()
    assert details["scan_id"] == scan_id
    assert details["status"] in ("running", "completed")

def test_list_scans():
    _scans["test-id-1"] = {
        "scan_id": "test-id-1",
        "status": "completed",
        "started_at": "2026-07-31T12:00:00Z",
        "finished_at": "2026-07-31T12:05:00Z",
        "result": None,
        "error": None
    }
    _scans["test-id-2"] = {
        "scan_id": "test-id-2",
        "status": "running",
        "started_at": "2026-07-31T12:10:00Z",
        "finished_at": None,
        "result": None,
        "error": None
    }
    
    response = client.get("/api/scans")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    # Check that they are sorted newest first (test-id-2 started at 12:10)
    assert data[0]["scan_id"] == "test-id-2"
    assert data[1]["scan_id"] == "test-id-1"

def test_get_scan_not_found():
    response = client.get("/api/scans/non-existent-id")
    assert response.status_code == 404

def test_get_report_not_found():
    response = client.get("/api/scans/non-existent-id/report.html")
    assert response.status_code == 404
    
    response = client.get("/api/scans/non-existent-id/report.pdf")
    assert response.status_code == 404

def test_get_report_not_completed():
    _scans["test-id-running"] = {
        "scan_id": "test-id-running",
        "status": "running",
        "started_at": "2026-07-31T12:00:00Z",
        "finished_at": None,
        "result": None,
        "error": None
    }
    response = client.get("/api/scans/test-id-running/report.html")
    assert response.status_code == 400
    
    response = client.get("/api/scans/test-id-running/report.pdf")
    assert response.status_code == 400

def test_get_reports_success():
    _scans["test-id-done"] = {
        "scan_id": "test-id-done",
        "status": "completed",
        "started_at": "2026-07-31T12:00:00Z",
        "finished_at": "2026-07-31T12:05:00Z",
        "result": {
            "scan_results": [],
            "bola_probe_results": [],
            "findings": [
                {
                    "check_id": "BOLA",
                    "title": "BOLA on GET /api/orders/{order_id}",
                    "endpoint": "/api/orders/{order_id}",
                    "method": "GET",
                    "auth_context": "alice_user",
                    "severity": "High",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    "description": "BOLA vulnerability details",
                    "evidence": "evidence",
                    "remediation": "remediation"
                }
            ],
            "summary": {
                "total_findings": 1,
                "by_severity": {"High": 1},
                "highest_score": 7.5
            }
        },
        "error": None
    }
    
    # Check HTML report
    html_response = client.get("/api/scans/test-id-done/report.html")
    assert html_response.status_code == 200
    assert "text/html" in html_response.headers["content-type"]
    assert "BOLAHawk" in html_response.text or "API Security Testing Platform" in html_response.text
    
    # Check PDF report
    pdf_response = client.get("/api/scans/test-id-done/report.pdf")
    assert pdf_response.status_code == 200
    assert "application/pdf" in pdf_response.headers["content-type"]
