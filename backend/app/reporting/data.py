from datetime import datetime, timezone

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}


def build_report_context(scan: dict) -> dict:
    """
    `scan` is one of the records stored in main.py's `_scans` dict:
    {scan_id, status, started_at, finished_at, result: {...}, error}

    `result` (once completed) is exactly what security_orchestrator.run_full_scan()
    returns: {scan_results, bola_probe_results, findings, summary}.
    """
    result = scan.get("result") or {}
    findings = sorted(
        result.get("findings", []),
        key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 99), -f["cvss_score"]),
    )

    return {
        "scan_id": scan["scan_id"],
        "scan_number": scan.get("scan_number"),
        "status": scan["status"],
        "started_at": scan.get("started_at"),
        "finished_at": scan.get("finished_at"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": result.get("summary", {"total_findings": 0, "by_severity": {}, "highest_score": 0.0}),
        "findings": findings,
    }
