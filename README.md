# API Security Testing Platform

An automated security scanning platform designed to audit REST APIs for OWASP API Top 10 vulnerabilities (including BOLA, Mass Assignment, BFLA, Rate Limiting issues, and JWT flaws), calculate CVSS scores, and generate professional PDF reports.

## Project Structure

- `backend/`: The security scanning engine and reporting module (FastAPI).
- `frontend/`: React-based dashboard for orchestrating scans and reviewing findings.
- `vulnerable-target-api/`: A deliberately flawed Flask API serving as a demonstration and validation target.
- `docs/`: Design documentation and lists of planted vulnerabilities.

## Phase Status

- **Phase 1: Project Setup** — Completed.
- **Phase 2: Vulnerable Target API** — Completed.
- **Phase 3: Authentication Layer (scanner)** — Completed.
- **Phase 4: Scanning Engine** — Completed (auth matrix now includes Bob for cross-owner testing).
- **Phase 5: Security Test Modules** — Completed. BOLA, Mass Assignment, BFLA, JWT flaws, and missing rate limiting all detected and CVSS-scored. See `backend/app/scanner/security_orchestrator.py`.
- **Phase 6: Dashboard** — Completed. React + recharts dashboard (`frontend/`), backend scan-trigger API (`POST /api/scans`, `GET /api/scans/{id}`).
- **Phase 7: Report Generation** — Completed. HTML (Jinja2) and PDF (reportlab) findings reports via `GET /api/scans/{id}/report.html` / `.pdf`.
- **Phase 8: Deployment** — Completed. Dockerfiles for backend + target API, `docker-compose.yml`, see `DEPLOYMENT.md`.

## Quickstart

```bash
docker compose up --build
# target API:  http://localhost:5000
# backend API: http://localhost:8000  (docs at /docs)

cd frontend && npm install && npm run dev
# dashboard: http://localhost:5173
```
