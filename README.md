# BOLAHawk (API Security Testing Platform)

An automated security scanning platform designed to audit REST APIs for OWASP API Top 10 vulnerabilities (including BOLA, Mass Assignment, BFLA, Rate Limiting issues, and JWT flaws), calculate CVSS scores, and generate professional PDF reports.

## Project Structure

- `backend/`: The security scanning engine and reporting module (FastAPI).
- `frontend/`: React-based dashboard for orchestrating scans and reviewing findings.
- `vulnerable-target-api/`: A deliberately flawed Flask API serving as a demonstration and validation target.
- `docs/`: Design documentation and lists of planted vulnerabilities.

## Phase Status

- **Phase 1: Project Setup** - Completed (Skeleton created, FastAPI app running, test passing).
- **Phase 2: Vulnerable Target API** - Next.
