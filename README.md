# BOLAHawk 🦅

> **Automated API Security Testing Platform** — Scan REST APIs for OWASP API Top 10 vulnerabilities, score findings with CVSS, and generate professional PDF/HTML reports in seconds.

---

## 📖 Overview

**BOLAHawk** is an open-source, automated security auditing tool built for developers, security engineers, and penetration testers who need fast, reliable REST API vulnerability assessments.

It targets the [OWASP API Security Top 10](https://owasp.org/API-Security/), with deep coverage of:

| Vulnerability | OWASP Category | Severity |
|---|---|---|
| Broken Object Level Authorization | API1:2023 BOLA | Critical |
| Broken Function Level Authorization | API5:2023 BFLA | High |
| Mass Assignment | API6:2023 | High |
| Missing / Broken Rate Limiting | API4:2023 | Medium |
| Broken Authentication / JWT Flaws | API2:2023 | Critical |

Each finding is automatically scored using the **CVSS v3.1** scoring system and compiled into a structured HTML or PDF report — no manual effort required.

---

## ✨ Features

- 🔍 **Multi-vector scanning** — Tests BOLA, BFLA, Mass Assignment, Rate Limiting, and JWT vulnerabilities in a single scan
- 📊 **CVSS v3.1 scoring** — Every finding receives an industry-standard severity score
- 📄 **Dual report formats** — Download findings as HTML (Jinja2) or PDF (ReportLab) reports
- 🔐 **Multi-user auth matrix** — Simulates cross-owner access using multiple test identities
- ⚡ **FastAPI backend** — High-performance async scanning engine with auto-generated OpenAPI docs
- 🖥️ **React dashboard** — Real-time scan orchestration and findings review via browser UI
- 🐳 **Docker-first** — One command to spin up the full stack locally
- 🎯 **Built-in vulnerable target** — Includes a deliberately flawed Flask API for safe, realistic testing

---

## 🏗️ Architecture

```
BOLAHawk/
├── backend/                  # FastAPI scanning engine + report generator
│   ├── app/
│   │   ├── main.py           # API routes and CORS config
│   │   ├── auth_manager.py   # Multi-user token acquisition
│   │   ├── config.py         # Environment-based configuration
│   │   ├── token_store.py    # In-memory token cache
│   │   ├── scanner/
│   │   │   ├── engine.py              # Scan orchestration core
│   │   │   ├── security_orchestrator.py  # Coordinates all security checks
│   │   │   ├── request_runner.py      # HTTP request executor
│   │   │   ├── endpoint_loader.py     # API endpoint definitions loader
│   │   │   └── security_tests/        # Individual vulnerability modules
│   │   │       ├── checks/            # BOLA, BFLA, mass-assignment, rate-limit, JWT
│   │   │       ├── cvss.py            # CVSS v3.1 scoring calculator
│   │   │       ├── models.py          # Finding data models
│   │   │       └── runner.py          # Test execution runner
│   │   └── reporting/                 # HTML + PDF report templates & generators
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                 # React + Vite dashboard
│   ├── src/
│   └── vite.config.js
├── vulnerable-target-api/    # Deliberately flawed Flask API (demo target)
│   ├── app.py
│   ├── routes/
│   ├── models.py
│   └── Dockerfile
├── docs/                     # Design docs and planted vulnerability inventory
├── docker-compose.yml
└── DEPLOYMENT.md
```

---

## 🚀 Getting Started

### Prerequisites

| Tool | Version |
|---|---|
| Docker & Docker Compose | 20.x+ |
| Node.js | 18.x+ |
| Python | 3.11+ (for local dev only) |

---

### Option 1 — Docker (Recommended)

The fastest way to get the full stack running:

```bash
# Clone the repository
git clone https://github.com/Astik4/BOLAHawk.git
cd BOLAHawk

# Start the backend + vulnerable target API
docker compose up --build
```

Services available after startup:

| Service | URL | Description |
|---|---|---|
| Vulnerable Target API | http://localhost:5000 | Flask API with planted vulnerabilities |
| Backend / Scanner API | http://localhost:8000 | FastAPI scanning engine |
| API Documentation | http://localhost:8000/docs | Interactive OpenAPI (Swagger) UI |

Then start the frontend separately:

```bash
cd frontend
npm install
npm run dev
# Dashboard: http://localhost:5173
```

---

### Option 2 — Local Development (No Docker)

**1. Backend**

```bash
cd backend

# Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env if needed (defaults work for local dev)

# Start the backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**2. Vulnerable Target API**

```bash
cd vulnerable-target-api
pip install -r requirements.txt
python app.py
# Runs at http://127.0.0.1:5000
```

**3. Frontend**

```bash
cd frontend
npm install
npm run dev
# Dashboard at http://localhost:5173
```

---

## ⚙️ Environment Variables

Create a `.env` file in `backend/` (copy from `.env.example`):

```env
# Backend server settings
HOST=127.0.0.1
PORT=8000

# URL of the API to scan (Docker Compose sets this automatically)
TARGET_API_URL=http://127.0.0.1:5000
```

> **Note:** When using Docker Compose, `TARGET_API_URL` is automatically set to `http://target-api:5000` via Docker's internal DNS — no manual `.env` configuration needed.

---

## 🔬 Running a Scan

1. Open the dashboard at **http://localhost:5173**
2. Click **"Start Scan"** to trigger a full security audit against the target API
3. View real-time results as findings come in
4. Download the **HTML** or **PDF** report from the scan results page

You can also trigger scans directly via the API:

```bash
# Start a scan
curl -X POST http://localhost:8000/api/scans

# Poll scan status
curl http://localhost:8000/api/scans/{scan_id}

# Download HTML report
curl http://localhost:8000/api/scans/{scan_id}/report.html -o report.html

# Download PDF report
curl http://localhost:8000/api/scans/{scan_id}/report.pdf -o report.pdf
```

---

## 🧪 Running Tests

```bash
cd backend
pytest
```

---

## ☁️ Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md) for full production deployment instructions including:

- **Docker Compose** (local / self-hosted)
- **Render / Railway** (backend + target API)
- **Vercel** (frontend)

> ⚠️ **Important:** The `vulnerable-target-api` is intentionally insecure and must **never** be exposed publicly. Always deploy it on a private/internal network or behind strict network rules.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend / Scanner | Python 3.11, FastAPI, Uvicorn |
| Auth & JWT testing | PyJWT |
| Report Generation | Jinja2 (HTML), ReportLab (PDF) |
| HTTP Client | HTTPX |
| Vulnerable Target | Python, Flask, SQLite |
| Frontend | React, Vite, Recharts |
| Containerization | Docker, Docker Compose |

---

## 📂 API Reference

Full interactive documentation is available at **http://localhost:8000/docs** when the backend is running.

Key endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scans` | Start a new security scan |
| `GET` | `/api/scans/{id}` | Get scan status and findings |
| `GET` | `/api/scans/{id}/report.html` | Download HTML report |
| `GET` | `/api/scans/{id}/report.pdf` | Download PDF report |

---

## 🤝 Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes with clear messages
4. Open a Pull Request

Please ensure all tests pass before submitting a PR.

---

## ⚖️ License

This project is intended for **authorized security testing and educational purposes only**.  
Do not run scans against APIs you do not own or have explicit permission to test.

---

## 👤 Author

**Astik Gupta** — [GitHub @Astik4](https://github.com/Astik4)
