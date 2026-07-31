# BOLAHawk 🦅

---

## What is BOLAHawk?

If you've ever shipped a REST API and wondered *"is this thing actually secure?"* BOLAHawk is the answer.

Most security tools are either too complex to set up, too generic to be useful, or they produce walls of raw output that take hours to make sense of. BOLAHawk was built to fix that. Point it at an API, click scan, and within seconds you get a clean, structured report telling you exactly what's broken, how bad it is, and where it lives.

The name comes from **BOLA** — Broken Object Level Authorization which is the #1 vulnerability in the OWASP API Security Top 10. It's also one of the most commonly missed issues in real-world APIs, because it doesn't look broken from the outside. A user can log in fine, endpoints respond correctly, but underneath, one user can quietly access another user's data just by changing an ID in the URL. BOLAHawk specifically hunts for this and a lot more.

Under the hood, BOLAHawk:
- Logs in as **multiple test users** and builds an authentication matrix
- Fires cross-user requests across every API endpoint it knows about
- Checks whether object-level authorization is enforced (BOLA), function-level access is gated (BFLA), fields are protected from mass assignment, rate limiting is in place, and JWT tokens are handled correctly
- Assigns each finding a **CVSS v3.1 score** the same standard used by security advisories and CVEs
- Compiles everything into a readable **HTML or downloadable PDF report**

It ships with a **deliberately vulnerable Flask API** so you can run real scans against real broken code right out of the box no need to risk scanning something you shouldn't.

---

## Why it matters

APIs are the backbone of modern software, and they're also the most actively exploited attack surface. The [OWASP API Security Top 10](https://owasp.org/API-Security/) exists because these vulnerabilities show up again and again in startups, in enterprises, in apps used by millions of people.

The problem isn't that developers don't care. It's that:
- Manual testing is slow and inconsistent
- Most existing tools focus on web apps, not APIs specifically
- BOLA-type bugs are nearly invisible without cross-user testing

BOLAHawk automates the hard part. It sets up the test matrix, fires the cross-authenticated requests, interprets the responses, and scores the severity so you can focus on fixing issues rather than finding them.

---

## Vulnerabilities Covered

| Vulnerability | OWASP Category | What BOLAHawk checks |
|---|---|---|
| Broken Object Level Authorization (BOLA) | API1:2023 | Can User A access User B's resources by changing an ID? |
| Broken Function Level Authorization (BFLA) | API5:2023 | Can a regular user call admin-only endpoints? |
| Mass Assignment | API6:2023 | Does the API blindly accept unexpected fields in a request body? |
| Missing Rate Limiting | API4:2023 | Can the same endpoint be hammered with requests without any throttle? |
| Broken Authentication / JWT Flaws | API2:2023 | Are tokens validated correctly? Can they be tampered with? |

Each detected issue is given a **CVSS v3.1 base score** with a breakdown of the exploitability and impact metrics the same format you'd see in a professional security audit.

---

## Features

- 🔍 **Automated multi-vector scanning** — runs all vulnerability checks in a single scan session, no configuration per test needed
- 👥 **Multi-user auth matrix** — logs in as multiple identities and cross-tests access between them to catch authorization flaws
- 📊 **CVSS v3.1 scoring** — every finding gets an industry-standard severity score, not just a vague "high/medium/low"
- 📄 **Dual report formats** — export findings as a clean HTML page or a downloadable PDF with full details
- ⚡ **FastAPI backend** — async scanning engine with auto-generated interactive API docs at `/docs`
- 🖥️ **React dashboard** — browser-based UI to kick off scans and review results without touching the terminal
- 🐳 **Docker-first setup** — one command spins up the entire stack, no environment fiddling required
- 🎯 **Built-in vulnerable target** — comes with a deliberately broken Flask API so you can test against real vulnerabilities safely

---

## How It Works (High Level)

```
┌─────────────────────────────────────────────────────────┐
│                     React Dashboard                     │
│               (Trigger scans, view findings)            │
└────────────────────────┬────────────────────────────────┘
                         │ POST /api/scans
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   FastAPI Backend                       │
│  ┌──────────────┐   ┌─────────────────────────────┐    │
│  │ Auth Manager │   │    Security Orchestrator    │    │
│  │ (token store)│──▶│  BOLA · BFLA · MassAssign   │    │
│  └──────────────┘   │  RateLimit · JWT checks     │    │
│                     └──────────────┬────────────── ┘    │
│                                    │                    │
│                     ┌──────────────▼────────────────┐   │
│                     │   CVSS Scorer + Report Gen    │   │
│                     │   (HTML via Jinja2 / PDF)     │   │
│                     └───────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼ HTTP requests
┌─────────────────────────────────────────────────────────┐
│              Vulnerable Target API (Flask)              │
│     (Intentionally broken — safe sandbox for testing)  │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
BOLAHawk/
├── backend/                        # FastAPI scanning engine + report generator
│   ├── app/
│   │   ├── main.py                 # API routes, CORS config, app entrypoint
│   │   ├── auth_manager.py         # Acquires and manages tokens for test users
│   │   ├── config.py               # Environment-based configuration (reads .env)
│   │   ├── token_store.py          # In-memory token cache per user session
│   │   ├── scanner/
│   │   │   ├── engine.py           # Top-level scan orchestration
│   │   │   ├── security_orchestrator.py  # Runs all security check modules
│   │   │   ├── request_runner.py   # Fires authenticated HTTP requests
│   │   │   ├── endpoint_loader.py  # Loads API endpoint definitions
│   │   │   └── security_tests/
│   │   │       ├── checks/         # Individual modules: BOLA, BFLA, mass-assign, rate-limit, JWT
│   │   │       ├── cvss.py         # CVSS v3.1 score calculator
│   │   │       ├── models.py       # Finding data models (structured output)
│   │   │       └── runner.py       # Executes each check and collects results
│   │   └── reporting/              # Report templates and PDF/HTML generators
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                       # React + Vite dashboard
│   ├── src/                        # Components, pages, API hooks
│   └── vite.config.js
│
├── vulnerable-target-api/          # Deliberately flawed Flask API (the scan target)
│   ├── app.py                      # Flask app entrypoint
│   ├── routes/                     # Endpoints with planted vulnerabilities
│   ├── models.py                   # SQLite-backed data models
│   └── Dockerfile
│
├── docs/                           # Design docs and planted vulnerability inventory
├── docker-compose.yml              # Wires backend + target API together
└── DEPLOYMENT.md                   # Full hosting and deployment guide
```

---

## Getting Started

### What you'll need

| Tool | Version | Why |
|---|---|---|
| Docker & Docker Compose | 20.x+ | Runs the full stack with one command |
| Node.js | 18.x+ | For the React dashboard |
| Python | 3.11+ | Only needed for local (non-Docker) dev |

---

### Option 1 — Docker (Recommended)

This is the simplest way. Docker handles the backend and the vulnerable target API together. You just need to run the frontend separately since it's a dev server.

```bash
# Clone the repo
git clone https://github.com/Astik4/BOLAHawk.git
cd BOLAHawk

# Build and start the backend + target API
docker compose up --build
```

Once it's running, you'll have:

| Service | URL | What it is |
|---|---|---|
| Vulnerable Target API | http://localhost:5000 | The broken Flask API you'll be scanning |
| Backend / Scanner | http://localhost:8000 | The FastAPI engine that runs the scans |
| Interactive API Docs | http://localhost:8000/docs | Swagger UI — explore or test endpoints directly |

Now start the dashboard:

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** and you're ready to scan. 🎉

---

### Option 2 — Local Dev (No Docker)

If you'd rather run everything directly, here's how to wire each piece up.

**Step 1 — Start the vulnerable target API**

```bash
cd vulnerable-target-api
pip install -r requirements.txt
python app.py
# Runs at http://127.0.0.1:5000
```

**Step 2 — Start the backend scanner**

```bash
cd backend

# Set up a virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy the example env file (defaults work out of the box)
cp .env.example .env

# Start the server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Step 3 — Start the frontend**

```bash
cd frontend
npm install
npm run dev
# Dashboard at http://localhost:5173
```

---

## Environment Variables

The backend reads from a `.env` file. Copy the example and you're good to go for local dev — the defaults work without any changes.

```bash
cp backend/.env.example backend/.env
```

```env
# Where the backend listens
HOST=127.0.0.1
PORT=8000

# The API that BOLAHawk will scan
TARGET_API_URL=http://127.0.0.1:5000
```

> **Docker users:** When running via `docker compose`, `TARGET_API_URL` is automatically set to `http://target-api:5000` using Docker's internal DNS. You don't need to touch `.env` at all.

---

## Running a Scan

**From the dashboard:**

1. Open **http://localhost:5173**
2. Hit **"Start Scan"**
3. Watch findings populate in real time
4. Click a finding to expand it and see the CVSS score and details
5. Download your report as **HTML** or **PDF**

**From the terminal (curl):**

```bash
# Kick off a scan
curl -X POST http://localhost:8000/api/scans

# Check the scan status (use the id from the response above)
curl http://localhost:8000/api/scans/{scan_id}

# Get the HTML report
curl http://localhost:8000/api/scans/{scan_id}/report.html -o report.html

# Get the PDF report
curl http://localhost:8000/api/scans/{scan_id}/report.pdf -o report.pdf
```

The scan typically completes in a few seconds. The report breaks down every finding with its endpoint, the request that triggered it, and the CVSS v3.1 score with severity classification.

---

## Running Tests

```bash
cd backend
pytest
```

---

## Deployment

Full hosting instructions are in [DEPLOYMENT.md](./DEPLOYMENT.md), covering:

- **Docker Compose** — for local or self-hosted setups
- **Render / Railway** — for hosting the backend and target API in the cloud
- **Vercel** — for deploying the React frontend

> ⚠️ **Security note:** The `vulnerable-target-api` is intentionally broken by design. It must **never** be exposed on the public internet. If you're deploying to the cloud, keep it on a private/internal network and only let the backend reach it.

---

## Tech Stack

| Layer | Technology | Why this choice |
|---|---|---|
| Backend / Scanner | Python 3.11, FastAPI, Uvicorn | Fast async runtime, great for concurrent HTTP testing |
| Auth & JWT testing | PyJWT | Lightweight JWT encode/decode for simulating flawed token flows |
| Report Generation | Jinja2 (HTML), ReportLab (PDF) | Jinja for readable templates, ReportLab for portable PDF output |
| HTTP Client | HTTPX | Async-native HTTP client — pairs naturally with FastAPI |
| Vulnerable Target | Python, Flask, SQLite | Minimal setup, easy to plant vulnerabilities deliberately |
| Frontend | React, Vite, Recharts | Snappy dev experience, good charting for findings visualization |
| Containerization | Docker, Docker Compose | Reproducible environments, easy one-command startup |

---

## API Reference

The full interactive API documentation is available at **http://localhost:8000/docs** while the backend is running. You can explore endpoints, fire test requests, and inspect response schemas right from the browser.

Core endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scans` | Start a new security scan |
| `GET` | `/api/scans/{id}` | Get scan status, progress, and findings |
| `GET` | `/api/scans/{id}/report.html` | Render findings as an HTML report |
| `GET` | `/api/scans/{id}/report.pdf` | Download findings as a PDF report |

---

## Contributing

Contributions are genuinely welcome whether it's a new vulnerability check, a better report format, or just fixing a typo.

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature-name`
3. Make your changes and write tests if relevant
4. Open a Pull Request with a clear description of what and why

Please make sure existing tests still pass before submitting.

---

## Ethical Use

This tool is built for **authorized security testing and educational purposes only**. The vulnerable target API included in this repo exists so you have a safe, legal environment to test against.

Do not run BOLAHawk against any API that you don't own or have explicit written permission to test. Unauthorized security scanning is illegal in most jurisdictions.
