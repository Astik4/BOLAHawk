# 🦅 BOLAHawk: Automated REST API Security Scanner

An automated security scanning and auditing platform designed to discover **OWASP API Top 10 vulnerabilities** (such as BOLA, Mass Assignment, BFLA, Rate Limiting issues, and JWT exploits) in REST APIs. The platform includes a scanning engine, an interactive React-based dashboard, a ReportLab PDF exporter, and a deliberately vulnerable companion Flask API for testing and validation.

---

## 🚀 Key Features

* **Vulnerability Probing:**
  * **BOLA / IDOR:** Active cross-user request checking (GET/PUT/DELETE) on parameterized resources.
  * **Mass Assignment:** Identifies endpoints that accept raw objects into DB constructors and promote user roles (e.g. `role: admin`).
  * **BFLA (Access Control):** Checks for missing administrative role verification on privileged endpoints.
  * **JWT Forgery:** Actively tests target APIs for weak secrets (brute-forcing) and the signature-bypass `alg: "none"` exploit.
  * **Missing Rate Limiting:** Audits authentication endpoints (e.g., `/api/auth/login`) against high-frequency brute-forcing.
* **Score & Severity Metrics:** Calculates automated **CVSS v3.1** vectors and base scores for every finding.
* **Reporting:** Generates downloadable **ReportLab PDF reports** (with severity tables, styling, and metadata) and **Jinja2-rendered dark-mode HTML reports**.
* **Visual Dashboard:** An interactive Vite-React UI featuring overview cards, severity distributions (using Recharts), and a detailed findings browser.

---

## 📁 Project Structure

```
├── backend/                   # FastAPI Scanner Engine & Report Exporters
│   ├── app/
│   │   ├── main.py            # API routes (scans, reports, CORS)
│   │   ├── auth_manager.py    # Multi-role token management
│   │   ├── scanner/           # Security scanning core & checks
│   │   └── reporting/         # PDF (ReportLab) & HTML (Jinja2) templates
│   └── tests/                 # Scanner and routing unit tests
│
├── frontend/                  # React + Vite Dashboard
│   ├── src/
│   │   ├── App.jsx            # Scan orchestrator console
│   │   ├── components/        # Recharts graphs & tables
│   │   └── api.js             # Client connections
│   └── dist/                  # Compiled production static bundle
│
├── vulnerable-target-api/     # deliberate Flask target (seeded vulnerabilities)
│   ├── routes/                # Vulnerable endpoints (auth, orders, admin)
│   ├── app.py                 # Flask server core
│   └── seed_data.py           # Database fixture manager
│
└── docker-compose.yml         # Dev services orchestration
```

---

## 🛠️ Quick Start (Docker Compose)

The easiest way to boot the backend scanner and the vulnerable target API together is via Docker Compose:

1. **Launch Containers:**
   ```bash
   docker compose up --build
   ```
   * Target API will run at: `http://localhost:5000`
   * Backend & API docs will run at: `http://localhost:8000` / `http://localhost:8000/docs`

2. **Launch Dashboard:**
   Open a separate shell, navigate to the frontend directory, install dependencies, and run Vite dev:
   ```bash
   cd frontend
   npm install
   VITE_API_BASE=http://localhost:8000 npm run dev
   ```
   * The dashboard will open at: `http://localhost:5173`

---

## 💻 Manual Local Development Setup

If you prefer to run the servers directly in Python:

### 1. Set Up Backend & Target
1. **Initialize Virtual Environment & Install Packages:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r backend/requirements.txt
   pip install -r vulnerable-target-api/requirements.txt
   ```
2. **Run vulnerable Flask Target:**
   ```bash
   python vulnerable-target-api/app.py
   # Runs on http://127.0.0.1:5000
   ```
3. **Run FastAPI Backend & Scanner:**
   ```bash
   uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

### 2. Run Automated Pytest Suite
To verify the scanning engine, JWT exploits, and endpoint routers, execute:
```bash
pytest
```
*(All 18 unit tests should pass successfully)*

---

## 🛡️ Planted Vulnerabilities (Reference Key)

The companion target API has the following vulnerabilities seeded for verification testing:
1. **BOLA/IDOR:** `GET|PUT|DELETE /api/orders/<order_id>` verifies JWT validity but fails to check resource owner constraints (`order.user_id == current_user.id`).
2. **Mass Assignment:** `POST /api/users/signup` feeds request parameters raw into the SQLite database constructor, allowing request bodies containing `"role": "admin"` to gain immediate administrative privilege.
3. **BFLA:** `GET /api/admin/users` admin console does not enforce administrative role boundaries; standard users can query admin actions.
4. **JWT Flaws:** Supports header algorithm `none` signatures without validation, uses `secret` as a weak key signature, and omits standard expiration timestamps (`exp`).
5. **No Rate-Limiting:** `POST /api/auth/login` accepts unlimited calls without IP throttling or lockout policies.
