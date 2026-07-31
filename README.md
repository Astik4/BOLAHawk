# BOLAHawk

> An API security scanner for authorized testing of common OWASP API Security Top 10 issues.

BOLAHawk runs authorization, mass-assignment, rate-limit, and JWT checks against an API you own or are explicitly authorized to test. It includes a deliberately vulnerable Flask target for local demonstrations only.

## Important safety note

The bundled `vulnerable-target-api` is intentionally insecure. It is for local learning and scanner verification only. Do not deploy it publicly or point BOLAHawk at systems without written permission.

## Local addresses and ports

The `localhost` URLs in this README are expected and safe to publish. They identify services on the reader's own computer; they are not credentials and do not expose your machine on GitHub.

| Service | Local URL | Purpose |
| --- | --- | --- |
| Dashboard | http://localhost:5173 | React/Vite interface |
| Scanner backend | http://localhost:8000 | FastAPI scan API |
| API documentation | http://localhost:8000/docs | Interactive FastAPI documentation |
| Demo target | http://localhost:5000 | Deliberately vulnerable local Flask API |

Docker Compose binds the backend and demo target to `127.0.0.1`, so they cannot be reached from another device on your local network.

## Features

- Multi-user authorization testing for BOLA and BFLA
- Mass-assignment, rate-limiting, and JWT checks
- CVSS v3.1 scoring
- HTML and PDF reports
- React dashboard and FastAPI API documentation
- Docker-based local setup

## Quick start with Docker

Prerequisites: Docker Desktop and Node.js 18 or later.

```bash
git clone https://github.com/Astik4/BOLAHawk.git
cd BOLAHawk
docker compose up --build
```

In a second terminal, start the dashboard:

```bash
cd frontend
npm ci
npm run dev
```

Open http://localhost:5173. Use `Ctrl+C` in the Docker terminal to stop the backend and demo target.

## Local development without Docker

Start the demo target:

```bash
cd vulnerable-target-api
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Start the scanner backend in another terminal:

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
# Windows PowerShell: Copy-Item .env.example .env
# macOS/Linux: cp .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Then start the dashboard:

```bash
cd frontend
npm ci
npm run dev
```

## Environment configuration

Copy `backend/.env.example` to `backend/.env` only for local development. The file is ignored by Git.

```env
HOST=127.0.0.1
PORT=8000
TARGET_API_URL=http://127.0.0.1:5000
ALLOWED_ORIGINS=http://localhost:5173
```

These values are configuration, not secrets:

- `HOST` and `PORT` control where the backend listens.
- `TARGET_API_URL` is the API to scan. In Docker Compose it is automatically set to `http://target-api:5000` through Docker's internal network.
- `ALLOWED_ORIGINS` is a comma-separated CORS allowlist. In production, replace the localhost value with your deployed dashboard URL, for example `https://dashboard.example.com`.

Never commit real tokens, API keys, passwords, private keys, or a production `.env` file. If a real secret was ever committed, rotate it immediately, even if it is later deleted from the repository.

## Run a scan through the API

```bash
curl -X POST http://localhost:8000/api/scans
curl http://localhost:8000/api/scans/{scan_id}
```

Reports are available at:

```text
/api/scans/{scan_id}/report.html
/api/scans/{scan_id}/report.pdf
```

## Tests

```bash
cd backend
pytest
```

## Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md). Keep the vulnerable target on a private network and restrict CORS to the real dashboard domain before any deployment.

## Ethical use

Use BOLAHawk only against APIs you own or are explicitly authorized to test. Unauthorized scanning can be illegal and harmful.

## Author

Built by [Astik Gupta](https://github.com/Astik4).