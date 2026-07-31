# Deployment

## Local (Docker Compose)

```bash
docker compose up --build
```

- Target API: http://localhost:5000
- Backend + scanner: http://localhost:8000
- Docs: http://localhost:8000/docs

The backend's `TARGET_API_URL` is set to `http://target-api:5000` via compose
(Docker's internal DNS) — no `.env` needed for this path.

Frontend isn't containerized here (see below); run it separately:

```bash
cd frontend
npm install
VITE_API_BASE=http://localhost:8000 npm run dev
```

## Split-architecture hosting (recommended for a real deployment)

Since the target API is *intentionally vulnerable*, don't expose it on the
open internet. Recommended split:

| Component | Where | Notes |
|---|---|---|
| `vulnerable-target-api/` | Render/Railway, private/internal networking only | Never expose publicly — it's deliberately broken |
| `backend/` (FastAPI + scanner) | Render/Railway | Set `TARGET_API_URL` to the target's internal service URL |
| `frontend/` | Vercel | Set `VITE_API_BASE` to the backend's public URL |

Steps:
1. Deploy `vulnerable-target-api/` and `backend/` on Render/Railway using
   their Dockerfiles directly (`Root Directory` = the respective folder).
   Put `target-api` on a private service / internal network if the
   platform supports it; otherwise at minimum keep it unauthenticated only
   to the backend's IP range.
2. Set `backend`'s `TARGET_API_URL` env var to the target's internal URL.
3. Deploy `frontend/` on Vercel (`vercel --prod` or Git integration).
   Set `VITE_API_BASE` to the backend's public Render/Railway URL.
4. Update the FastAPI CORS `allow_origins` in `backend/app/main.py` from
   `["*"]` to the actual Vercel domain before this is reachable by anyone
   but you.

## Notes

- `db.sqlite3` for the target API is ephemeral inside its container unless
  you mount a volume — fine for a testing tool where `POST /api/seed`
  resets fixtures anyway.
- Dockerfiles were written and reviewed by hand but not build-tested in
  this environment (no Docker daemon available here) — worth a local
  `docker compose up --build` before you rely on them.
