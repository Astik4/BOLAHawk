# How to apply this bundle

Every path below mirrors your repo layout, so you can copy the folders straight over the
top of `BOLAHawk/`. Nothing here adds a dependency — the frontend still uses only React,
Recharts and Vite, and the backend changes touch two files.

Work on a branch so you can back out:

```bash
git checkout -b submission-polish
```

---

## 1. Restore the deleted tests

`bolahawk-upgrade/backend/tests/` → `backend/tests/`

These are the 11 tests removed in commit `453ab25`, recovered from git history, plus 2 new
ones for the token-expiry check. Verify:

```bash
cd backend
python -m pytest tests -v      # expect: 13 passed
```

If you skip the expiry check in step 3, delete the last two tests in
`test_security_tests.py` and you'll be back to 11 passing.

---

## 2. Backend fixes

`bolahawk-upgrade/backend/app/main.py` → `backend/app/main.py`

One line changed. `_allowed_origins` was being computed from the `ALLOWED_ORIGINS` env var
and then ignored in favour of a hardcoded list. The middleware now uses the variable, which
is what your `.env.example` and the comment above it already promised.

If you'd rather patch by hand than overwrite the file:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,    # was a hardcoded list of two origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## 3. Sixth detection — JWT missing expiry (optional)

`bolahawk-upgrade/backend/app/scanner/security_tests/checks/jwt_flaws.py`
→ `backend/app/scanner/security_tests/checks/jwt_flaws.py`

Adds `_check_missing_expiry()` and wires it into `run()`. Your
`docs/planted_vulnerabilities.md` documents three JWT flaws but the scanner only detected
two — this closes that gap.

Takes your scan from **17 findings / 8 distinct flaws** to **18 / 9**. If you take it,
use the numbers in `BOLAHawk_report_patches.md`; if you skip it, don't copy this file and
use 17/8 throughout.

---

## 4. Make a clean clone actually start

`bolahawk-upgrade/vulnerable-target-api/.env.example` → `vulnerable-target-api/.env.example`
`bolahawk-upgrade/docker-compose.yml` → `docker-compose.yml`

Right now `routes/auth.py` raises if `JWT_SECRET` is unset, `.env` is gitignored, there's no
example file, and compose doesn't set the variable — so `docker compose up --build` on a
fresh clone kills the target container.

The new compose file sets `JWT_SECRET` explicitly, with a comment explaining that the weak
value is deliberate. **Also restore the weak secret in your own `vulnerable-target-api/.env`:**

```
JWT_SECRET=secret
```

Your local `.env` currently holds a strong random secret, which means the
"JWT weak signing secret — Critical 10.0" finding in your report no longer reproduces on
your own machine. That Semgrep fix landed on the wrong service; the target is meant to be
breakable.

Commit the `.env.example`, not the `.env`:

```bash
git add -f vulnerable-target-api/.env.example
```

---

## 5. Dashboard

`bolahawk-upgrade/frontend/src/` → `frontend/src/`
`bolahawk-upgrade/frontend/index.html` → `frontend/index.html`

Same API contract, same filenames where they already existed. `owasp.js` is the only new
module. Then:

```bash
cd frontend
npm run build
npm run preview     # check it before you screenshot
```

What changed: exposure matrix (routes × identities, cells painted at severity), grouped
findings with `×N` badges and an "N unique flaws / N evidence records" header, OWASP
API1–API5:2023 tags linked to the spec, scan-to-scan diffing, a 0–100 exposure gauge, real
phase progress, JSON export, copy toasts, keyboard focus, reduced-motion support, and a
mobile layout down to 390px.

`bolahawk-upgrade/frontend/Dockerfile` → `frontend/Dockerfile` is a multi-stage build that
serves the bundle from nginx. The new compose file adds it as a third service on port 8080,
which closes objective 7 — "containerise the entire platform" — honestly.

---

## 6. Manual verification collection

`bolahawk-upgrade/docs/BOLAHawk_manual_verification.postman_collection.json` → `docs/`

Import into Postman, set `target_url` if you're not on `127.0.0.1:5000`, run the **00 —
Setup** folder first (it stores Alice's and Bob's tokens automatically), then work through
folders 01–05. Each has test scripts asserting the vulnerable response.

Screenshot two of these for the report: one Postman request proving BOLA by hand, and the
`alg:none` forgery replayed in Burp Repeater. The brief names both tools by name.

---

## 7. Rebuild the submission zip without `.venv/`

Your current archive ships the whole virtual environment. Use git so the ignore rules apply:

```bash
git archive --format=zip -o BOLAHawk_submission.zip HEAD
```

---

## Order of work

1. Restore tests, run `pytest -v`, screenshot the output — 2 min
2. Apply `main.py`, `.env.example`, compose, and reset `.env` to `JWT_SECRET=secret` — 10 min
3. Decide on the expiry check (step 3) — 5 min
4. Copy frontend, `npm run build`, run a scan, screenshot desktop and mobile — 20 min
5. Apply `BOLAHawk_report_patches.md` to the report and deck — 40 min
6. Postman + Burp screenshots into `docs/` — 30 min
7. `git archive` the final zip — 2 min
