# BOLAHawk — submission readiness

Everything below comes from running the project, not from reading it. The stack was
started locally (Flask target on :5000, FastAPI backend on :8000, built dashboard on
:4173), two scans were executed end-to-end, and the deleted test suite was restored
and run.

---

## Verified working

| Check | Result |
|---|---|
| Full scan against running target | **17 findings** — 8 Critical, 2 High, 7 Medium, peak CVSS 10.0 |
| All five vulnerability classes fire | BOLA, Mass Assignment, BFLA, JWT flaws, Rate limiting — all present |
| CVSS v3.1 implementation | Correct roundup, correct scope-dependent PR weights, vector strings well-formed |
| Restored test suite | **11 tests pass** in 0.70s |
| Frontend production build | Clean, no errors |
| Reseed-before-scan ordering fix | Confirmed — repeat scans return identical counts |

The engineering is real. What's costing marks is almost entirely evidence and
consistency, not code quality.

---

## Blockers — fix these before you submit

### 1. The test folder was deleted from the repo

Commit `453ab25 "Deleted Test Folders"` removed `backend/tests/` — 111 lines, 11 tests.
But the report still lists **pytest 8.0 — "Unit tests for the scanner's detection logic"**
in the tools table, and Step 1 says *"Verified it with a pytest test."* An evaluator who
clones the repo finds nothing. That reads worse than never having written tests.

They were recovered from git history and **all 11 still pass unchanged**. Restore them:

```bash
git checkout 453ab25^ -- backend/tests/
cd backend && python -m pytest tests -q     # 11 passed
git add backend/tests && git commit -m "Restore detection-logic unit tests"
```

Files are also in `bolahawk-upgrade/backend/tests/` if you'd rather copy them in.

### 2. A clean clone will not start

`vulnerable-target-api/routes/auth.py` raises `RuntimeError` if `JWT_SECRET` is unset.
`.env` is gitignored, there is **no `.env.example`** for the target, and
`docker-compose.yml` doesn't set the variable. So `docker compose up --build` on a fresh
clone crashes the target container — directly contradicting objective 7 and Step 8.

Worse: your local `.env` now has a strong random secret, so the **"JWT weak signing
secret — Critical 10.0"** finding in your report no longer reproduces on your own
machine. The target is supposed to be weak; that was a Semgrep fix applied to the wrong
service.

Fixed files are in `bolahawk-upgrade/`: `vulnerable-target-api/.env.example` and a
`docker-compose.yml` that sets `JWT_SECRET` explicitly with a comment explaining why the
weak value is deliberate.

### 3. Dead CORS code

`backend/app/main.py` builds `_allowed_origins` from the `ALLOWED_ORIGINS` env var, then
ignores it and hardcodes two origins into the middleware. The env var, the `.env.example`
entry, and the three-line comment above it are all doing nothing. This actually blocked
the dashboard during testing here. One-line fix:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,   # was a hardcoded list
    ...
)
```

### 4. Your screenshots contradict your text

The dashboard screenshot in the report shows **11 findings, 2 Critical**. The abstract,
conclusion, and slide 9 all say **17 findings, 8 Critical**. The report's own summary
table lists **6 rows**. Three different numbers for the same scan.

The gap is explainable: 17 − 11 = the 6 Mass Assignment findings, which weren't firing on
the deployed Render target. Fix the deployment, re-run, re-screenshot — or replace the
screenshot with a local run.

Then say the numbers plainly, once, in the abstract:

> The scan produced **17 confirmed findings**, which collapse to **8 unique flaws** across
> five vulnerability classes — a single BOLA bug, for instance, is proven six times over
> (GET, PUT and DELETE, in both directions).

The new dashboard shows both numbers side by side so this can't happen again.

### 5. `.venv/` shipped inside your submission zip

It's correctly in `.gitignore`, but it's in the archive you handed in — hundreds of files
of noise, and a reviewer opening the zip sees that first. Rebuild the zip from a clean
`git archive`.

---

## Should fix — cheap marks

- **Version table is wrong.** Report says FastAPI 0.111+, pytest 8.0, reportlab 4.0,
  PyJWT 2.8, httpx 0.27. `requirements.txt` actually pins 0.141.1, 9.1.1, 5.0.0, 2.13.0,
  0.28.1. Copy the real pins across.
- **React "Version 1.0/0.2.5"** in the same table is meaningless. It's React 18.3 + Vite 6.4.
- **Slide 9 labels BOLA "Critical · 6.5"** — 6.5 is Medium. Same slide's severity split
  (8/2/7) is the raw count while the table beside it is the deduplicated view.
- **Slide numbering** repeats 7 twice across 11 slides.
- **No architecture diagram in the report.** The README has one; Section 3.1 or 4 is
  crying out for it.
- **Objective 7 says "containerize the entire platform"** but compose only has two
  services — the dashboard isn't in it. A `frontend/Dockerfile` and a third compose
  service are included in `bolahawk-upgrade/`; that closes the objective honestly.
- **The brief names Postman and Burp Suite** ("Security testing with Postman and Burp
  Suite"). Nothing in the submission shows either. Cheapest possible fix: export a Postman
  collection of the target's endpoints, drop the JSON in `docs/`, and add two screenshots
  — one Postman request proving BOLA by hand, one Burp Repeater tab showing the forged
  `alg:none` token being accepted. Half an hour of work against an explicit line in the brief.
- **"API key exposure testing"** is in the brief and isn't covered. Either add a sixth
  check or name it in Future Scope so the omission looks deliberate.

---

## Add a Section 5.3: Verification Evidence

This is the single highest-value addition for the Testing & Evidence band. Right now the
report asserts results; it doesn't prove them. Add:

1. `pytest -q` terminal output — 11 passed
2. The scan summary JSON (`Export JSON` in the new dashboard produces it)
3. A ground-truth table: planted vulnerability → detecting module → finding → CVSS →
   matched/missed. You already have `docs/planted_vulnerabilities.md`; turning it into a
   traceability matrix proves zero false negatives against a known target, which is
   exactly the argument a scanner needs to make.
4. One line on false positives: the scanner found nothing outside the planted set, and
   the `/health` and admin-context rows in the exposure matrix show correct 401/403
   rejections being *not* flagged.

---

## Frontend upgrade

Drop-in replacements are in `bolahawk-upgrade/frontend/`. Same API contract, same file
names where they existed — copy over `src/` and `index.html`, then `npm run build`.
No new dependencies.

**Exposure matrix** — the signature addition. Every route as a row, every identity the
scanner authenticated as (Anonymous, Alice, Bob, Admin) as a column, the returned status
code in each cell. Flagged cells are painted at the finding's severity, correct 401/403
rejections go green. It makes the whole point of the project — *same endpoint, different
identity* — visible in one glance, which no amount of prose in the findings list does.

**Grouped findings.** One BOLA bug proved six ways now shows as one row with a `×6` badge;
expanding it lists every occurrence. The header shows "8 unique flaws / 17 evidence
records," which resolves the number confusion in your report at the interface level.

**OWASP mapping.** Every finding carries its real category — API1:2023 through API5:2023 —
linked to the OWASP page. Your five detection modules happen to map cleanly onto five
distinct Top 10 categories, which is a genuinely strong claim you currently make nowhere
in the UI. Findings are also sortable and searchable by OWASP ID.

**Scan diff.** The status strip compares the current scan against the previous one:
*N new / N still open / N fixed*, with new findings badged. Scan history rows show the
delta. This is what turns a scanner into something a team would actually re-run.

**Exposure index.** A 0–100 weighted posture score with a radial gauge, so the dashboard
opens with a verdict instead of a table.

**Scan progress.** The five real phases (reseed → authenticate → BOLA probes → matrix
sweep → detection + scoring) with a progress bar, instead of a bare seconds counter. It's
a time-based estimate and the code says so in a comment — don't claim it's live telemetry
if you're asked.

**Export JSON**, copy-to-clipboard toasts, keyboard focus rings, `prefers-reduced-motion`
respected, and a proper mobile layout down to 390px.

One design note in case you're asked: the interactive accent was moved off the severity
spectrum to indigo. In a security console, red/orange/yellow/blue carry meaning, so a
brand accent sharing those hues is a real usability bug — nothing clickable should ever be
the same colour as a risk level.

---

## Marks estimate

Honest read of the rubric, as submitted today:

| Band | As submitted | After the fixes above |
|---|---|---|
| Technical implementation (40) | **33** | 37 |
| Testing and evidence (20) | **12** | 19 |
| Documentation quality (20) | **15** | 19 |
| Completeness and professionalism (20) | **16** | 19 |
| **Total** | **≈ 76 / 100** | **≈ 94 / 100** |

**Technical (33/40).** The engine is genuinely good — async multi-identity scanning, five
independent detection modules, CVSS v3.1 from the spec with correct roundup and
scope-dependent PR weights, a reseed-before-scan fix that most students never find the
need for. Deductions are for the clean-clone failure, the dead CORS code, and the
dashboard being outside the compose file.

**Testing (12/20).** This is where the marks are leaking. The suite exists in history and
passes, but the repo says otherwise while the report claims pytest coverage — an evaluator
who checks will read that as an overclaim. Add the tests back plus a verification section
and this jumps straight to 19; it's the cheapest 7 marks on the table.

**Documentation (15/20).** The report is well written and unusually honest about what went
wrong — the challenges and learning-outcomes sections are stronger than most. Held back by
the 17/11/6 inconsistency, the wrong version table, and the "Critical · 6.5" slide error.

**Completeness (16/20).** Live deployment, MIT licence, declaration, references, PPT — all
present and professional. Losing marks on objective 7 being partly met and on Postman /
Burp / API key exposure being in the brief but absent from the submission.

---

## Order to do it in

1. `git checkout 453ab25^ -- backend/tests/` and commit — 2 minutes, biggest single gain
2. Apply the CORS one-liner and the target `.env.example` + compose fix — 10 minutes
3. Re-run the scan locally with the weak secret restored, re-screenshot at 17 findings — 15 minutes
4. Copy in the new frontend, `npm run build`, re-screenshot the dashboard — 20 minutes
5. Fix the version table, the 17/8 wording, and the slide 9 severity label — 20 minutes
6. Postman collection + two Burp screenshots into `docs/` — 30 minutes
7. Write Section 5.3 Verification Evidence — 30 minutes
8. Rebuild the zip with `git archive` so `.venv/` is gone — 2 minutes
