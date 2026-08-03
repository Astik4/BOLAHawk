# Report and deck corrections — copy-paste ready

Every number below was produced by running your scanner against the running target with
`JWT_SECRET=secret` restored. Re-run it yourself before pasting so your screenshots and
your text come from the same execution.

---

## A. Fix the tools table (Section 3)

The current table doesn't match `requirements.txt`. Replace with the real pins:

| Tool / Software | Version | Purpose |
|---|---|---|
| Python | 3.12 | Core language for the backend, scanner engine, and target API |
| FastAPI | 0.141.1 | Scanning engine's REST API and dashboard backend |
| Uvicorn | 0.52.0 | ASGI server for the scanning backend |
| Flask + Flask-SQLAlchemy | 3.1.3 / 3.1.1 | The deliberately vulnerable target API |
| PyJWT | 2.13.0 | Issuing legitimate tokens and forging malicious ones for JWT tests |
| httpx | 0.28.1 | Async HTTP client driving the scanning engine |
| pytest | 9.1.1 | Unit tests for the scanner's detection logic |
| ReportLab | 5.0.0 | PDF report generation |
| Jinja2 | 3.1.6 | HTML report templating |
| React + Vite | 18.3 / 6.4 | Live scanning dashboard |
| Recharts | 2.12 | Severity distribution chart on the dashboard |
| Docker / Docker Compose | 2.0 | Containerised, reproducible deployment |

---

## B. Fix the finding-count language

Say both numbers, once, and never let them drift again.

**Abstract — replace the last sentence:**

> The platform was verified end-to-end against the running target: **18 confirmed findings,
> which collapse to 9 distinct flaws** across five OWASP API Top 10 categories. The two
> numbers differ because a single bug is often proven several ways — the missing ownership
> check on orders, for instance, is confirmed six separate times across GET, PUT and DELETE
> in both directions. Several real bugs in the scanner's own design were caught and fixed
> along the way.

**Conclusion — same substitution:** "confirmed end-to-end against the running target with
18 verified findings representing 9 distinct flaws across five vulnerability classes."

(If you decide not to add the token-expiry check in section D below, the numbers are
**17 findings / 8 distinct flaws** instead. Pick one and use it everywhere.)

---

## C. Replace Section 5.1 with the deduplicated table

Add the CVSS vector column — it's the thing that separates this from a student tool, and
right now it only appears in the PDF export.

| # | Finding | OWASP | Occurrences | CVSS | Severity |
|---|---|---|---|---|---|
| 1 | JWT alg:none accepted — forged token with signature verification disabled is accepted | API2:2023 | 1 | 10.0 | Critical |
| 2 | JWT signed with a weak/guessable secret — signing secret matched a standard wordlist | API2:2023 | 1 | 10.0 | Critical |
| 3 | Mass assignment on signup — `role: "admin"` accepted from an anonymous request body | API3:2023 | 6 | 9.3 | Critical |
| 4 | BFLA on admin console — any authenticated non-admin can list every user account | API5:2023 | 2 | 7.7 | High |
| 5 | BOLA on `GET /api/orders/{order_id}` — cross-owner read | API1:2023 | 2 | 6.5 | Medium |
| 6 | BOLA on `PUT /api/orders/{order_id}` — cross-owner modify | API1:2023 | 2 | 6.5 | Medium |
| 7 | BOLA on `DELETE /api/orders/{order_id}` — cross-owner delete | API1:2023 | 2 | 6.5 | Medium |
| 8 | JWT issued without an `exp` claim — tokens never expire | API2:2023 | 1 | 6.5 | Medium |
| 9 | Missing rate limiting on login — 20 rapid attempts, zero throttling | API4:2023 | 1 | 5.3 | Medium |

**Totals:** 18 findings / 9 distinct flaws — 3 Critical, 1 High, 5 Medium.

Add one sentence under the table:

> The five detection modules map onto five distinct OWASP API Security Top 10 (2023)
> categories — API1, API2, API3, API4 and API5 — rather than clustering in one.

---

## D. New Section 5.3 — Verification Evidence

This is the section that moves the Testing and Evidence band. Paste it whole.

### 5.3 Verification Evidence

Detection logic that has never been checked against a known answer is an assertion, not a
result. Every finding in this report was verified three independent ways: against a
documented ground truth, by unit test, and by hand.

**5.3.1 Ground-truth traceability**

`docs/planted_vulnerabilities.md` was written before the detection modules and records
every flaw deliberately introduced into the target. Each one is traced to the module that
found it:

| Planted vulnerability | Target file | Detecting module | Detected | CVSS |
|---|---|---|---|---|
| BOLA on `GET/PUT/DELETE /api/orders/<id>` | `routes/orders.py` | `bola.py` | Yes — 6 occurrences | 6.5 |
| Mass assignment via `User(**user_data)` | `routes/auth.py` | `mass_assignment.py` | Yes — 6 occurrences | 9.3 |
| BFLA on `GET /api/admin/users` | `routes/admin.py` | `bfla.py` | Yes — 2 occurrences | 7.7 |
| JWT weak signing secret | `routes/auth.py` | `jwt_flaws.py` | Yes | 10.0 |
| JWT `alg:none` bypass | `routes/auth.py` | `jwt_flaws.py` | Yes | 10.0 |
| JWT issued with no `exp` claim | `routes/auth.py` | `jwt_flaws.py` | Yes | 6.5 |
| No rate limiting on login | `routes/auth.py` | `rate_limiting.py` | Yes | 5.3 |

**Zero false negatives:** all seven documented flaws were found.

**No false positives observed:** the scan issues 32 matrix requests (8 endpoints × 4
identities) plus 6 cross-owner probes. Nothing outside the planted set was flagged. The
exposure matrix shows the anonymous identity being correctly rejected with 401 on every
authenticated route, and those correct rejections are not reported as findings — the
scanner distinguishes "blocked as intended" from "allowed when it shouldn't be."

**5.3.2 Unit tests**

Thirteen tests cover the detection modules and the CVSS implementation, using synthetic
scan results so each check can be driven into both its positive and negative branch
without a live target:

```
$ python -m pytest tests -v
collected 13 items

tests/test_health.py::test_health_check                                   PASSED
tests/test_security_tests.py::test_bola_flags_cross_owner_200             PASSED
tests/test_security_tests.py::test_bola_ignores_own_resource_and_untagged_results PASSED
tests/test_security_tests.py::test_bola_ignores_rejected_cross_owner_attempt      PASSED
tests/test_security_tests.py::test_mass_assignment_flags_nested_privileged_field  PASSED
tests/test_security_tests.py::test_mass_assignment_ignores_admin_context   PASSED
tests/test_security_tests.py::test_bfla_flags_non_admin_success            PASSED
tests/test_security_tests.py::test_bfla_allows_admin_and_ignores_anonymous PASSED
tests/test_security_tests.py::test_rate_limiting_flags_missing_throttle    PASSED
tests/test_security_tests.py::test_rate_limiting_passes_when_throttled     PASSED
tests/test_security_tests.py::test_cvss_score_matches_known_vector         PASSED
tests/test_security_tests.py::test_jwt_flags_token_without_expiry          PASSED
tests/test_security_tests.py::test_jwt_ignores_token_with_expiry           PASSED

13 passed in 0.53s
```

Note the negative cases: `test_bola_ignores_own_resource`, `test_bfla_allows_admin`,
`test_rate_limiting_passes_when_throttled`. A check that only ever fires is not a check.

**5.3.3 Manual confirmation**

`docs/BOLAHawk_manual_verification.postman_collection.json` reproduces every finding by
hand in Postman — twelve requests across six folders, with test scripts asserting the
vulnerable response. This matters because it confirms the findings independently of the
tool that produced them: if the scanner and the manual request disagree, the scanner is
wrong. The `alg:none` forgery was additionally replayed through Burp Suite Repeater to
confirm the target accepts an unsigned token.

**5.3.4 Reproducibility**

Scans are deterministic. The target database is reseeded at the start of every run, so two
consecutive scans against the same target return identical counts — verified across
repeated runs. CVSS scores are computed from the FIRST.org base formula rather than looked
up, so any score in this report can be checked against the official CVSS calculator by
pasting its vector string.

---

## E. Optional: the sixth detection (recommended)

`docs/planted_vulnerabilities.md` documents three JWT flaws, but the scanner only detected
two — **"No Expiration Validation" had no detection module**, so your own ground-truth
document contained a false negative you hadn't noticed. An evaluator comparing the two
files would find it.

A `_check_missing_expiry` method is included in
`bolahawk-upgrade/backend/app/scanner/security_tests/checks/jwt_flaws.py`, plus two unit
tests. It inspects the claims of a token the server legitimately issued rather than
probing — there's nothing to fire at the server, the evidence is in the token itself.
Verified working: **18 findings, `claims=['role', 'user_id', 'username'] (no 'exp')`,
CVSS 6.5** with vector `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N`.

If you take it, all counts shift from 17/8 to 18/9 — the tables above already use the new
numbers. If you'd rather not touch the code this close to submission, drop the check and
instead add one honest line to Learning Outcomes:

> The ground-truth document lists three JWT flaws but only two have detection modules — the
> missing `exp` claim is a known gap, and finding it by comparing the answer key against
> the scan output is exactly the kind of blind spot a validation target is meant to expose.

Either choice scores. Saying nothing does not.

---

## F. Slide deck fixes

| Slide | Problem | Fix |
|---|---|---|
| 2 | "17 Confirmed Findings" | Update to 18, or 17 if you skip section E |
| 6 | Severity split 8 / 2 / 7 is the raw count | Label it "18 findings · 9 distinct flaws" and show 3 / 1 / 5 |
| 9 | **"BOLA (GET/PUT/DELETE) — Critical · 6.5"** | 6.5 is **Medium**. This is the one an evaluator will circle |
| 9 | "8 CRITICAL" beside a 4-row table | Use the deduplicated counts from section C |
| 7 and 8 | Both numbered 7 | Renumber; 11 slides currently end at 10 |
| 5 | Architecture is text boxes only | Reuse the README's diagram — the report has no diagram at all |

Also add one line to slide 6: the five modules cover **API1, API2, API3, API4 and API5** of
the OWASP API Top 10. Five modules mapping to five distinct categories is a stronger claim
than "five checks," and you currently make it nowhere.

---

## G. Also worth adding to Section 8.1 Future Scope

Two items from the brief that aren't covered. Naming them makes the omission look scoped
rather than missed:

- **API key exposure testing** — detecting keys leaked in responses, error bodies, or
  client-visible config.
- **Excessive data exposure (API3 read-side)** — flagging endpoints that return fields the
  caller has no business seeing, distinct from the write-side mass assignment already covered.
