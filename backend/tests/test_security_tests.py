import asyncio
from app.scanner.security_tests.checks.bola import BOLACheck
from app.scanner.security_tests.checks.mass_assignment import MassAssignmentCheck
from app.scanner.security_tests.checks.bfla import BFLACheck
from app.scanner.security_tests.checks.rate_limiting import RateLimitingCheck
from app.scanner.security_tests.cvss import CVSSVector, AV, AC, PR, UI, SCOPE, IMPACT, base_score


def test_bola_flags_cross_owner_200():
    results = [
        {"endpoint": "/api/orders/{order_id}", "method": "GET", "auth_context": "alice_user",
         "status_code": 200, "response_body": {}, "resource_owner_id": "bob_user", "requested_id": 2},
    ]
    findings = BOLACheck().run(results)
    assert len(findings) == 1
    assert findings[0].auth_context == "alice_user"


def test_bola_ignores_own_resource_and_untagged_results():
    results = [
        {"endpoint": "/api/orders", "method": "GET", "auth_context": "alice_user",
         "status_code": 200, "response_body": []},  # no resource_owner_id -> not a probe result
        {"endpoint": "/api/orders/{order_id}", "method": "GET", "auth_context": "bob_user",
         "status_code": 200, "response_body": {}, "resource_owner_id": "bob_user", "requested_id": 2},
    ]
    assert BOLACheck().run(results) == []


def test_bola_ignores_rejected_cross_owner_attempt():
    results = [
        {"endpoint": "/api/orders/{order_id}", "method": "GET", "auth_context": "alice_user",
         "status_code": 403, "response_body": {}, "resource_owner_id": "bob_user", "requested_id": 2},
    ]
    assert BOLACheck().run(results) == []


def test_mass_assignment_flags_nested_privileged_field():
    endpoints = [{
        "path": "/api/users/signup", "method": "POST",
        "sensitive_fields": [["user.role", ["admin"]], ["user.is_admin", [True]]],
    }]
    results = [{
        "endpoint": "/api/users/signup", "method": "POST", "auth_context": "anonymous",
        "status_code": 201, "response_body": {"message": "ok", "user": {"role": "admin", "is_admin": True}},
    }]
    findings = MassAssignmentCheck().run(results, endpoints)
    assert len(findings) == 2  # role + is_admin both flagged


def test_mass_assignment_ignores_admin_context():
    endpoints = [{"path": "/api/users/signup", "method": "POST",
                  "sensitive_fields": [["user.role", ["admin"]]]}]
    results = [{"endpoint": "/api/users/signup", "method": "POST", "auth_context": "admin_user",
                "status_code": 201, "response_body": {"user": {"role": "admin"}}}]
    assert MassAssignmentCheck().run(results, endpoints) == []


def test_bfla_flags_non_admin_success():
    endpoints = [{"path": "/api/admin/users", "method": "GET", "admin_only": True}]
    results = [{"endpoint": "/api/admin/users", "method": "GET", "auth_context": "alice_user", "status_code": 200}]
    findings = BFLACheck().run(results, endpoints)
    assert len(findings) == 1


def test_bfla_allows_admin_and_ignores_anonymous():
    endpoints = [{"path": "/api/admin/users", "method": "GET", "admin_only": True}]
    results = [
        {"endpoint": "/api/admin/users", "method": "GET", "auth_context": "admin_user", "status_code": 200},
        {"endpoint": "/api/admin/users", "method": "GET", "auth_context": "anonymous", "status_code": 401},
    ]
    assert BFLACheck().run(results, endpoints) == []


def test_rate_limiting_flags_missing_throttle():
    endpoints = [{"path": "/api/auth/login", "method": "POST", "rate_limit_expected": True}]

    async def always_200(path, method, headers, json_data=None):
        return 200, {}

    findings = asyncio.run(RateLimitingCheck(attempts=5).run(always_200, endpoints))
    assert len(findings) == 1


def test_rate_limiting_passes_when_throttled():
    endpoints = [{"path": "/api/auth/login", "method": "POST", "rate_limit_expected": True}]
    calls = {"n": 0}

    async def throttles_after_three(path, method, headers, json_data=None):
        calls["n"] += 1
        return (200 if calls["n"] <= 3 else 429), {}

    findings = asyncio.run(RateLimitingCheck(attempts=5).run(throttles_after_three, endpoints))
    assert findings == []


def test_cvss_score_matches_known_vector():
    # AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N is a documented 6.5/Medium per the
    # official CVSS 3.1 calculator.
    v = CVSSVector(av=AV.NETWORK, ac=AC.LOW, pr=PR.LOW, ui=UI.NONE,
                   scope=SCOPE.UNCHANGED, conf=IMPACT.HIGH, integ=IMPACT.NONE, avail=IMPACT.NONE)
    assert base_score(v) == 6.5
