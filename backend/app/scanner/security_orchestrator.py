"""
Phase 5 entry point: run_full_scan().

Execution order matters here, so it's spelled out:
1. Reseed the target (POST /api/seed) so fixtures are known-good regardless
   of what a previous run's destructive tests left behind.
2. Discover what Alice and Bob each own (dedicated GET /api/orders calls)
   and fire cross-owner BOLA probes across GET, PUT, and DELETE (Alice ->
   Bob's order, Bob -> Alice's) — BEFORE the Phase 4 matrix runs, because
   that matrix's own DELETE test (order_id=1, run under every context in
   sequence) legitimately succeeds on Alice's turn and would remove the
   evidence. PUT/DELETE probes use disposable orders created just for
   the probe so they don't consume the seeded fixtures.
3. Run the existing Phase 4 matrix (engine.run_scan) unchanged.
4. Run the static checks (BOLA/Mass Assignment/BFLA) over both result
   sets, and the active checks (JWT forgery, rate limiting).
"""
import httpx
from app import auth_manager, config
from app.scanner import endpoint_loader, engine, request_runner
from app.scanner.security_tests.runner import SecurityTestRunner


async def _discover_owned_order_ids(client, target_url, auth_headers) -> dict:
    """
    One dedicated GET /api/orders call per user, run BEFORE engine.run_scan's
    matrix. This has to happen first: that matrix's own DELETE test
    (order_id=1, run under every context in sequence) legitimately
    succeeds on Alice's turn since she owns it — by the time a probe
    added afterward looked at order 1, it would already be gone.
    """
    owned = {}
    for context in ("alice_user", "bob_user"):
        res = await request_runner.send_request(
            client=client, method="GET", url=f"{target_url}/api/orders", headers=auth_headers[context],
        )
        if isinstance(res["body"], list):
            owned[context] = [o["id"] for o in res["body"] if isinstance(o, dict) and "id" in o]
    return owned


async def _run_bola_cross_owner_probes(client, target_url, auth_headers, owned) -> list:
    """Alice requests Bob's order, Bob requests Alice's order. A 200 here
    is the smoking gun for BOLA — this is what the Phase 4 matrix couldn't
    reach since it only ever used order_id=1."""
    results = []
    contexts = [c for c in ("alice_user", "bob_user") if owned.get(c)]

    for attacker in contexts:
        for victim in contexts:
            if attacker == victim:
                continue
            victim_order_id = owned[victim][0]
            path = f"/api/orders/{victim_order_id}"
            res = await request_runner.send_request(
                client=client,
                method="GET",
                url=f"{target_url}{path}",
                headers=auth_headers[attacker],
            )
            results.append({
                "endpoint": "/api/orders/{order_id}",
                "method": "GET",
                "auth_context": attacker,
                "status_code": res["status_code"],
                "latency_sec": res["latency_sec"],
                "error": res["error"],
                "response_body": res["body"],
                "resource_owner_id": victim,
                "requested_id": victim_order_id,
            })
    return results


async def _create_disposable_order(client, target_url, auth_headers, owner_context) -> int:
    """Creates a throwaway order owned by owner_context, used as bait for
    the PUT/DELETE cross-owner probes below (doesn't touch the seeded
    orders the GET probe and Phase 4 matrix rely on)."""
    res = await request_runner.send_request(
        client=client, method="POST", url=f"{target_url}/api/orders",
        headers=auth_headers[owner_context],
        json_data={"item_name": "BOLA-probe-item", "quantity": 1, "price": 9.99},
    )
    return res["body"]["id"]


async def _run_bola_write_probes(client, target_url, auth_headers, contexts) -> list:
    """Bob attempts to PUT/DELETE an order Alice owns (and vice versa),
    using a disposable order created just for this probe. Covers the
    write-side of BOLA that the read-only GET probe above doesn't."""
    results = []
    for attacker in contexts:
        for victim in contexts:
            if attacker == victim:
                continue
            victim_order_id = await _create_disposable_order(client, target_url, auth_headers, victim)

            put_res = await request_runner.send_request(
                client=client, method="PUT", url=f"{target_url}/api/orders/{victim_order_id}",
                headers=auth_headers[attacker], json_data={"item_name": "tampered-by-attacker"},
            )
            results.append({
                "endpoint": "/api/orders/{order_id}", "method": "PUT", "auth_context": attacker,
                "status_code": put_res["status_code"], "latency_sec": put_res["latency_sec"],
                "error": put_res["error"], "response_body": put_res["body"],
                "resource_owner_id": victim, "requested_id": victim_order_id,
            })

            del_res = await request_runner.send_request(
                client=client, method="DELETE", url=f"{target_url}/api/orders/{victim_order_id}",
                headers=auth_headers[attacker],
            )
            results.append({
                "endpoint": "/api/orders/{order_id}", "method": "DELETE", "auth_context": attacker,
                "status_code": del_res["status_code"], "latency_sec": del_res["latency_sec"],
                "error": del_res["error"], "response_body": del_res["body"],
                "resource_owner_id": victim, "requested_id": victim_order_id,
            })
    return results


async def _reseed_target(client: httpx.AsyncClient, target_url: str) -> None:
    """
    The Phase 4 matrix's own DELETE test (order_id=1, run under every
    context in sequence) legitimately succeeds for whichever context owns
    it and removes the row — corrupting fixtures for every later probe
    (including this module's own cross-owner checks) and for the next
    time the scan runs. Reseeding first makes every run start from the
    same known-good state.
    """
    await request_runner.send_request(client=client, method="POST", url=f"{target_url}/api/seed")


async def run_full_scan(target_url: str = None) -> dict:
    if not target_url:
        target_url = config.TARGET_API_URL

    endpoints = endpoint_loader.load_endpoints()

    async with httpx.AsyncClient() as client:
        await _reseed_target(client, target_url)
        # Tokens minted before the reseed reference stale user ids — clear
        # the cache so auth_manager re-logs-in against the fresh data.
        auth_manager.clear_tokens()
        auth_headers = {
            "alice_user": {"Authorization": f"Bearer {auth_manager.get_token('alice_user')}"},
            "bob_user": {"Authorization": f"Bearer {auth_manager.get_token('bob_user')}"},
        }

        owned = await _discover_owned_order_ids(client, target_url, auth_headers)
        bola_probe_results = await _run_bola_cross_owner_probes(client, target_url, auth_headers, owned)
        contexts = [c for c in ("alice_user", "bob_user") if owned.get(c)]
        bola_probe_results += await _run_bola_write_probes(client, target_url, auth_headers, contexts)

    # Now safe to run the Phase 4 matrix — its destructive PUT/DELETE tests
    # can consume order_id=1 without affecting the BOLA check above, which
    # already ran and recorded its evidence.
    scan_results = await engine.run_scan(target_url)

    async with httpx.AsyncClient() as client:
        async def prober(path, method, headers, json_data=None):
            res = await request_runner.send_request(
                client=client, method=method, url=f"{target_url}{path}",
                headers=headers, json_data=json_data,
            )
            return res["status_code"], res["body"]

        runner = SecurityTestRunner()
        static_findings = runner.run_static(scan_results + bola_probe_results, endpoints)
        active_findings = await runner.run_active(
            prober=prober,
            endpoints=endpoints,
            sample_valid_token=auth_manager.get_token("alice_user"),
            jwt_protected_endpoint="/api/orders",
            login_payload={"username": "alice", "password": "password123"},
        )

    all_findings = static_findings + active_findings

    return {
        "scan_results": scan_results,
        "bola_probe_results": bola_probe_results,
        "findings": [f.to_dict() for f in all_findings],
        "summary": SecurityTestRunner.summary(all_findings),
    }
