import httpx
import random
from app import auth_manager, config
from app.scanner import endpoint_loader, request_runner

DEFAULT_PATH_PARAMS = {
    "order_id": 1,
    "user_id": 1
}

async def run_scan(target_url: str = None) -> list:
    """
    Orchestrates the endpoint scanner: loads routes, runs them against the target API
    under Anonymous, Standard, and Admin contexts, and records outcomes.
    """
    if not target_url:
        target_url = config.TARGET_API_URL
        
    endpoints = endpoint_loader.load_endpoints()
    scan_results = []
    
    # Establish authorization headers for each context
    auth_headers = {
        "anonymous": {},
        "alice_user": {},
        "bob_user": {},
        "admin_user": {}
    }
    
    try:
        alice_token = auth_manager.get_token("alice_user")
        auth_headers["alice_user"] = {"Authorization": f"Bearer {alice_token}"}
    except Exception as e:
        print(f"Scan Engine Warning: Could not retrieve token for Alice: {e}")

    try:
        bob_token = auth_manager.get_token("bob_user")
        auth_headers["bob_user"] = {"Authorization": f"Bearer {bob_token}"}
    except Exception as e:
        print(f"Scan Engine Warning: Could not retrieve token for Bob: {e}")

    try:
        admin_token = auth_manager.get_token("admin_user")
        auth_headers["admin_user"] = {"Authorization": f"Bearer {admin_token}"}
    except Exception as e:
        print(f"Scan Engine Warning: Could not retrieve token for Admin: {e}")

    async with httpx.AsyncClient() as client:
        for ep in endpoints:
            path = ep["path"]
            method = ep["method"]
            
            # Interpolate path params
            formatted_path = path
            for param, val in DEFAULT_PATH_PARAMS.items():
                formatted_path = formatted_path.replace(f"{{{param}}}", str(val))
                
            full_url = f"{target_url}{formatted_path}"
            
            # Execute for each authorization context
            for context_name, headers in auth_headers.items():
                payload = ep.get("payload_template")
                
                # Check for special payload cases to avoid database constraints
                if payload:
                    payload = payload.copy()
                    if "{rand}" in payload.get("username", ""):
                        payload["username"] = payload["username"].replace("{rand}", str(random.randint(10000, 99999)))
                    # Replace template variables for login tests
                    if "{username}" in payload.get("username", ""):
                        payload["username"] = "alice"
                        payload["password"] = "password123"

                res = await request_runner.send_request(
                    client=client,
                    method=method,
                    url=full_url,
                    headers=headers,
                    json_data=payload
                )
                
                scan_results.append({
                    "endpoint": path,
                    "method": method,
                    "auth_context": context_name,
                    "status_code": res["status_code"],
                    "latency_sec": res["latency_sec"],
                    "error": res["error"],
                    "response_body": res["body"]
                })
                
    return scan_results
