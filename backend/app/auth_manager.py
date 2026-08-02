import json
import time
import httpx
from app import config
from app import token_store

# Free-tier hosts (Render, Railway free plans, etc.) spin down the target API
# after inactivity and can take 30-50s to cold-start on the next request,
# often returning a 502/503 with the host's own HTML gateway page while the
# container boots. Retrying with backoff rides that out instead of failing
# the whole scan on the very first request.
_COLD_START_RETRIES = 6
_COLD_START_DELAY_SECONDS = 8


def _load_credentials():
    """Loads configured test credentials from JSON."""
    try:
        with open(config.USERS_CONFIG_PATH, 'r') as f:
            data = json.load(f)
            return data.get("users", [])
    except FileNotFoundError:
        raise FileNotFoundError(f"Test users config not found at path: {config.USERS_CONFIG_PATH}")


def _summarize_error_body(text: str, content_type: str = "") -> str:
    """Raw HTML/CSS gateway error pages are useless (and huge) in a finding's
    evidence field — surface a short, readable summary instead of the full body."""
    stripped = text.strip()
    looks_like_html = "html" in content_type.lower() or stripped.lower().startswith(("<!doctype", "<html"))
    if looks_like_html:
        return f"(non-JSON HTML response, {len(text)} chars — likely a gateway/cold-start error page, not the target API itself)"
    return stripped[:300] + ("…" if len(stripped) > 300 else "")


def login_user(role: str) -> str:
    """Performs HTTP login against the target API and caches the token.
    Retries through cold-start 502/503s and connection errors before failing."""
    users = _load_credentials()
    user_cred = next((u for u in users if u.get("role") == role), None)
    if not user_cred:
        raise ValueError(f"Credentials for role '{role}' not configured in test_users.json")

    payload = {
        "username": user_cred["username"],
        "password": user_cred["password"]
    }

    url = f"{config.TARGET_API_URL}/api/auth/login"
    last_error = None

    for attempt in range(1, _COLD_START_RETRIES + 1):
        try:
            response = httpx.post(url, json=payload, timeout=15.0)
        except httpx.RequestError as e:
            last_error = ConnectionError(f"Unable to reach the target API at {url}: {e}")
            time.sleep(_COLD_START_DELAY_SECONDS)
            continue

        if response.status_code == 200:
            token = response.json().get("token")
            if token:
                token_store.set_token(role, token)
                return token
            raise ValueError("Authentication succeeded, but 'token' was missing in response body.")

        if response.status_code in (502, 503, 504) and attempt < _COLD_START_RETRIES:
            # Likely a cold start — wait and retry rather than failing immediately.
            time.sleep(_COLD_START_DELAY_SECONDS)
            last_error = Exception(
                f"Target API returned {response.status_code} on attempt {attempt}/{_COLD_START_RETRIES} "
                f"(retrying, this usually means the target is still waking up): "
                f"{_summarize_error_body(response.text, response.headers.get('content-type', ''))}"
            )
            continue

        raise Exception(
            f"Target API authentication rejected with status {response.status_code}: "
            f"{_summarize_error_body(response.text, response.headers.get('content-type', ''))}"
        )

    raise last_error


def get_token(role: str) -> str:
    """Gets token from cache, or logins if it does not exist."""
    token = token_store.get_token(role)
    if not token:
        token = login_user(role)
    return token


def clear_tokens():
    """Clears cached tokens in token store."""
    token_store.clear_tokens()
