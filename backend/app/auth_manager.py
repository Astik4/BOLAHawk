import json
import httpx
from app import config
from app import token_store

def _load_credentials():
    """Loads configured test credentials from JSON."""
    try:
        with open(config.USERS_CONFIG_PATH, 'r') as f:
            data = json.load(f)
            return data.get("users", [])
    except FileNotFoundError:
        raise FileNotFoundError(f"Test users config not found at path: {config.USERS_CONFIG_PATH}")

def login_user(role: str) -> str:
    """Performs HTTP login against the target API and caches the token."""
    users = _load_credentials()
    user_cred = next((u for u in users if u.get("role") == role), None)
    if not user_cred:
        raise ValueError(f"Credentials for role '{role}' not configured in test_users.json")
    
    payload = {
        "username": user_cred["username"],
        "password": user_cred["password"]
    }
    
    url = f"{config.TARGET_API_URL}/api/auth/login"
    try:
        # Use sync HTTPX client to perform standard auth call
        response = httpx.post(url, json=payload, timeout=5.0)
        if response.status_code == 200:
            token = response.json().get("token")
            if token:
                token_store.set_token(role, token)
                return token
            else:
                raise ValueError("Authentication succeeded, but 'token' was missing in response body.")
        else:
            raise Exception(f"Target API authentication rejected with status {response.status_code}: {response.text}")
    except httpx.RequestError as e:
        raise ConnectionError(f"Unable to reach the target API at {url}. Error: {e}")

def get_token(role: str) -> str:
    """Gets token from cache, or logins if it does not exist."""
    token = token_store.get_token(role)
    if not token:
        token = login_user(role)
    return token

def clear_tokens():
    """Clears cached tokens in token store."""
    token_store.clear_tokens()
