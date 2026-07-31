# In-memory token store for caching JWTs associated with different test roles

_store = {}

def set_token(role: str, token: str):
    """Saves a token for a given role in memory."""
    _store[role] = token

def get_token(role: str) -> str:
    """Retrieves a token for a given role, returning None if not found."""
    return _store.get(role)

def clear_tokens():
    """Wipes all cached tokens."""
    global _store
    _store = {}
