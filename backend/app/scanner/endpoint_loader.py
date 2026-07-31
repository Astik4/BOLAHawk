import os
import json

def load_endpoints() -> list:
    """Loads and returns the endpoints list configured in endpoints.json."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "endpoints.json")
    try:
        with open(config_path, 'r') as f:
            data = json.load(f)
            return data.get("endpoints", [])
    except FileNotFoundError:
        # Default fallback list if configuration is missing
        return []
