import time
import httpx
from typing import Dict, Any, Optional


def _summarize_non_json_body(text: str, content_type: str = "") -> str:
    """A sleeping free-tier host can return its own HTML gateway error page
    instead of the target API's JSON. Dumping that raw HTML/CSS into a
    finding's evidence is unreadable — summarize it instead."""
    stripped = text.strip()
    looks_like_html = "html" in content_type.lower() or stripped.lower().startswith(("<!doctype", "<html"))
    if looks_like_html:
        return f"(non-JSON HTML response, {len(text)} chars — likely a gateway/cold-start error page)"
    return stripped[:300] + ("…" if len(stripped) > 300 else "")


async def send_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    json_data: Optional[Any] = None,
    timeout: float = 20.0
) -> Dict[str, Any]:
    """
    Fires an async HTTP request and returns performance metrics, status codes, and body details.
    Timeout defaults to 20s (not 5s) since free-tier hosts (Render, etc.) can take
    several seconds to respond even once awake, and much longer on a cold start.
    """
    if headers is None:
        headers = {}
    
    # Track execution time
    start_time = time.time()
    response_status = 0
    response_body = ""
    response_headers = {}
    error_message = None
    
    try:
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            json=json_data,
            timeout=timeout
        )
        response_status = response.status_code
        response_headers = dict(response.headers)
        
        try:
            response_body = response.json()
        except ValueError:
            response_body = _summarize_non_json_body(response.text, response_headers.get("content-type", ""))
            
    except httpx.RequestError as exc:
        error_message = str(exc)
        response_status = 599  # Custom code for request exceptions
        
    latency = time.time() - start_time
    
    return {
        "method": method,
        "url": url,
        "status_code": response_status,
        "headers": response_headers,
        "body": response_body,
        "latency_sec": latency,
        "error": error_message
    }
