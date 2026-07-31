import time
import httpx
from typing import Dict, Any, Optional

async def send_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    json_data: Optional[Any] = None,
    timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Fires an async HTTP request and returns performance metrics, status codes, and body details.
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
            response_body = response.text
            
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
