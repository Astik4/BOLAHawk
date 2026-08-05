import asyncio
import time
import httpx
from typing import Dict, Any, Optional

# Free-tier hosts (Render, Railway free plans, etc.) spin down the target API
# after inactivity and can take 30-60s to cold-start on the next request,
# often returning a 502/503/504 with the host's own HTML gateway page while
# the container boots (or a raw connection error if the port isn't even
# listening yet). Every scan-time HTTP call goes through here, so retrying
# with backoff at this single choke point rides that out for the whole scan
# (reseed, auth, discovery, probes, matrix, active checks) instead of only
# the login step.
_COLD_START_RETRIES = 6
_COLD_START_DELAY_SECONDS = 10
_COLD_START_STATUS_CODES = {502, 503, 504}


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
    timeout: float = 25.0,
    retry_cold_start: bool = True,
) -> Dict[str, Any]:
    """
    Fires an async HTTP request and returns performance metrics, status codes, and body details.
    Timeout defaults to 25s since free-tier hosts (Render, etc.) can take several
    seconds to respond even once awake, and much longer on a cold start.

    When retry_cold_start is True (the default), connection errors and
    502/503/504 responses are retried with a fixed backoff before giving up —
    covering up to roughly (_COLD_START_RETRIES - 1) * _COLD_START_DELAY_SECONDS
    of sleep plus _COLD_START_RETRIES * timeout of request time in the worst
    case, which comfortably outlasts a typical free-tier cold start. Once the
    host is warm, this adds zero overhead since the first attempt succeeds.
    """
    if headers is None:
        headers = {}

    attempts = _COLD_START_RETRIES if retry_cold_start else 1
    start_time = time.time()
    response_status = 0
    response_body = ""
    response_headers = {}
    error_message = None

    for attempt in range(1, attempts + 1):
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

        cold_start_status = response_status in _COLD_START_STATUS_CODES
        cold_start_error = response_status == 599
        if (cold_start_status or cold_start_error) and attempt < attempts:
            await asyncio.sleep(_COLD_START_DELAY_SECONDS)
            continue
        break

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
