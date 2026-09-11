"""How the gateway talks to the extraction capability.

Same pattern as the scan client, for the same reason: one contract, two
transports, and the caller never needs to know which one it got.

* **in-process** (default) - the gateway runs extraction itself. Local development
  and small deployments keep working with one container and no orchestration.
* **over HTTP** - when `AEGIS_EXTRACTION_SERVICE_URL` is set, extraction runs in
  its own container, so a language server that crashes or leaks memory cannot take
  the API down with it, and the two can be scaled independently.
"""

from __future__ import annotations

import os
from typing import Any

from aegis_core.logging import get_logger

log = get_logger(__name__)

ENV_EXTRACTION_SERVICE_URL = "AEGIS_EXTRACTION_SERVICE_URL"


class ExtractionUnavailable(RuntimeError):
    """The extraction service could not be reached, or refused the request."""


def extraction_service_url() -> str | None:
    url = os.getenv(ENV_EXTRACTION_SERVICE_URL, "").strip()
    return url.rstrip("/") or None


def extraction_is_remote() -> bool:
    return extraction_service_url() is not None


def request_extraction(
    payload: dict[str, Any],
    *,
    timeout_s: float = 1800.0,
) -> dict[str, Any]:
    """Ask the extraction service for a bundle. Raises if it cannot be produced."""
    url = extraction_service_url()
    if url is None:
        raise ExtractionUnavailable("no extraction service configured")

    import httpx

    log.info("delegating extraction to %s", url)
    try:
        response = httpx.post(f"{url}/v1/extract", json=payload, timeout=timeout_s)
    except Exception as exc:
        raise ExtractionUnavailable(f"extraction service at {url} unreachable: {exc}") from exc

    if response.status_code >= 400:
        detail: Any
        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text
        raise ExtractionUnavailable(
            f"extraction service at {url} refused the request "
            f"({response.status_code}): {detail}"
        )
    return response.json()
