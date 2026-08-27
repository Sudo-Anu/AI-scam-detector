"""
AI Scam Detector Backend — Input Router (Orchestrator)
======================================================
backend/core/input_router.py

Acts as the central orchestration and dispatching layer between the
raw API endpoint payloads and the specialised scanning engines.

Responsibilities:
    - Determine the payload type (url | email | text | image).
    - Dispatch to the correct scanning engine.
    - Aggregate and normalise raw scanner results.
    - Catch all scanner-level exceptions and return a standardised
      error payload without crashing the API layer.
"""

import logging
import traceback
from typing import Any

from backend.scanners.url_scanner   import scan_url
from backend.scanners.email_scanner import scan_email
from backend.scanners.text_scanner  import scan_text
from backend.scanners.image_scanner import scan_image


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


# ---------------------------------------------------------------------------
# Supported payload types
# ---------------------------------------------------------------------------
SUPPORTED_PAYLOAD_TYPES: frozenset[str] = frozenset(
    {"url", "email", "text", "image"}
)


# ---------------------------------------------------------------------------
# Standardised result helpers
# ---------------------------------------------------------------------------
def _success_payload(
    payload_type: str,
    result: Any,
) -> dict[str, Any]:
    """
    Wraps a successful scanner result in a normalised envelope.

    Args:
        payload_type: The type of payload that was scanned.
        result:       The raw result returned by the scanning engine.

    Returns:
        A JSON-serialisable dict with status, payload_type, and data.
    """
    return {
        "status": "success",
        "payload_type": payload_type,
        "data": result,
        "error": None,
    }


def _error_payload(
    payload_type: str,
    exception: Exception,
    tb: str,
) -> dict[str, Any]:
    """
    Builds a standardised error envelope when a scanner raises an exception.

    Args:
        payload_type: The type of payload that was being scanned.
        exception:    The caught exception instance.
        tb:           Full formatted traceback string for diagnostics.

    Returns:
        A JSON-serialisable dict with status, error details, and traceback.
    """
    return {
        "status": "error",
        "payload_type": payload_type,
        "data": None,
        "error": {
            "type": type(exception).__name__,
            "message": str(exception),
            "traceback": tb,
        },
    }


# ---------------------------------------------------------------------------
# InputRouter orchestrator class
# ---------------------------------------------------------------------------
class InputRouter:
    """
    Central orchestrator that routes scan payloads to the appropriate
    specialised scanning engine and returns normalised results.

    Usage:
        router = InputRouter()
        result = await router.route_scan(payload_type="url", payload="https://…")
    """

    # Map each supported payload type to its corresponding scanning engine.
    # Each engine callable must accept (payload, *args, **kwargs) and return
    # a JSON-serialisable dict of raw scan results.
    _SCANNER_REGISTRY: dict[str, Any] = {
        "url":   scan_url,
        "email": scan_email,
        "text":  scan_text,
        "image": scan_image,
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def route_scan(
        self,
        payload_type: str,
        payload: Any,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Validate the payload type, dispatch to the correct scanner, and
        return a normalised result envelope.

        Args:
            payload_type: One of "url" | "email" | "text" | "image".
            payload:      The raw submission to be scanned.
                          - "url"   → str (the suspicious URL)
                          - "email" → bytes | str | PathLike (raw .eml data)
                          - "text"  → str (free-form text or SMS body)
                          - "image" → bytes | PathLike (image file content)
            *args:        Forwarded verbatim to the scanning engine.
            **kwargs:     Forwarded verbatim to the scanning engine.

        Returns:
            A JSON-serialisable dict conforming to the standardised result
            envelope (see _success_payload / _error_payload).

        Raises:
            This method is intentionally exception-safe; it will never
            propagate scanner exceptions to the caller.
        """
        normalised_type = payload_type.strip().lower()

        # ── Guard: unsupported payload type ──────────────────────────────
        if normalised_type not in SUPPORTED_PAYLOAD_TYPES:
            logger.warning(
                "Unsupported payload_type received: '%s'. "
                "Supported types: %s",
                payload_type,
                sorted(SUPPORTED_PAYLOAD_TYPES),
            )
            return {
                "status": "error",
                "payload_type": payload_type,
                "data": None,
                "error": {
                    "type": "UnsupportedPayloadType",
                    "message": (
                        f"'{payload_type}' is not a recognised payload type. "
                        f"Accepted values: {sorted(SUPPORTED_PAYLOAD_TYPES)}."
                    ),
                    "traceback": None,
                },
            }

        scanner = self._SCANNER_REGISTRY[normalised_type]

        logger.info(
            "Dispatching scan → payload_type='%s'  scanner='%s'",
            normalised_type,
            getattr(scanner, "__name__", repr(scanner)),
        )

        # ── Dispatch ─────────────────────────────────────────────────────
        try:
            raw_result = await self._invoke_scanner(
                scanner=scanner,
                payload=payload,
                *args,
                **kwargs,
            )

            logger.info(
                "Scan completed successfully → payload_type='%s'",
                normalised_type,
            )
            return _success_payload(
                payload_type=normalised_type,
                result=raw_result,
            )

        except Exception as exc:  # noqa: BLE001  (intentionally broad)
            tb_str = traceback.format_exc()
            logger.error(
                "Scanner failure for payload_type='%s': %s\n%s",
                normalised_type,
                exc,
                tb_str,
            )
            return _error_payload(
                payload_type=normalised_type,
                exception=exc,
                tb=tb_str,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _invoke_scanner(
        self,
        scanner: Any,
        payload: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Invoke a scanning engine in a coroutine-safe manner.

        Supports both async and sync scanner callables — sync scanners are
        awaited via asyncio to avoid blocking the event loop.

        Args:
            scanner: The scanning engine callable.
            payload: The raw payload to pass to the scanner.
            *args:   Additional positional arguments for the scanner.
            **kwargs: Additional keyword arguments for the scanner.

        Returns:
            The raw result from the scanner.

        Raises:
            Re-raises any exception from the scanner so that route_scan
            can catch and normalise it into an error payload.
        """
        import asyncio
        import inspect

        if inspect.iscoroutinefunction(scanner):
            # Async scanner — await directly.
            return await scanner(payload, *args, **kwargs)

        # Sync scanner — run in the default thread-pool executor so we
        # do not block the asyncio event loop.
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: scanner(payload, *args, **kwargs),
        )


# ---------------------------------------------------------------------------
# Module-level singleton for convenient import
# ---------------------------------------------------------------------------
input_router = InputRouter()