"""
AI Scam Detector Backend — Core Application Entry Point
=======================================================
Initializes the FastAPI application, configures CORS middleware,
sets up required directory structures via lifespan events, registers
API routers, and exposes a health-check endpoint.
"""

import os
import time
import uvicorn
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Load environment variables from .env at project root (if present).
# This ensures API keys (GEMINI_API_KEY, VIRUSTOTAL_API_KEY, GOOGLE_API_KEY)
# are available regardless of how the server is started (start.bat or direct).
# ---------------------------------------------------------------------------
_project_root = Path(__file__).resolve().parent.parent  # AI-Scam detector/
_env_path = _project_root / ".env"
if _env_path.is_file():
    load_dotenv(_env_path, override=False)
    print(f"[dotenv] Loaded environment from {_env_path}")
else:
    print(f"[dotenv] No .env file found at {_env_path} — relying on system env vars.")

from backend.api.endpoints import router


# ---------------------------------------------------------------------------
# Directory structure required at startup
# ---------------------------------------------------------------------------
REQUIRED_DIRECTORIES: list[str] = [
    "backend/storage/uploads/images",
    "backend/storage/uploads/emails",
    "backend/storage/uploads/documents",
    "backend/storage/reports/pdf",
    "backend/storage/reports/json",
    "backend/storage/prompts",
]


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI lifespan event handler.

    Startup:
        Inspects and creates required local directory structures so that
        file-based operations (uploads, reports, prompts) never fail due
        to missing paths.

    Shutdown:
        Placeholder for any graceful-shutdown logic (e.g. closing DB
        connections, flushing caches).
    """
    # ── Startup ──────────────────────────────────────────────────────────
    print("[lifespan] Starting AI Scam Detector Backend …")

    for directory in REQUIRED_DIRECTORIES:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"[lifespan] Created directory: {directory}")
        else:
            print(f"[lifespan] Directory already exists: {directory}")

    print("[lifespan] Directory structure verified. Server is ready.")

    yield  # ← application runs here

    # ── Shutdown ─────────────────────────────────────────────────────────
    print("[lifespan] Shutting down AI Scam Detector Backend …")


# ---------------------------------------------------------------------------
# FastAPI application instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI Scam Detector Backend",
    version="1.0.0",
    description=(
        "A high-performance backend API that accepts HTTP requests from a "
        "React/Vite frontend, routes submissions (URLs, emails, text, and "
        "images) through specialised AI-powered scanning engines, and "
        "compiles structured scam-detection reports."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS: list[str] = [
    "http://localhost:5173",    # Vite dev server (localhost)
    "http://127.0.0.1:5173",   # Vite dev server (loopback IP)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],        # GET, POST, OPTIONS, PUT, DELETE, PATCH …
    allow_headers=["*"],        # Content-Type, Authorization, X-* …
)


# ---------------------------------------------------------------------------
# Health-check endpoint
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    summary="Health Check",
    description="Returns a 200 OK response confirming the API is operational.",
    tags=["System"],
    response_class=JSONResponse,
)
async def health_check() -> JSONResponse:
    """
    Lightweight liveness probe.

    Returns:
        200 OK with a JSON payload containing status, service name,
        API version, and the current server timestamp (UTC epoch).
    """
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "message": "AI Scam Detector API is operational.",
            "service": "AI Scam Detector Backend",
            "version": app.version,
            "timestamp": time.time(),
        },
    )


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------
# Mounts all scam-scanning endpoints defined in backend/api/endpoints.py:
#   POST /scan/url       — Scan a URL for phishing / malicious indicators
#   POST /scan/email     — Scan an email for scam patterns
#   POST /scan/text      — Scan free-form text for scam signals
#   POST /scan/image     — Scan an uploaded image for scam content
app.include_router(router)


# ---------------------------------------------------------------------------
# Development entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )