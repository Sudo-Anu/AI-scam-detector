"""
AI Scam Detector Backend — API Endpoints
=========================================
backend/api/endpoints.py

Defines all four scanning endpoints and the report retrieval endpoint.
Coordinates the multi-stage pipeline:
  1. Input Router  → scans the payload
  2. Evidence      → normalises raw findings
  3. Risk Engine   → computes risk score
  4. Gemini Client → generates AI explanation
  5. Generator     → compiles PDF and JSON reports
"""

import os
import uuid
import shutil
import logging
import traceback

# pyrefly: ignore [missing-import]
from fastapi import APIRouter, UploadFile, File, HTTPException
# pyrefly: ignore [missing-import]
from fastapi.responses import FileResponse

# Pydantic Schemas — single source of truth
from backend.models.schemas import (
    URLScanRequest,
    TextScanRequest,
    RiskEvaluation,
    AIExplanation,
    ScanResponse,
    StandardizedEvidence,
)

# Core Pipeline Services — import specific callables to avoid name-collision ambiguity
from backend.core.input_router   import input_router as scan_router  # InputRouter singleton
from backend.core.evidence       import normalize    as normalize_evidence
from backend.core.risk_engine    import evaluate     as evaluate_risk
from backend.integrations.gemini_client import generate_safety_report
from backend.reporting.generator import generate_reports

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
router = APIRouter()

# ---------------------------------------------------------------------------
# Storage Directories
# ---------------------------------------------------------------------------
UPLOAD_DIR_EMAILS = os.path.join("backend", "storage", "uploads", "emails")
UPLOAD_DIR_IMAGES = os.path.join("backend", "storage", "uploads", "images")
REPORT_DIR_PDF    = os.path.join("backend", "storage", "reports", "pdf")
REPORT_DIR_JSON   = os.path.join("backend", "storage", "reports", "json")

for path in [UPLOAD_DIR_EMAILS, UPLOAD_DIR_IMAGES, REPORT_DIR_PDF, REPORT_DIR_JSON]:
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Pipeline Coordinator
# ---------------------------------------------------------------------------
async def coordinate_pipeline(
    input_payload: str,
    payload_type: str,
    scan_id: str,
) -> ScanResponse:
    """
    Coordinates the multi-stage threat scanning, evaluation, and report
    generation pipeline.

    Args:
        input_payload: The raw value to scan (URL string, file path, or text).
        payload_type:  One of "url" | "email" | "text" | "image".
        scan_id:       UUID string for this scan request.

    Returns:
        A fully populated ScanResponse.
    """
    try:
        # ── Stage 1: Execute Scanning Engine ─────────────────────────────
        # scan_router is the InputRouter singleton imported directly.
        router_result = await scan_router.route_scan(
            payload_type=payload_type,
            payload=input_payload,
        )

        if router_result.get("status") == "error":
            logger.warning(
                "Scanner reported an error for payload_type='%s': %s",
                payload_type,
                router_result.get("error"),
            )

        # ── Stage 2: Normalise Evidence ───────────────────────────────────
        normalized_evidence: StandardizedEvidence = normalize_evidence(router_result)

        # ── Stage 3: Evaluate Risk ────────────────────────────────────────
        risk_eval: RiskEvaluation = evaluate_risk(normalized_evidence)

        # ── Stage 4: Generate AI Explanation ─────────────────────────────
        evidence_dict = normalized_evidence.model_dump()
        ai_report_dict = generate_safety_report(
            input_type=payload_type,
            risk_score=risk_eval.risk_score,
            risk_level=risk_eval.risk_level,
            evidence=evidence_dict,
        )
        ai_explanation = AIExplanation(**ai_report_dict)

        # ── Stage 5: Compile & Archive Reports ───────────────────────────
        report_urls = generate_reports(
            scan_data={
                "input":   str(input_payload)[:500],
                "type":    payload_type,
                "scan_id": scan_id,
            },
            evidence=evidence_dict,
            evaluation=risk_eval.model_dump(),
            ai_explanation=ai_report_dict,
        )

        # ── Stage 6: Serve Unified Response ──────────────────────────────
        return ScanResponse(
            scan_id=scan_id,
            input_type=payload_type,
            evaluation=risk_eval,
            evidence=normalized_evidence,
            ai_explanation=ai_explanation,
            report_urls=report_urls,
        )

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline processing failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# Scan Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan/url", response_model=ScanResponse, tags=["Scanning"])
async def scan_url(request: URLScanRequest):
    """Scan a URL for phishing, malware, and scam indicators."""
    scan_id = str(uuid.uuid4())
    return await coordinate_pipeline(request.url, "url", scan_id)


@router.post("/scan/text", response_model=ScanResponse, tags=["Scanning"])
async def scan_text(request: TextScanRequest):
    """Scan free-form text or an SMS message for scam signals."""
    scan_id = str(uuid.uuid4())
    return await coordinate_pipeline(request.text, "text", scan_id)


@router.post("/scan/email", response_model=ScanResponse, tags=["Scanning"])
async def scan_email(file: UploadFile = File(...)):
    """
    Accept an .eml file upload, process it via the email scanning engine,
    and clean up the temporary file afterwards.
    """
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Expected an .eml file.",
        )

    scan_id = str(uuid.uuid4())
    safe_filename = f"{scan_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR_EMAILS, safe_filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        return await coordinate_pipeline(file_path, "email", scan_id)

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process email upload: {str(e)}",
        )
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as cleanup_err:
                logger.warning("Temp file cleanup failed for %s: %s", file_path, cleanup_err)


@router.post("/scan/image", response_model=ScanResponse, tags=["Scanning"])
async def scan_image(file: UploadFile = File(...)):
    """
    Accept an image file upload (PNG/JPG/JPEG/WEBP), run OCR scanning,
    and clean up the temporary file afterwards.
    """
    valid_extensions = (".png", ".jpg", ".jpeg", ".webp")
    if not any(file.filename.lower().endswith(ext) for ext in valid_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Expected one of: {valid_extensions}",
        )

    scan_id = str(uuid.uuid4())
    safe_filename = f"{scan_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR_IMAGES, safe_filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        return await coordinate_pipeline(file_path, "image", scan_id)

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process image upload: {str(e)}",
        )
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as cleanup_err:
                logger.warning("Temp file cleanup failed for %s: %s", file_path, cleanup_err)


# ---------------------------------------------------------------------------
# Report Retrieval Endpoint
# ---------------------------------------------------------------------------

@router.get("/report/{filename}", tags=["Reports"])
async def get_report(filename: str):
    """
    Retrieve and serve a generated PDF or JSON report from local storage.
    """
    if filename.lower().endswith(".pdf"):
        file_path  = os.path.join(REPORT_DIR_PDF,  filename)
        media_type = "application/pdf"
    elif filename.lower().endswith(".json"):
        file_path  = os.path.join(REPORT_DIR_JSON, filename)
        media_type = "application/json"
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid report format. Expected .pdf or .json",
        )

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found.")

    return FileResponse(path=file_path, media_type=media_type, filename=filename)