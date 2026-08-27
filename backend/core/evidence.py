"""
AI Scam Detector Backend — Evidence Collector
=============================================
backend/core/evidence.py

Normalises, categorises, and aggregates raw scanner output dictionaries
from any of the four scanning engines (URL, Email, Text, Image) into a
single, downstream-friendly StandardizedEvidence object.

The structured object is fed directly into the RiskEngine to compute
a final threat risk score.
"""

import logging
from typing import Any, Literal

# Import canonical schema classes — single source of truth
from backend.models.schemas import EvidenceItem, StandardizedEvidence

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity type alias
# ---------------------------------------------------------------------------
SeverityLevel = Literal["low", "medium", "high"]

# ---------------------------------------------------------------------------
# Supported payload types
# ---------------------------------------------------------------------------
SUPPORTED_PAYLOAD_TYPES: frozenset[str] = frozenset(
    {"url", "email", "text", "image"}
)


# ===========================================================================
# EvidenceCollector
# ===========================================================================
class EvidenceCollector:
    """
    Processes raw scanner output dictionaries and maps them to structured
    StandardizedEvidence objects.

    Each ``collect_from_*`` method understands the exact nested structure
    returned by its corresponding scanner and safely extracts values using
    .get() with defaults to handle partial scanner failures.

    Usage:
        evidence = EvidenceCollector.collect_from_url(raw_data)
        # — or via the unified dispatcher —
        evidence = normalize(router_result)
    """

    # ------------------------------------------------------------------
    # URL Scanner → StandardizedEvidence
    # Understands output of scanners/url_scanner.py::scan_url()
    # Structure: {url, domain, whois:{domain_age_days, registrar}, ssl:{is_valid},
    #             threat_intelligence:{virustotal_detections, google_safe_browsing_flagged},
    #             heuristics:{suspicious_tld_detected, impersonation_keywords_found}}
    # ------------------------------------------------------------------
    @staticmethod
    def collect_from_url(raw_data: dict[str, Any]) -> StandardizedEvidence:
        logger.info("[EvidenceCollector] Processing URL scanner output …")

        # ── Technical Indicators ─────────────────────────────────────────
        technical: list[EvidenceItem] = []

        ssl_info: dict = raw_data.get("ssl") or {}
        ssl_valid: bool = ssl_info.get("is_valid", False)
        technical.append(
            EvidenceItem(
                name="ssl_valid",
                value=ssl_valid,
                description="SSL/TLS certificate validity status.",
                severity="high" if not ssl_valid else "low",
            )
        )

        whois_info: dict = raw_data.get("whois") or {}
        domain_age: int | None = whois_info.get("domain_age_days")
        if domain_age is not None:
            technical.append(
                EvidenceItem(
                    name="domain_age_days",
                    value=domain_age,
                    description=f"Age of the registered domain: {domain_age} day(s).",
                    severity=(
                        "high"   if domain_age < 30  else
                        "medium" if domain_age < 180 else
                        "low"
                    ),
                )
            )

        registrar: str | None = whois_info.get("registrar")
        if registrar:
            technical.append(
                EvidenceItem(
                    name="registrar",
                    value=registrar,
                    description=f"Domain registrar: {registrar}.",
                    severity="low",
                )
            )

        # ── Threat Intelligence ──────────────────────────────────────────
        threat_intel: list[EvidenceItem] = []

        ti: dict = raw_data.get("threat_intelligence") or {}
        vt_detections: int = ti.get("virustotal_detections", 0)
        threat_intel.append(
            EvidenceItem(
                name="virustotal_positives",
                value=vt_detections,
                description=(
                    f"VirusTotal engine detections: {vt_detections}."
                ),
                severity=(
                    "high"   if vt_detections >= 5 else
                    "medium" if vt_detections >= 1 else
                    "low"
                ),
            )
        )

        gsb_flagged: bool = ti.get("google_safe_browsing_flagged", False)
        threat_intel.append(
            EvidenceItem(
                name="gsb_unsafe",
                value=gsb_flagged,
                description=(
                    "Google Safe Browsing flagged this URL as unsafe."
                    if gsb_flagged else
                    "Not flagged by Google Safe Browsing."
                ),
                severity="high" if gsb_flagged else "low",
            )
        )

        # ── Heuristic Matches ────────────────────────────────────────────
        heuristics: list[EvidenceItem] = []

        heur: dict = raw_data.get("heuristics") or {}
        suspicious_tld: bool = heur.get("suspicious_tld_detected", False)
        if suspicious_tld:
            heuristics.append(
                EvidenceItem(
                    name="suspicious_tld",
                    value=True,
                    description="Domain uses a suspicious/high-risk TLD.",
                    severity="medium",
                )
            )

        keywords: list = heur.get("impersonation_keywords_found", [])
        if keywords:
            heuristics.append(
                EvidenceItem(
                    name="url_keyword_detections",
                    value=keywords,
                    description=(
                        f"{len(keywords)} brand impersonation keyword(s) found in URL."
                    ),
                    severity=(
                        "high"   if len(keywords) >= 3 else
                        "medium" if len(keywords) >= 1 else
                        "low"
                    ),
                )
            )

        is_ip: bool = heur.get("is_ip_address", False)
        if is_ip:
            heuristics.append(
                EvidenceItem(
                    name="is_ip_address",
                    value=True,
                    description="URL uses a raw IP address instead of a domain name.",
                    severity="high",
                )
            )

        is_tracker: bool = heur.get("is_tracker_or_shortener", False)
        if is_tracker:
            heuristics.append(
                EvidenceItem(
                    name="is_tracker_or_shortener",
                    value=True,
                    description="URL uses a known link shortener or IP tracking service.",
                    severity="high",
                )
            )

        return StandardizedEvidence(
            payload_type="url",
            technical_indicators=technical,
            threat_intelligence=threat_intel,
            heuristic_matches=heuristics,
        )

    # ------------------------------------------------------------------
    # Email Scanner → StandardizedEvidence
    # Understands output of scanners/email_scanner.py::scan_email()
    # Structure: {sender, sender_display_name, subject, headers:{from,to,reply_to,date},
    #             extracted_links, heuristics:{from_reply_mismatch, is_spf_aligned,
    #             is_dkim_valid, suspicious_keywords_found, keyword_match_count}}
    # ------------------------------------------------------------------
    @staticmethod
    def collect_from_email(raw_data: dict[str, Any]) -> StandardizedEvidence:
        logger.info("[EvidenceCollector] Processing Email scanner output …")

        technical: list[EvidenceItem] = []
        threat_intel: list[EvidenceItem] = []
        heuristics: list[EvidenceItem] = []

        heur: dict = raw_data.get("heuristics") or {}

        is_spf: bool = heur.get("is_spf_aligned", False)
        technical.append(
            EvidenceItem(
                name="spf_pass",
                value=is_spf,
                description="SPF (Sender Policy Framework) authentication result.",
                severity="high" if not is_spf else "low",
            )
        )

        is_dkim: bool = heur.get("is_dkim_valid", False)
        technical.append(
            EvidenceItem(
                name="dkim_pass",
                value=is_dkim,
                description="DKIM (DomainKeys Identified Mail) signature validation.",
                severity="high" if not is_dkim else "low",
            )
        )

        sender: str | None = raw_data.get("sender")
        if sender:
            technical.append(
                EvidenceItem(
                    name="sender_address",
                    value=sender,
                    description=f"Email sender address: {sender}.",
                    severity="low",
                )
            )

        from_reply_mismatch: bool = heur.get("from_reply_mismatch", False)
        if from_reply_mismatch:
            headers: dict = raw_data.get("headers") or {}
            technical.append(
                EvidenceItem(
                    name="reply_to_mismatch",
                    value={"from": headers.get("from", ""), "reply_to": headers.get("reply_to", "")},
                    description=(
                        "Reply-To address differs from the sender address — "
                        "a common indicator of phishing or spoofing."
                    ),
                    severity="high",
                )
            )

        links: list = raw_data.get("extracted_links", [])
        if links:
            threat_intel.append(
                EvidenceItem(
                    name="embedded_links",
                    value=links,
                    description=(
                        f"{len(links)} hyperlink(s) extracted from the email body."
                    ),
                    severity=(
                        "high"   if len(links) > 10 else
                        "medium" if len(links) >= 1 else
                        "low"
                    ),
                )
            )

        flag_keywords: list = heur.get("suspicious_keywords_found", [])
        if flag_keywords:
            heuristics.append(
                EvidenceItem(
                    name="email_flag_keywords",
                    value=flag_keywords,
                    description=(
                        f"{len(flag_keywords)} scam-trigger keyword(s) detected "
                        "in the email subject or body."
                    ),
                    severity=(
                        "high"   if len(flag_keywords) >= 5 else
                        "medium" if len(flag_keywords) >= 2 else
                        "low"
                    ),
                )
            )

        return StandardizedEvidence(
            payload_type="email",
            technical_indicators=technical,
            threat_intelligence=threat_intel,
            heuristic_matches=heuristics,
        )

    # ------------------------------------------------------------------
    # Text Scanner → StandardizedEvidence
    # Understands output of scanners/text_scanner.py::scan_text()
    # Structure: {text, keywords:{detected_keywords, keyword_count},
    #             patterns:{crypto_wallets_found, phone_numbers_found,
    #             shortened_urls_found, sensitive_numbers_found},
    #             heuristics:{urgency_detected, urgency_score, shouting_detected,
    #             financial_scam_detected}}
    # ------------------------------------------------------------------
    @staticmethod
    def collect_from_text(raw_data: dict[str, Any]) -> StandardizedEvidence:
        logger.info("[EvidenceCollector] Processing Text scanner output …")

        technical: list[EvidenceItem] = []
        threat_intel: list[EvidenceItem] = []
        heuristics: list[EvidenceItem] = []

        heur: dict = raw_data.get("heuristics") or {}
        patterns: dict = raw_data.get("patterns") or {}
        keywords_info: dict = raw_data.get("keywords") or {}

        keyword_count: int = keywords_info.get("keyword_count", 0)
        detected_kw: list = keywords_info.get("detected_keywords", [])

        if keyword_count:
            technical.append(
                EvidenceItem(
                    name="spam_keyword_count",
                    value=keyword_count,
                    description=f"{keyword_count} suspicious keyword(s) detected in text.",
                    severity=(
                        "high"   if keyword_count >= 10 else
                        "medium" if keyword_count >= 4  else
                        "low"
                    ),
                )
            )

        crypto: list = patterns.get("crypto_wallets_found", [])
        if crypto:
            threat_intel.append(
                EvidenceItem(
                    name="crypto_wallet_matches",
                    value=crypto,
                    description=(
                        f"{len(crypto)} cryptocurrency wallet address(es) found — "
                        "a strong indicator of investment or advance-fee scams."
                    ),
                    severity="high",
                )
            )

        phones: list = patterns.get("phone_numbers_found", [])
        if phones:
            threat_intel.append(
                EvidenceItem(
                    name="phone_number_matches",
                    value=phones,
                    description=(
                        f"{len(phones)} phone number(s) extracted — "
                        "may indicate callback or social engineering scams."
                    ),
                    severity="medium",
                )
            )

        sensitive: list = patterns.get("sensitive_numbers_found", [])
        if sensitive:
            threat_intel.append(
                EvidenceItem(
                    name="sensitive_numbers",
                    value=sensitive,
                    description=(
                        f"{len(sensitive)} sensitive number(s) (e.g., CC/OTP) found."
                    ),
                    severity="high",
                )
            )

        urgency_detected: bool = heur.get("urgency_detected", False)
        urgency_score: int = heur.get("urgency_score", 0)
        if urgency_detected:
            heuristics.append(
                EvidenceItem(
                    name="urgency_flags",
                    value=urgency_score,
                    description=(
                        f"Urgency/pressure language detected (score: {urgency_score}). "
                        "Creates artificial time pressure to override critical thinking."
                    ),
                    severity="high" if urgency_score >= 3 else "medium",
                )
            )

        financial: bool = heur.get("financial_scam_detected", False)
        if financial:
            heuristics.append(
                EvidenceItem(
                    name="payment_triggers",
                    value=detected_kw,
                    description=(
                        f"Financial scam keywords detected ({len(detected_kw)} match(es)). "
                        "Indicative of financial fraud or advance-fee scams."
                    ),
                    severity="high" if len(detected_kw) >= 3 else "medium",
                )
            )

        shouting: bool = heur.get("shouting_detected", False)
        if shouting:
            heuristics.append(
                EvidenceItem(
                    name="shouting_detected",
                    value=True,
                    description="Excessive use of uppercase letters (shouting) detected.",
                    severity="low",
                )
            )

        shortened_urls: list = patterns.get("shortened_urls_found", [])
        if shortened_urls:
            heuristics.append(
                EvidenceItem(
                    name="shortened_urls",
                    value=shortened_urls,
                    description=(
                        f"{len(shortened_urls)} shortened URL(s) found — "
                        "common in smishing and phishing attacks."
                    ),
                    severity="medium",
                )
            )

        return StandardizedEvidence(
            payload_type="text",
            technical_indicators=technical,
            threat_intelligence=threat_intel,
            heuristic_matches=heuristics,
        )

    # ------------------------------------------------------------------
    # Image Scanner → StandardizedEvidence
    # Understands output of scanners/image_scanner.py::scan_image()
    # Structure: {file_metadata:{format,width,height,file_size_kb},
    #             extracted_text, keywords:{detected_keywords, keyword_count},
    #             patterns:{phone_numbers_found, urls_found},
    #             heuristics:{urgency_detected, suspicious_image_flag, classification}}
    # ------------------------------------------------------------------
    @staticmethod
    def collect_from_image(raw_data: dict[str, Any]) -> StandardizedEvidence:
        logger.info("[EvidenceCollector] Processing Image scanner output …")

        technical: list[EvidenceItem] = []
        threat_intel: list[EvidenceItem] = []
        heuristics: list[EvidenceItem] = []

        meta: dict = raw_data.get("file_metadata") or {}
        keywords_info: dict = raw_data.get("keywords") or {}
        patterns: dict = raw_data.get("patterns") or {}
        heur: dict = raw_data.get("heuristics") or {}

        fmt: str = meta.get("format", "UNKNOWN")
        technical.append(
            EvidenceItem(
                name="image_format",
                value=fmt,
                description=f"Detected image file format: {fmt}.",
                severity="low",
            )
        )

        ocr_text: str = raw_data.get("extracted_text", "")
        if ocr_text:
            technical.append(
                EvidenceItem(
                    name="ocr_text",
                    value=ocr_text[:500],
                    description="Text extracted from the image via OCR (truncated to 500 chars).",
                    severity="low",
                )
            )

        keyword_count: int = keywords_info.get("keyword_count", 0)
        detected_kw: list = keywords_info.get("detected_keywords", [])
        if keyword_count:
            heuristics.append(
                EvidenceItem(
                    name="ocr_keyword_matches",
                    value=detected_kw,
                    description=(
                        f"{keyword_count} suspicious keyword(s) detected in OCR-extracted text."
                    ),
                    severity=(
                        "high"   if keyword_count >= 3 else
                        "medium" if keyword_count >= 1 else
                        "low"
                    ),
                )
            )

        urgency: bool = heur.get("urgency_detected", False)
        if urgency:
            heuristics.append(
                EvidenceItem(
                    name="urgency_flags",
                    value=True,
                    description="Urgency keywords detected in image text content.",
                    severity="high",
                )
            )

        suspicious: bool = heur.get("suspicious_image_flag", False)
        if suspicious:
            classification: str = heur.get("classification", "Unknown")
            heuristics.append(
                EvidenceItem(
                    name="suspicious_image_flag",
                    value=True,
                    description=f"Image classified as suspicious: {classification}.",
                    severity="high",
                )
            )

        phones: list = patterns.get("phone_numbers_found", [])
        if phones:
            threat_intel.append(
                EvidenceItem(
                    name="phone_number_matches",
                    value=phones,
                    description=f"{len(phones)} phone number(s) extracted from image.",
                    severity="medium",
                )
            )

        urls: list = patterns.get("urls_found", [])
        if urls:
            threat_intel.append(
                EvidenceItem(
                    name="embedded_links",
                    value=urls,
                    description=f"{len(urls)} URL(s) found in image content.",
                    severity="medium",
                )
            )

        return StandardizedEvidence(
            payload_type="image",
            technical_indicators=technical,
            threat_intelligence=threat_intel,
            heuristic_matches=heuristics,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_collector = EvidenceCollector()


# ---------------------------------------------------------------------------
# Public dispatch function (Bug 3 fix: adds the normalize() function that
# endpoints.py calls, dispatching to the correct collect_from_* method)
# ---------------------------------------------------------------------------
def normalize(router_result: dict[str, Any]) -> StandardizedEvidence:
    """
    Dispatches the raw scanner result envelope from InputRouter to the correct
    EvidenceCollector method based on payload_type.

    Args:
        router_result: The dict returned by InputRouter.route_scan(), containing
                       keys: status, payload_type, data, error.

    Returns:
        A populated StandardizedEvidence instance. Returns an empty
        StandardizedEvidence on unsupported types or missing data.
    """
    payload_type: str = router_result.get("payload_type", "").lower()
    raw_data: dict = router_result.get("data") or {}

    dispatch: dict[str, Any] = {
        "url":   EvidenceCollector.collect_from_url,
        "email": EvidenceCollector.collect_from_email,
        "text":  EvidenceCollector.collect_from_text,
        "image": EvidenceCollector.collect_from_image,
    }

    collector_fn = dispatch.get(payload_type)
    if collector_fn is None:
        logger.warning("[normalize] Unknown payload_type '%s'. Returning empty evidence.", payload_type)
        return StandardizedEvidence(payload_type=payload_type)

    try:
        return collector_fn(raw_data)
    except Exception as exc:
        logger.error("[normalize] EvidenceCollector failed for '%s': %s", payload_type, exc, exc_info=True)
        return StandardizedEvidence(payload_type=payload_type)