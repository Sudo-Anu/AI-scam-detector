"""
AI Scam Detector Backend — Risk Engine
=======================================
backend/core/risk_engine.py

Rule-based scoring algorithm to evaluate StandardizedEvidence and
calculate a final risk score (0-100), risk level, and list of triggered rules.
"""

import logging
from typing import Any, List

# Import canonical schema classes — single source of truth
from backend.models.schemas import EvidenceItem, StandardizedEvidence, RiskEvaluation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: find an EvidenceItem by name within a list
# ---------------------------------------------------------------------------
def _find(items: List[EvidenceItem], name: str, default: Any = None) -> Any:
    """
    Searches a list of EvidenceItem objects for a specific named item and
    returns its value. Returns `default` if no match is found.
    """
    for item in items:
        if item.name == name:
            return item.value
    return default


# ---------------------------------------------------------------------------
# RiskEngine
# ---------------------------------------------------------------------------
class RiskEngine:
    """
    Rule-based scoring algorithm to evaluate normalized evidence and calculate
    a final risk score. Handles missing evidence fields defensively to return
    a valid evaluation even under partial scanner failures.
    """

    def evaluate(self, evidence: Any) -> RiskEvaluation:
        """
        Evaluate a StandardizedEvidence object and return a RiskEvaluation.

        Args:
            evidence: A StandardizedEvidence instance (or any object with
                      technical_indicators, threat_intelligence, heuristic_matches
                      attributes that are lists of EvidenceItem objects).

        Returns:
            RiskEvaluation with score (0-100), risk_level, and triggered_rules.
        """
        score: int = 5
        triggered_rules: List[str] = ["Baseline: Inherent internet risk (+5)"]

        # Safely extract evidence lists
        tech:   List[EvidenceItem] = getattr(evidence, "technical_indicators", []) or []
        threat: List[EvidenceItem] = getattr(evidence, "threat_intelligence",  []) or []
        heur:   List[EvidenceItem] = getattr(evidence, "heuristic_matches",    []) or []

        # -----------------------------------------------------------------
        # 1. Technical Indicators
        # -----------------------------------------------------------------

        # SSL/TLS validity
        ssl_valid = _find(tech, "ssl_valid")
        if ssl_valid is False:
            score += 20
            triggered_rules.append("Technical: Invalid SSL/TLS certificate (+20)")

        # Domain age
        domain_age = _find(tech, "domain_age_days")
        if isinstance(domain_age, (int, float)) and domain_age < 30:
            score += 25
            triggered_rules.append(
                f"Technical: Domain registered within last 30 days ({domain_age} day(s)) (+25)"
            )

        # SPF authentication failure
        spf_pass = _find(tech, "spf_pass")
        if spf_pass is False:
            score += 25
            triggered_rules.append("Technical: SPF authentication failed (+25)")

        # DKIM authentication failure
        dkim_pass = _find(tech, "dkim_pass")
        if dkim_pass is False:
            score += 20
            triggered_rules.append("Technical: DKIM signature validation failed (+20)")

        # Reply-To mismatch (phishing indicator)
        reply_mismatch = _find(tech, "reply_to_mismatch")
        if reply_mismatch:
            score += 35
            triggered_rules.append("Technical: Reply-To address mismatch detected (+35)")

        # -----------------------------------------------------------------
        # 2. Threat Intelligence
        # -----------------------------------------------------------------

        # VirusTotal detections
        vt_detections = _find(threat, "virustotal_positives", 0)
        if isinstance(vt_detections, int) and vt_detections > 0:
            added = min(60, vt_detections * 15)
            score += added
            triggered_rules.append(
                f"Threat Intel: {vt_detections} VirusTotal detection(s) (+{added})"
            )

        # Google Safe Browsing
        gsb_unsafe = _find(threat, "gsb_unsafe", False)
        if gsb_unsafe is True:
            score += 50
            triggered_rules.append("Threat Intel: Google Safe Browsing flagged URL (+50)")

        # Cryptocurrency wallet addresses
        crypto = _find(threat, "crypto_wallet_matches")
        if crypto:
            score += 45
            triggered_rules.append("Threat Intel: Cryptocurrency wallet address(es) found (+45)")

        # Sensitive numbers (CC/OTP)
        sensitive = _find(threat, "sensitive_numbers")
        if sensitive:
            score += 35
            triggered_rules.append("Threat Intel: Sensitive numbers (CC/OTP) requested (+35)")

        # Phone numbers
        phones = _find(threat, "phone_number_matches")
        if phones:
            score += 20
            triggered_rules.append("Threat Intel: Phone number(s) included (+20)")

        # Embedded links (email context)
        links = _find(threat, "embedded_links")
        if isinstance(links, list) and len(links) > 10:
            score += 20
            triggered_rules.append(
                f"Threat Intel: High number of embedded links ({len(links)}) (+20)"
            )

        # -----------------------------------------------------------------
        # 3. Heuristic Matches
        # -----------------------------------------------------------------

        # Urgency flags
        urgency = _find(heur, "urgency_flags")
        if urgency:
            urgency_score = urgency if isinstance(urgency, int) else 1
            added = min(40, urgency_score * 15)
            score += added
            triggered_rules.append(f"Heuristic: Urgency/pressure language detected (+{added})")

        # Payment / financial keywords
        payment_triggers = _find(heur, "payment_triggers")
        if payment_triggers:
            kw_count = len(payment_triggers) if isinstance(payment_triggers, list) else 1
            added = min(45, kw_count * 15)
            score += added
            triggered_rules.append(f"Heuristic: Payment/financial keywords detected (+{added})")

        # OCR keyword matches (image scanner)
        ocr_kw = _find(heur, "ocr_keyword_matches")
        if ocr_kw:
            kw_count = len(ocr_kw) if isinstance(ocr_kw, list) else 1
            added = min(40, kw_count * 15)
            score += added
            triggered_rules.append(f"Heuristic: {kw_count} suspicious keyword(s) in image (+{added})")

        # Suspicious image flag
        suspicious_img = _find(heur, "suspicious_image_flag")
        if suspicious_img:
            score += 35
            triggered_rules.append("Heuristic: Suspicious image content detected (+35)")

        # Spam keyword count (text scanner)
        spam_kw = _find(tech, "spam_keyword_count")
        if isinstance(spam_kw, int) and spam_kw > 0:
            added = min(40, spam_kw * 10)
            score += added
            triggered_rules.append(f"Heuristic: {spam_kw} spam keyword(s) in text (+{added})")

        # Email scam keywords
        email_kw = _find(heur, "email_flag_keywords")
        if email_kw:
            kw_count = len(email_kw) if isinstance(email_kw, list) else 1
            added = min(45, kw_count * 15)
            score += added
            triggered_rules.append(f"Heuristic: {kw_count} scam keyword(s) in email (+{added})")

        # URL keyword detections
        url_kw = _find(heur, "url_keyword_detections")
        if url_kw:
            kw_count = len(url_kw) if isinstance(url_kw, list) else 1
            added = min(40, kw_count * 15)
            score += added
            triggered_rules.append(f"Heuristic: {kw_count} impersonation keyword(s) in URL (+{added})")

        # Suspicious TLD
        suspicious_tld = _find(heur, "suspicious_tld")
        if suspicious_tld:
            score += 25
            triggered_rules.append("Heuristic: Suspicious/high-risk TLD detected (+25)")

        # Raw IP address
        is_ip = _find(heur, "is_ip_address")
        if is_ip:
            score += 40
            triggered_rules.append("Heuristic: URL uses a raw IP address (+40)")

        # URL Shortener / IP Tracker
        is_tracker = _find(heur, "is_tracker_or_shortener")
        if is_tracker:
            score += 40
            triggered_rules.append("Heuristic: URL uses a known link shortener or IP tracker (+40)")

        # Shortened URLs (text scanner)
        shortened = _find(heur, "shortened_urls")
        if shortened:
            score += 35
            triggered_rules.append("Heuristic: Suspicious shortened URL used (+35)")

        # Shouting detected (text scanner)
        shouting = _find(heur, "shouting_detected")
        if shouting:
            score += 15
            triggered_rules.append("Heuristic: Excessive capitalization/shouting detected (+15)")

        # -----------------------------------------------------------------
        # Clamp and classify
        # -----------------------------------------------------------------
        final_score: int = max(0, min(100, score))

        if final_score <= 30:
            risk_level = "Low Risk"
        elif final_score <= 60:
            risk_level = "Medium Risk"
        else:
            risk_level = "High Risk"

        return RiskEvaluation(
            risk_score=final_score,
            risk_level=risk_level,
            triggered_rules=triggered_rules,
        )


# ---------------------------------------------------------------------------
# Module-level singleton — import and call risk_engine.evaluate(evidence)
# ---------------------------------------------------------------------------
risk_engine = RiskEngine()


def evaluate(evidence: Any) -> RiskEvaluation:
    """Module-level convenience wrapper around the singleton RiskEngine."""
    return risk_engine.evaluate(evidence)