"""
AI Scam Detector Backend — Gemini AI Client
============================================
backend/integrations/gemini_client.py

Interfaces with the Google Gemini API (via the modern `google-genai` SDK)
to transform threat evidence into a structured JSON safety report.
"""

import os
import json
import re
import logging
from typing import Dict, Any, Optional

from google import genai  # type: ignore[import-untyped]
from google.genai import types as genai_types  # type: ignore[import-untyped]

# Configure module logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

PROMPT_FILE_PATH = "backend/storage/prompts/gemini_prompt.txt"

DEFAULT_SYSTEM_PROMPT = """
You are an expert cybersecurity analyst and AI Scam Detector.
Your task is to analyze the provided threat evidence, risk score, and risk level to generate a structured, human-readable safety analysis report.
You must strictly return your findings in JSON format matching exactly this structure:
{
    "summary": "A brief, user-friendly overview of the findings.",
    "reasons": ["A specific, technical justification", "Another justification"],
    "possible_threat": "Specific category of scam or malware (e.g., Phishing, Advance-Fee Scam)",
    "recommendations": ["Actionable safety step 1", "Actionable safety step 2"]
}
Ensure the JSON is valid and contains no additional text or markdown formatting outside of the JSON block.
""".strip()


def _get_api_key() -> Optional[str]:
    """Safely retrieves the Gemini API key from environment variables."""
    key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    return key.strip() if key else None


def _load_system_prompt() -> str:
    """
    Attempts to load the system prompt from the designated file path.
    Falls back to the hardcoded default if the file doesn't exist or is unreadable.
    """
    if os.path.exists(PROMPT_FILE_PATH):
        try:
            with open(PROMPT_FILE_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception as e:
            logger.warning(f"Failed to read prompt file at {PROMPT_FILE_PATH}: {e}. Using fallback.")
    return DEFAULT_SYSTEM_PROMPT


def _get_mock_response(risk_level: str) -> Dict[str, Any]:
    """
    Returns a pre-compiled mock evaluation based on the risk level.
    Used as a fallback when the API is unavailable, unauthenticated, or fails.
    """
    level = risk_level.lower()
    if "high" in level:
        return {
            "summary": "High risk detected. The provided input matches known malicious patterns.",
            "reasons": [
                "Multiple heuristic flags triggered.",
                "Matches signatures of known threats or blocklists.",
            ],
            "possible_threat": "Phishing or Malware",
            "recommendations": [
                "Do not interact with the link or file.",
                "Run a full system antivirus scan.",
                "Delete or quarantine the source material immediately.",
            ],
        }
    elif "medium" in level:
        return {
            "summary": "Medium risk detected. The input exhibits some suspicious characteristics.",
            "reasons": [
                "Suspicious metadata or uncommon indicators found.",
                "Unable to fully verify the origin or reputation.",
            ],
            "possible_threat": "Suspicious Activity / Potential Spam",
            "recommendations": [
                "Proceed with caution.",
                "Verify the sender or source through a secondary channel before continuing.",
                "Do not provide sensitive personal information.",
            ],
        }
    else:
        return {
            "summary": "Low risk detected. No immediate threats were identified.",
            "reasons": [
                "Input appears normal and lacks typical malicious indicators.",
                "Domain/file is benign based on current checks.",
            ],
            "possible_threat": "None",
            "recommendations": [
                "Standard safety practices apply.",
                "Always stay vigilant when interacting with external links or files.",
            ],
        }


def _clean_json_string(raw_text: str) -> str:
    """Strips markdown code block wrappers from a JSON string if present."""
    text = re.sub(r"^```json\s*", "", raw_text.strip(), flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def generate_safety_report(
    input_type: str,
    risk_score: int,
    risk_level: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Interfaces with the Gemini API to transform threat evidence into a structured
    JSON report using the modern `google-genai` SDK.

    Args:
        input_type: The type of input analyzed (url, email, text, image).
        risk_score:  Numerical risk score from 0 to 100.
        risk_level:  Categorized risk level (Low Risk / Medium Risk / High Risk).
        evidence:    Dictionary of collected evidence indicators.

    Returns:
        Dict with keys: summary, reasons, possible_threat, recommendations.
        Falls back to a mock response if the API call fails.
    """
    api_key = _get_api_key()

    if not api_key:
        logger.warning("Gemini API key is missing or empty. Returning mock evaluation.")
        return _get_mock_response(risk_level)

    system_instruction = _load_system_prompt()

    user_prompt = f"""
Please analyze the following threat intelligence data and provide a safety report.

Input Type: {input_type}
Risk Score: {risk_score}/100
Risk Level: {risk_level}
Collected Evidence:
{json.dumps(evidence, indent=2, default=str)}
""".strip()

    try:
        # Initialise client with the new google-genai SDK
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                temperature=0.2,
            ),
        )

        raw_text = response.text
        if not raw_text:
            raise ValueError("Empty response received from Gemini.")

        cleaned_text = _clean_json_string(raw_text)
        report_data = json.loads(cleaned_text)

        # Validate required schema keys
        required_keys = {"summary", "reasons", "possible_threat", "recommendations"}
        if not required_keys.issubset(report_data.keys()):
            logger.warning(
                "Missing required keys in Gemini response. Keys received: %s",
                list(report_data.keys()),
            )
            return _get_mock_response(risk_level)

        return report_data

    except json.JSONDecodeError as e:
        logger.error("Failed to parse Gemini JSON response: %s", e)
        return _get_mock_response(risk_level)
    except Exception as e:
        logger.error("Gemini API call failed: %s", e)
        return _get_mock_response(risk_level)


# Module-level alias so any code calling `explain()` also works
explain = generate_safety_report