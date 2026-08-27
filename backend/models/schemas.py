from typing import Any, Dict, List, Literal
from datetime import datetime, timezone
import uuid
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field, field_validator, ValidationInfo, HttpUrl, TypeAdapter

class URLScanRequest(BaseModel):
    """Schema for submitting a URL for scanning."""
    url: str = Field(
        ...,
        min_length=1,
        description="A valid, non-empty URL string to be scanned."
    )

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        # Utilize standard Pydantic HttpUrl validation while preserving the str type
        TypeAdapter(HttpUrl).validate_python(v)
        return v

class TextScanRequest(BaseModel):
    """Schema for submitting an SMS or block text for scanning."""
    text: str = Field(
        ...,
        min_length=1,
        description="A non-empty text block to be scanned."
    )

class EvidenceItem(BaseModel):
    """Models a single piece of threat evidence."""
    name: str = Field(..., description="The name of the indicator, e.g., 'SSL Certificate', 'Urgency Phrase count'")
    value: Any = Field(..., description="The raw value analyzed, e.g., True, False, or an integer")
    description: str = Field(..., description="A friendly explanation of what this indicator represents")
    severity: Literal["low", "medium", "high"] = Field(..., description="The severity level of this evidence indicator")

class StandardizedEvidence(BaseModel):
    """Models the evidence aggregated and grouped by the collector."""
    payload_type: str = Field(
        default="",
        description="The scanner type that produced this evidence (url, email, text, image)"
    )
    technical_indicators: List[EvidenceItem] = Field(
        default_factory=list,
        description="List of technical indicators observed in the scan"
    )
    threat_intelligence: List[EvidenceItem] = Field(
        default_factory=list,
        description="List of threat intelligence matching items"
    )
    heuristic_matches: List[EvidenceItem] = Field(
        default_factory=list,
        description="List of heuristic and pattern matches"
    )

class RiskEvaluation(BaseModel):
    """Models the results calculated by the scoring engine."""
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="The calculated risk score, strictly between 0 and 100 inclusive"
    )
    risk_level: Literal["Low Risk", "Medium Risk", "High Risk"] = Field(
        ...,
        description="The qualitative risk level (Low Risk, Medium Risk, High Risk)"
    )
    triggered_rules: List[str] = Field(
        default_factory=list,
        description="A list of names of specific security and scanner rules violated"
    )

    @field_validator('risk_level')
    @classmethod
    def validate_risk_level_matches_score(cls, v: str, info: ValidationInfo) -> str:
        score = info.data.get('risk_score')
        if score is not None:
            if 0 <= score <= 30 and v != "Low Risk":
                raise ValueError(f"risk_score of {score} must correspond to 'Low Risk' (0-30)")
            elif 31 <= score <= 60 and v != "Medium Risk":
                raise ValueError(f"risk_score of {score} must correspond to 'Medium Risk' (31-60)")
            elif 61 <= score <= 100 and v != "High Risk":
                raise ValueError(f"risk_score of {score} must correspond to 'High Risk' (61-100)")
        return v

class AIExplanation(BaseModel):
    """Models the natural language assessment returned by the AI generator."""
    summary: str = Field(
        ...,
        description="A brief, user-friendly summary of why the input is safe or unsafe"
    )
    reasons: List[str] = Field(
        ...,
        description="Specific bullet points explaining the risk score"
    )
    possible_threat: str = Field(
        ...,
        description="The category of scam or exploit suspected (e.g., 'Phishing')"
    )
    recommendations: List[str] = Field(
        ...,
        description="Actionable safety advice for the user"
    )

class ScanResponse(BaseModel):
    """The unified master schema returned by all four /scan/* endpoints."""
    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="A unique request identifier (UUID string)"
    )
    input_type: Literal["url", "email", "text", "image"] = Field(
        ...,
        description="The type of submission that was processed"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 formatted generation timestamp string"
    )
    evaluation: RiskEvaluation = Field(
        ...,
        description="The risk scoring and categorization details"
    )
    evidence: StandardizedEvidence = Field(
        ...,
        description="Aggregated evidence indicators"
    )
    ai_explanation: AIExplanation = Field(
        ...,
        description="AI-generated assessment and safety advice"
    )
    report_urls: Dict[str, str] = Field(
        ...,
        description="Dictionary containing downloadable link paths to generated reports"
    )

class HealthResponse(BaseModel):
    """Models the service availability endpoint response."""
    status: Literal["healthy"] = Field(
        default="healthy",
        description="Status of the application"
    )
    service: Literal["AI Scam Detector Backend"] = Field(
        default="AI Scam Detector Backend",
        description="The name of the service"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 current timestamp"
    )