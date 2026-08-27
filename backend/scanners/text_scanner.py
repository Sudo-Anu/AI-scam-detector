import re
import logging
from typing import Dict, Any, List, Set

# Initialize logger for the module
logger = logging.getLogger(__name__)

# --- Categorized Keyword & Phrase Lists ---
# We structure this dictionary to easily identify the intent behind the text block
KEYWORD_CATEGORIES = {
    "financial_frauds": [
        "wire transfer", "refund", "gift card", "inheritance", 
        "cryptocurrency", "western union", "direct deposit", "pay a fee"
    ],
    "account_exploits": [
        "verify account", "password reset", "security alert", "suspended", 
        "unauthorized login", "credentials", "unusual activity", "account", "verify"
    ],
    "prizes_giveaways": [
        "winner", "claims prize", "lottery", "gift card winner", 
        "inheritance", "selected"
    ],
    "impersonation_support": [
        "customer support", "helpdesk", "agent", "agent support"
    ],
    "urgency_triggers": [
        "immediate action", "act now", "within 24 hours", 
        "otherwise account closed", "final warning", "urgent"
    ]
}

# --- Regular Expressions ---
# Crypto: Match standard P2PKH/P2SH Bitcoin addresses (1 or 3), Bech32 (bc1), and standard Ethereum addresses (0x)
CRYPTO_BTC_REGEX = re.compile(r'\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b')
CRYPTO_ETH_REGEX = re.compile(r'\b0x[a-fA-F0-9]{40}\b')

# Phones: Broad match for international and domestic phone numbers commonly used in SMS
PHONE_REGEX = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')

# URLs: Match web links embedded in the text
URL_REGEX = re.compile(r'(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?')

# Sensitive Numerics: CC patterns (16 digits separated by spaces/dashes) and explicit 2FA/OTP contexts
CC_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
OTP_REGEX = re.compile(r'(?:otp|2fa|pin|code)[\s:]*?(\d{4,8})\b', re.IGNORECASE)

# Known URL shortener domains for smishing/phishing
SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "buff.ly", "ow.ly"]


def _check_shouting(text: str) -> bool:
    """
    Evaluates if a text block contains a high ratio of uppercase characters (shouting).
    Requires a minimum length of 20 characters to avoid flagging short acronyms.
    """
    try:
        if len(text) < 20:
            return False
            
        alpha_chars = [c for c in text if c.isalpha()]
        if not alpha_chars:
            return False
            
        upper_chars = [c for c in alpha_chars if c.isupper()]
        ratio = len(upper_chars) / len(alpha_chars)
        
        return ratio > 0.35
    except Exception as e:
        logger.debug(f"Error calculating shouting ratio: {e}")
        return False


def scan_text(text: str) -> Dict[str, Any]:
    """
    Main entry point for scanning raw text or SMS messages.
    Applies keyword heuristics, regex pattern matching, and urgency scoring.
    """
    text_lower = ""
    try:
        text_lower = text.lower()
    except Exception as e:
        logger.error(f"Error converting text to lowercase: {e}")
        # If we can't even lower the string, return an empty defensive structure
        return _get_empty_result(text)

    # 1. Suspicious Keyword / Phrase Check
    detected_keywords: Set[str] = set()
    financial_scam_detected = False
    urgency_score = 0
    
    try:
        for category, phrases in KEYWORD_CATEGORIES.items():
            for phrase in phrases:
                # Count occurrences for urgency scoring
                if category == "urgency_triggers" and phrase in text_lower:
                    occurrences = text_lower.count(phrase)
                    urgency_score += occurrences
                    
                if phrase in text_lower:
                    detected_keywords.add(phrase)
                    if category in ["financial_frauds", "account_exploits"]:
                        financial_scam_detected = True
                        
    except Exception as e:
        logger.error(f"Error during keyword extraction phase: {e}")

    # 2. Pattern Matching via Regular Expressions
    crypto_wallets = []
    phone_numbers = []
    shortened_urls = []
    sensitive_numbers = []
    
    try:
        # Crypto Wallets
        crypto_wallets.extend(CRYPTO_BTC_REGEX.findall(text))
        crypto_wallets.extend(CRYPTO_ETH_REGEX.findall(text))
        
        # Phone Numbers
        phone_matches = PHONE_REGEX.findall(text)
        phone_numbers.extend([p.strip() for p in phone_matches])
        
        # Hyperlinks & Shortened URLs
        urls = URL_REGEX.findall(text)
        for url in urls:
            try:
                # Extract the domain to check against known shorteners
                domain = url.split("://")[-1].split("/")[0].lower()
                if any(shortener in domain for shortener in SHORTENER_DOMAINS):
                    shortened_urls.append(url)
            except Exception:
                pass
                
        # Sensitive Numeric Triggers
        cc_matches = CC_REGEX.findall(text)
        for cc in cc_matches:
            digits_only = re.sub(r'[^0-9]', '', cc)
            if 13 <= len(digits_only) <= 16:
                sensitive_numbers.append(cc.strip())
                
        otp_matches = OTP_REGEX.findall(text)
        sensitive_numbers.extend(otp_matches)
        
    except Exception as e:
        logger.error(f"Error during regex pattern matching phase: {e}")

    # 3. Heuristic & Behavioral Rules
    shouting_detected = _check_shouting(text)
    urgency_detected = urgency_score > 0
    
    # 4. Assemble the Output Dictionary
    return {
        "text": text,
        "keywords": {
            "detected_keywords": list(detected_keywords),
            "keyword_count": len(detected_keywords)
        },
        "patterns": {
            "crypto_wallets_found": list(set(crypto_wallets)),
            "phone_numbers_found": list(set(phone_numbers)),
            "shortened_urls_found": list(set(shortened_urls)),
            "sensitive_numbers_found": list(set(sensitive_numbers))
        },
        "heuristics": {
            "urgency_detected": urgency_detected,
            "urgency_score": urgency_score,
            "shouting_detected": shouting_detected,
            "financial_scam_detected": financial_scam_detected
        }
    }


def _get_empty_result(text: str) -> Dict[str, Any]:
    """Defensive fallback output in case of severe scanning failure."""
    return {
        "text": text,
        "keywords": {
            "detected_keywords": [],
            "keyword_count": 0
        },
        "patterns": {
            "crypto_wallets_found": [],
            "phone_numbers_found": [],
            "shortened_urls_found": [],
            "sensitive_numbers_found": []
        },
        "heuristics": {
            "urgency_detected": False,
            "urgency_score": 0,
            "shouting_detected": False,
            "financial_scam_detected": False
        }
    }


if __name__ == "__main__":
    # Local dry-run test mimicking the output specification request
    import json
    
    sample_text = "URGENT: Your account is suspended! Log in to https://bit.ly/fake-login to verify within 24 hours or pay a fee."
    result = scan_text(sample_text)
    print(json.dumps(result, indent=4))