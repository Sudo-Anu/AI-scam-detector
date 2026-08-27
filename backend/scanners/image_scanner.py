import os
import re
import logging
from typing import Dict, Any, List, Set, Optional

# Configure module-level logging
logger = logging.getLogger(__name__)

# Safely import PIL for image metadata extraction
try:
    # pyrefly: ignore [missing-import]
    from PIL import Image, UnidentifiedImageError
except ImportError:
    Image = None
    logger.warning("Pillow (PIL) library not found. Image metadata extraction will be severely limited.")

# --- Singleton OCR Reader Setup ---
# EasyOCR is highly resource-intensive. We use a global reference to ensure
# it is only loaded into memory once across the entire lifecycle of the server.
_OCR_READER = None

def get_ocr_reader() -> Any:
    """
    Lazy-loads the EasyOCR reader singleton.
    Returns the reader instance, or 'UNAVAILABLE' if dependencies are missing/failed.
    """
    global _OCR_READER
    
    if _OCR_READER is None:
        try:
            # pyrefly: ignore [missing-import]
            import easyocr
            logger.info("Initializing EasyOCR reader (Singleton)...")
            # Initialize for English, disabling GPU to prioritize CPU compatibility if needed
            _OCR_READER = easyocr.Reader(['en'], gpu=False)
        except ImportError:
            logger.error("easyocr library is not installed. Image scanning will fall back to empty payloads.")
            _OCR_READER = "UNAVAILABLE"
        except Exception as e:
            logger.error(f"Failed to initialize EasyOCR reader: {e}", exc_info=True)
            _OCR_READER = "UNAVAILABLE"
            
    return _OCR_READER


# --- Keyword and Heuristic Definitions ---
# Structured by classification intent for downstream analysis
KEYWORD_CATEGORIES = {
    "Financial Scam": [
        "wire transfer", "refund", "gift card", "crypto", "western union"
    ],
    "Account Exploit": [
        "verify account", "security alert", "suspended", "unauthorized login", "verify", "account"
    ],
    "Prizes & Giveaways": [
        "winner", "claims prize", "lottery", "gift card winner"
    ],
    "Impersonation": [
        "customer support", "helpdesk", "agent"
    ]
}

URGENCY_KEYWORDS = [
    "urgent", "act now", "24 hours", "otherwise closed"
]

# --- Regular Expressions ---
PHONE_REGEX = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
URL_REGEX = re.compile(r'(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?')


def get_image_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extracts technical indicators from the image file safely.
    Returns format, width, height, and file size in KB.
    """
    metadata: Dict[str, Any] = {
        "format": "UNKNOWN",
        "width": 0,
        "height": 0,
        "file_size_kb": 0.0
    }
    
    if not os.path.exists(file_path):
        logger.error(f"File not found during metadata extraction: {file_path}")
        return metadata
        
    try:
        # Extract file size
        file_size_bytes = os.path.getsize(file_path)
        metadata["file_size_kb"] = round(file_size_bytes / 1024, 2)
        
        # Extract dimensions and format via PIL
        if Image:
            with Image.open(file_path) as img:
                metadata["format"] = img.format if img.format else "UNKNOWN"
                metadata["width"] = img.width
                metadata["height"] = img.height
                
    except UnidentifiedImageError:
        logger.error(f"File at {file_path} is not a valid image or is corrupted.")
    except Exception as e:
        logger.error(f"Unexpected error extracting metadata for {file_path}: {e}")
        
    return metadata


def scan_image(file_path: str) -> Dict[str, Any]:
    """
    Main asynchronous/synchronous entry point for the image OCR scanning engine.
    Extracts text, matches heuristics/patterns, and maps findings to the expected output payload.
    """
    # 1. Extract File Metadata
    file_metadata = get_image_metadata(file_path)
    extracted_text = ""
    
    # 2. Run OCR Detection
    if os.path.exists(file_path) and file_metadata["format"] != "UNKNOWN":
        reader = get_ocr_reader()
        if reader and reader != "UNAVAILABLE":
            try:
                # readtext with detail=0 returns only a list of string text blocks
                result_blocks = reader.readtext(file_path, detail=0)
                # Join blocks with spaces and convert to a cohesive lowercase string
                extracted_text = " ".join(result_blocks).lower()
            except Exception as e:
                logger.error(f"OCR execution crashed on {file_path}: {e}", exc_info=True)
                
    # 3. Text & Heuristic Content Analysis Setup
    detected_keywords: Set[str] = set()
    phone_numbers: List[str] = []
    urls: List[str] = []
    urgency_detected = False
    suspicious_image_flag = False
    classification = "Unknown"
    
    # Process extracted text for threats
    if extracted_text:
        # Keyword Category Matches
        for category, phrases in KEYWORD_CATEGORIES.items():
            for phrase in phrases:
                if phrase in extracted_text:
                    detected_keywords.add(phrase)
                    suspicious_image_flag = True
                    # In a real system, you might aggregate scores; here we take the last matched category
                    classification = category
                    
        # Urgency Phrase Matches
        for phrase in URGENCY_KEYWORDS:
            if phrase in extracted_text:
                detected_keywords.add(phrase)
                urgency_detected = True
                suspicious_image_flag = True
                
        # Regex Pattern Matches (Phones & URLs)
        try:
            phone_matches = PHONE_REGEX.findall(extracted_text)
            if phone_matches:
                phone_numbers.extend(list(set([p.strip() for p in phone_matches])))
                suspicious_image_flag = True
                
            urls_matches = URL_REGEX.findall(extracted_text)
            if urls_matches:
                urls.extend(list(set(urls_matches)))
                suspicious_image_flag = True
                
        except Exception as e:
            logger.error(f"Regex pattern matching failed on OCR text: {e}")

        # Finalize classification if no malicious indicators were found despite text existing
        if not suspicious_image_flag and len(detected_keywords) == 0:
            classification = "Safe"
            
    # Remove redundant sub-matches if desired (e.g. "verify" when "verify account" is present)
    # However, to strictly adhere to the output specification example, we pass them as found.
    detected_keywords_list = list(detected_keywords)
    
    # 4. Return Output Specification Payload
    return {
        "file_metadata": file_metadata,
        "extracted_text": extracted_text,
        "keywords": {
            "detected_keywords": detected_keywords_list,
            "keyword_count": len(detected_keywords_list)
        },
        "patterns": {
            "phone_numbers_found": phone_numbers,
            "urls_found": urls
        },
        "heuristics": {
            "urgency_detected": urgency_detected,
            "suspicious_image_flag": suspicious_image_flag,
            "classification": classification
        }
    }


if __name__ == "__main__":
    # Local dry-run test
    import json
    
    sample_path = "backend/storage/uploads/images/sample_suspicious_screenshot.png"
    result = scan_image(sample_path)
    print(json.dumps(result, indent=4))