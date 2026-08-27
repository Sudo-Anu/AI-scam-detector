import email
from email import policy
import email.utils
import re
import logging
from typing import Dict, Any, List, Tuple

# Safely import BeautifulSoup, falling back to regex if not installed
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None
    logging.warning("BeautifulSoup not found. HTML parsing for links will rely solely on regex.")

# Configure module logger
logger = logging.getLogger(__name__)

# Heuristic configurations for suspicious activities
SUSPICIOUS_KEYWORDS = [
    "verify your account", "immediate action required", "security alert", 
    "suspended", "login here", "bank", "invoice", "unusual activity",
    "urgent", "verify", "credentials", "password reset", "account limitation"
]

# Regex for extracting URLs from plain text
URL_REGEX = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')


def _extract_auth_alignment(msg: email.message.EmailMessage) -> Tuple[bool, bool]:
    """
    Examines email authentication headers to check for SPF and DKIM alignment.
    In the absence of a proper auth parser, it uses a simplified string match.
    """
    is_spf_aligned = False
    is_dkim_valid = False
    
    try:
        # Authentication-Results is the standard header for evaluating SPF/DKIM
        auth_results = msg.get_all("Authentication-Results", [])
        received_spf = msg.get_all("Received-SPF", [])
        
        # Combine relevant headers for a broader search
        auth_header_str = " ".join(str(h) for h in (auth_results + received_spf)).lower()
        
        if "spf=pass" in auth_header_str:
            is_spf_aligned = True
            
        if "dkim=pass" in auth_header_str:
            is_dkim_valid = True
            
    except Exception as e:
        logger.debug(f"Failed to parse authentication headers: {e}")

    return is_spf_aligned, is_dkim_valid


def _extract_links(msg: email.message.EmailMessage) -> List[str]:
    """
    Walks through the email payload structure to extract all URLs from text and HTML.
    Returns a deduplicated list of URLs.
    """
    links = set()
    
    try:
        for part in msg.walk():
            # Skip multiparts, we only care about the actual text/html leaves
            if part.is_multipart():
                continue
                
            content_type = part.get_content_type()
            if content_type not in ["text/plain", "text/html"]:
                continue
                
            # Safely get payload bytes
            payload = part.get_payload(decode=True)
            if not payload:
                continue
                
            # Decode bytes to string
            charset = part.get_content_charset() or 'utf-8'
            try:
                text = payload.decode(charset, errors='replace')
            except LookupError:
                # Fallback if declared charset is unknown to Python
                text = payload.decode('utf-8', errors='replace')
                
            # Always run regex over the raw text representation
            found_urls = URL_REGEX.findall(text)
            links.update(found_urls)
            
            # Use BeautifulSoup for more precise HTML attribute extraction if available
            if content_type == "text/html" and BeautifulSoup:
                soup = BeautifulSoup(text, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    if href.startswith("http"):
                        links.add(href)
                        
    except Exception as e:
        logger.error(f"Error while extracting links from email body: {e}")
        
    return list(links)


def _get_empty_result() -> Dict[str, Any]:
    """Returns a safe default dictionary mapping if parsing critically fails."""
    return {
        "sender": "",
        "sender_display_name": "",
        "subject": "",
        "headers": {
            "from": "",
            "to": "",
            "reply_to": None,
            "date": ""
        },
        "extracted_links": [],
        "heuristics": {
            "from_reply_mismatch": False,
            "is_spf_aligned": False,
            "is_dkim_valid": False,
            "suspicious_keywords_found": [],
            "keyword_match_count": 0
        }
    }


def scan_email(file_path: str) -> Dict[str, Any]:
    """
    Main entry point for scanning an .eml file.
    Reads the file safely, extracts headers, sender, links, and runs heuristic keyword checks.
    """
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except Exception as e:
        logger.error(f"Failed to read or parse email file {file_path}: {e}")
        return _get_empty_result()

    # 1. Extract standard headers safely
    from_header = str(msg.get("From", ""))
    to_header = str(msg.get("To", ""))
    subject_header = str(msg.get("Subject", ""))
    date_header = str(msg.get("Date", ""))
    reply_to_header = str(msg.get("Reply-To", ""))

    # 2. Sender Verification & Header Analysis
    display_name, sender_addr = email.utils.parseaddr(from_header)
    
    # Reply-to mismatch logic
    from_reply_mismatch = False
    if reply_to_header:
        _, reply_to_addr = email.utils.parseaddr(reply_to_header)
        # If reply-to is populated but doesn't match the sender address
        if reply_to_addr and sender_addr.lower() != reply_to_addr.lower():
            from_reply_mismatch = True
    else:
        # If there's no Reply-To, normalize reply_to_header for JSON output
        reply_to_header = None

    is_spf_aligned, is_dkim_valid = _extract_auth_alignment(msg)
    
    # 3. Link Extraction
    extracted_links = _extract_links(msg)
    
    # 4. Heuristic Phrase & Keyword Checks
    keywords_found = []
    body_text = subject_header + " "  # Include subject in heuristic checks
    
    try:
        # Extract plain text content for keyword scanning
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        text = payload.decode(charset, errors='replace')
                    except LookupError:
                        text = payload.decode('utf-8', errors='replace')
                    body_text += text + " "
    except Exception as e:
        logger.debug(f"Error compiling body text for heuristic analysis: {e}")
                
    body_lower = body_text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in body_lower:
            keywords_found.append(kw)
            
    # Assemble and return the normalized dictionary
    return {
        "sender": sender_addr,
        "sender_display_name": display_name,
        "subject": subject_header,
        "headers": {
            "from": from_header,
            "to": to_header,
            "reply_to": reply_to_header,
            "date": date_header
        },
        "extracted_links": extracted_links,
        "heuristics": {
            "from_reply_mismatch": from_reply_mismatch,
            "is_spf_aligned": is_spf_aligned,
            "is_dkim_valid": is_dkim_valid,
            "suspicious_keywords_found": keywords_found,
            "keyword_match_count": len(keywords_found)
        }
    }


if __name__ == "__main__":
    # Local dry-run test (Requires a valid .eml file in the working directory)
    import json
    import os
    
    sample_file = "suspicious_email.eml"
    if os.path.exists(sample_file):
        result = scan_email(sample_file)
        print(json.dumps(result, indent=4))
    else:
        print(f"Test file '{sample_file}' not found. Provide an .eml file to test execution.")