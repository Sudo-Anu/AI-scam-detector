import os
import base64
import logging
from typing import Dict, Any

import httpx

# Configure module logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

async def check_virustotal_url(url: str) -> Dict[str, Any]:
    """
    Checks a given URL against the VirusTotal v3 API.
    
    Args:
        url (str): The URL to scan/lookup.
        
    Returns:
        Dict[str, Any]: A standardized dictionary containing detection counts and status.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY is missing. Skipping VirusTotal check.")
        return {"detections": 0, "status": "skipped_or_unreachable"}

    # VirusTotal v3 uses a base64 (url-safe, unpadded) encoded string as the URL identifier.
    try:
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
    except Exception as e:
        logger.error(f"Failed to encode URL for VirusTotal: {e}")
        return {"detections": 0, "status": "skipped_or_unreachable"}

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=7.0) as client:
            response = await client.get(endpoint, headers=headers)
            
            # Handle standard missing/not-found as 0 detections instead of failure
            if response.status_code == 404:
                return {"detections": 0, "status": "not_found_in_db"}
                
            response.raise_for_status()
            data = response.json()
            
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            return {
                "detections": malicious + suspicious,
                "status": "success",
                "raw_stats": stats
            }
            
    except httpx.RequestError as e:
        logger.warning(f"Network error during VirusTotal API check for {url}: {e}")
        return {"detections": 0, "status": "skipped_or_unreachable"}
    except httpx.HTTPStatusError as e:
        logger.warning(f"HTTP error {e.response.status_code} during VirusTotal API check for {url}: {e}")
        return {"detections": 0, "status": "skipped_or_unreachable"}
    except Exception as e:
        logger.warning(f"Unexpected error during VirusTotal API check for {url}: {e}")
        return {"detections": 0, "status": "skipped_or_unreachable"}


async def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """
    Checks a given URL against the Google Safe Browsing API v4.
    
    Args:
        url (str): The URL to check.
        
    Returns:
        Dict[str, Any]: A standardized dictionary indicating if the URL is unsafe and the threat type.
    """
    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("SAFE_BROWSING_API_KEY")
    if not api_key:
        logger.warning("Google Safe Browsing API key is missing. Skipping check.")
        return {"is_unsafe": False, "threat_type": None, "status": "skipped_or_unreachable"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "ai-scam-detector-backend",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=7.0) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            data = response.json()
            
            matches = data.get("matches", [])
            if matches:
                # Extract the most prominent threat type (first match)
                threat_type = matches[0].get("threatType")
                return {
                    "is_unsafe": True,
                    "threat_type": threat_type,
                    "status": "success"
                }
            else:
                return {
                    "is_unsafe": False,
                    "threat_type": None,
                    "status": "success"
                }
                
    except httpx.RequestError as e:
        logger.warning(f"Network error during Google Safe Browsing API check for {url}: {e}")
        return {"is_unsafe": False, "threat_type": None, "status": "skipped_or_unreachable"}
    except httpx.HTTPStatusError as e:
        logger.warning(f"HTTP error {e.response.status_code} during Google Safe Browsing API check for {url}: {e}")
        return {"is_unsafe": False, "threat_type": None, "status": "skipped_or_unreachable"}
    except Exception as e:
        logger.warning(f"Unexpected error during Google Safe Browsing API check for {url}: {e}")
        return {"is_unsafe": False, "threat_type": None, "status": "skipped_or_unreachable"}