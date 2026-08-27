import ssl
import socket
import datetime
import logging
from urllib.parse import urlparse
from typing import Dict, Any

# Configure basic logger for the module
logger = logging.getLogger(__name__)

# Safely import python-whois
try:
    # pyrefly: ignore [missing-import]
    import whois
except ImportError:
    logger.warning("python-whois library is not installed. WHOIS lookups will return default values.")
    whois = None

# Safely import Threat API integrations, providing mock fallbacks if missing to prevent crashes
try:
    from backend.integrations.threat_apis import check_virustotal_url, check_google_safe_browsing
except ImportError:
    logger.warning("Threat API integrations module not found. Using fallback mock data.")
    
    async def check_virustotal_url(url: str) -> Dict[str, Any]:
        return {"detections": 0, "status": "skipped_or_unreachable"}
        
    async def check_google_safe_browsing(url: str) -> Dict[str, Any]:
        return {"is_unsafe": False, "threat_type": None, "status": "skipped_or_unreachable"}

# Heuristic configurations for suspicious activities
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".gq", ".zip", ".review", ".country", ".kim", ".science", ".work", ".party", ".gdn"}
IMPERSONATION_KEYWORDS = ["paypal", "netflix", "support-verify", "login-update", "apple", "microsoft", "google", "amazon", "bank", "secure", "account", "update", "verify"]


def get_domain_from_url(url: str) -> str:
    """Extracts the domain name from a given URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.split(":")[0]  # Strip port if present
        return domain.lower()
    except Exception as e:
        logger.debug(f"Failed to parse domain from URL {url}: {e}")
        return ""


def check_whois(domain: str) -> Dict[str, Any]:
    """Performs a WHOIS lookup and extracts domain age, registrar, and creation date."""
    whois_data = {
        "domain_age_days": 0,
        "registrar": None,
        "created_date": None
    }
    
    if not whois or not domain:
        return whois_data

    try:
        w = whois.whois(domain)
        
        # Handle cases where multiple dates or registrars are returned as lists
        registrar = w.registrar[0] if isinstance(w.registrar, list) else w.registrar
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        
        if registrar:
            whois_data["registrar"] = str(registrar)
        
        if isinstance(creation_date, datetime.datetime):
            whois_data["created_date"] = creation_date.isoformat()
            now = datetime.datetime.now(datetime.timezone.utc) if creation_date.tzinfo else datetime.datetime.now()
            age = (now - creation_date).days
            whois_data["domain_age_days"] = max(0, age)
            
    except Exception as e:
        logger.error(f"WHOIS lookup failed for domain {domain}: {e}")
        
    return whois_data


def check_ssl(domain: str) -> Dict[str, Any]:
    """Verifies SSL/TLS certificate and extracts issuer and expiration days."""
    ssl_data = {
        "is_valid": False,
        "issuer": None,
        "days_until_expiration": 0
    }
    
    if not domain:
        return ssl_data

    try:
        context = ssl.create_default_context()
        context.check_hostname = False  # Only checking connection and cert metadata
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_data["is_valid"] = True
                
                # Extract Issuer Organization Name
                for item in cert.get('issuer', ()):
                    for field in item:
                        if field[0] == 'organizationName':
                            ssl_data["issuer"] = field[1]
                            break
                            
                # Extract Expiration Date
                not_after = cert.get('notAfter')
                if not_after:
                    # typical format: 'Oct  8 23:59:59 2024 GMT'
                    expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.datetime.utcnow()).days
                    ssl_data["days_until_expiration"] = max(0, days_left)
                    
    except Exception as e:
        logger.error(f"SSL verification failed for domain {domain}: {e}")
        
    return ssl_data


def check_heuristics(url: str, domain: str) -> Dict[str, Any]:
    """Checks for suspicious TLDs and brand impersonation keywords in the URL."""
    import re
    
    heuristics_data = {
        "suspicious_tld_detected": False,
        "impersonation_keywords_found": [],
        "is_ip_address": False,
        "is_tracker_or_shortener": False
    }
    
    # 1. Check suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            heuristics_data["suspicious_tld_detected"] = True
            break
            
    # 2. Check for brand impersonation keywords in the entire URL path
    url_lower = url.lower()
    for keyword in IMPERSONATION_KEYWORDS:
        if keyword in url_lower:
            heuristics_data["impersonation_keywords_found"].append(keyword)

    # 3. Check if domain is a raw IP address (IPv4)
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(domain):
        heuristics_data["is_ip_address"] = True

    # 4. Check for common link shorteners and IP trackers
    trackers = ["grabify.link", "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "iplogger.org", "blasze.com"]
    if any(tracker in domain for tracker in trackers):
        heuristics_data["is_tracker_or_shortener"] = True
            
    return heuristics_data


async def scan_url(url: str) -> Dict[str, Any]:
    """
    Main scanning engine entry point (async).
    Aggregates WHOIS, SSL, Threat Intelligence, and Heuristics into a normalized dictionary.
    """
    domain = get_domain_from_url(url)
    
    # 1. Local Structural and Network Checks (sync — safe to call directly)
    whois_info = check_whois(domain)
    ssl_info = check_ssl(domain)
    heuristics_info = check_heuristics(url, domain)
    
    # 2. Threat Intelligence Integrations (async — must be awaited)
    vt_result: Dict[str, Any] = {"detections": 0, "status": "skipped_or_unreachable"}
    gsb_result: Dict[str, Any] = {"is_unsafe": False, "threat_type": None, "status": "skipped_or_unreachable"}
    
    try:
        vt_result = await check_virustotal_url(url)
    except Exception as e:
        logger.error(f"VirusTotal API check crashed for {url}: {e}")
        
    try:
        gsb_result = await check_google_safe_browsing(url)
    except Exception as e:
        logger.error(f"Google Safe Browsing API check crashed for {url}: {e}")
        
    threat_intel_info = {
        "virustotal_detections": vt_result.get("detections", 0),
        "google_safe_browsing_flagged": gsb_result.get("is_unsafe", False)
    }
    
    # 3. Assemble and return normalized dictionary
    return {
        "url": url,
        "domain": domain,
        "whois": whois_info,
        "ssl": ssl_info,
        "threat_intelligence": threat_intel_info,
        "heuristics": heuristics_info
    }


if __name__ == "__main__":
    # Local dry-run test
    import json
    sample_url = "https://suspicious-link.example.com/paypal/login-update"
    result = scan_url(sample_url)
    print(json.dumps(result, indent=4))