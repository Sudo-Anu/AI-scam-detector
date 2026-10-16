# Security Audit Report: AI Scam Detector

## Executive Summary
A static code analysis and security audit was conducted on the AI Scam Detector codebase. Several critical and high-severity vulnerabilities were identified, including Local File Inclusion (LFI), hardcoded API secrets, and insecure file handling mechanisms.

Below are the detailed findings, their risks, and the remediated code to apply.

---

## 1. Local File Inclusion (LFI) / Arbitrary File Read
**Severity:** CRITICAL
**Location:** `backend/api/endpoints.py` -> `get_report()` (Lines 244-264)

### The Vulnerability
The `/report/{filename}` endpoint takes the user-supplied `filename` path parameter and appends it directly to the local directory path using `os.path.join()`.

```python
@router.get("/report/{filename}", tags=["Reports"])
async def get_report(filename: str):
    if filename.lower().endswith(".pdf"):
        file_path  = os.path.join(REPORT_DIR_PDF,  filename)
# ...
```

FastAPI path parameters can contain URL-encoded slashes (`%2F`) and dot-dots (`%2E%2E`). An attacker can send a request like:
`GET /report/%2Fetc%2Fpasswd%00.pdf` or `GET /report/..%2F..%2F..%2F..%2Fetc%2Fpasswd.pdf`.
Because `os.path.join` replaces the base directory if the second argument is an absolute path, or traverses if it contains `../`, this allows an attacker to read arbitrary files from the server's filesystem.

### Remediated Code
Sanitize the filename to ensure it does not contain any directory separators by using `os.path.basename()` and ensuring the file remains in the intended directory.

```python
import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

@router.get("/report/{filename}", tags=["Reports"])
async def get_report(filename: str):
    # Sanitize the input to prevent Path Traversal
    safe_filename = os.path.basename(filename)
    
    if safe_filename.lower().endswith(".pdf"):
        file_path  = os.path.abspath(os.path.join(REPORT_DIR_PDF, safe_filename))
        expected_dir = os.path.abspath(REPORT_DIR_PDF)
        media_type = "application/pdf"
    elif safe_filename.lower().endswith(".json"):
        file_path  = os.path.abspath(os.path.join(REPORT_DIR_JSON, safe_filename))
        expected_dir = os.path.abspath(REPORT_DIR_JSON)
        media_type = "application/json"
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid report format. Expected .pdf or .json",
        )

    # Secondary check: ensure the resolved path strictly resides within the target directory
    if not file_path.startswith(expected_dir):
        raise HTTPException(status_code=403, detail="Access denied.")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found.")

    return FileResponse(path=file_path, media_type=media_type, filename=safe_filename)
```

---

## 2. Hardcoded API Secrets
**Severity:** CRITICAL
**Location:** `.env` file (Root Directory)

### The Vulnerability
The `.env` file contains sensitive live API keys for Gemini, VirusTotal, and Google APIs. While the `.gitignore` specifies `.env`, the file is currently present in the directory. If this environment file is accidentally checked into version control or packaged in a Docker image, attackers scanning GitHub or container registries will steal these keys, leading to financial loss, quota exhaustion, and data breaches.

### Remediation
1. **Rotate the Keys:** Immediately revoke the exposed `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, and `GOOGLE_API_KEY` from their respective provider dashboards and generate new ones.
2. **Remove from Git:** If `.env` was ever committed, remove it from git history using `git rm --cached .env` and BFG Repo-Cleaner.
3. **Use `.env.example`:** Provide a `.env.example` template with dummy values for other developers, and inject the real secrets via the host environment securely (e.g., AWS Secrets Manager, GitHub Actions Secrets, or Doppler).

---

## 3. Insecure File Upload Handling (Path Traversal Risk)
**Severity:** HIGH
**Location:** `backend/api/endpoints.py` -> `scan_email()` and `scan_image()`

### The Vulnerability
When handling file uploads, the application constructs the destination path using the user-provided `file.filename`:

```python
scan_id = str(uuid.uuid4())
safe_filename = f"{scan_id}_{file.filename}"
file_path = os.path.join(UPLOAD_DIR_EMAILS, safe_filename)
```

While prepending the `scan_id` unintentionally mitigates standard `../` directory traversal (because it looks for a directory starting with the UUID which doesn't exist), it remains a dangerous anti-pattern. If the application logic ever changes, or if OS-level parsing behaves unexpectedly with certain characters, an attacker could achieve an Arbitrary File Write, leading to Remote Code Execution (RCE).

### Remediated Code
Extract only the extension, or strictly sanitize the filename to strip out any directory paths provided by the client's browser.

```python
import os
import uuid
# from werkzeug.utils import secure_filename # Recommended for filename sanitization

@router.post("/scan/image", response_model=ScanResponse, tags=["Scanning"])
async def scan_image(file: UploadFile = File(...)):
    valid_extensions = (".png", ".jpg", ".jpeg", ".webp")
    
    # 1. Extract and validate extension cleanly
    _, ext = os.path.splitext(file.filename)
    if ext.lower() not in valid_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Expected one of: {valid_extensions}",
        )

    # 2. Ignore user filename completely or strictly sanitize it
    scan_id = str(uuid.uuid4())
    # Option A: Completely random name
    safe_filename = f"{scan_id}{ext.lower()}" 
    
    file_path = os.path.join(UPLOAD_DIR_IMAGES, safe_filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        # ... remainder of code
```

---

## 4. Missing Rate Limiting and File Size Caps
**Severity:** MEDIUM
**Location:** Global API and File Upload Endpoints

### The Vulnerability
1. **Unrestricted File Sizes:** The `/scan/email` and `/scan/image` endpoints do not limit the size of incoming files. `shutil.copyfileobj` will happily write gigabytes of data to the server's disk, leading to a Denial of Service (Storage Exhaustion).
2. **No Rate Limiting:** The API endpoints lack authentication and rate limiting. Attackers can spam the `/scan/url` endpoint, burning through your Gemini API quotas and VirusTotal limits, resulting in a severe financial Denial of Wallet.

### Remediation
**Add File Size Limits:**
For FastAPI, it is highly recommended to enforce a `Content-Length` limit using a middleware or manually checking the size as it's streamed.

**Implement Rate Limiting:**
Implement an API Gateway, or use `slowapi` (a rate-limiting library for FastAPI) to enforce IP-based rate limiting on all scanning endpoints.

```python
# Example of manual size validation before reading the whole file
MAX_FILE_SIZE = 5 * 1024 * 1024 # 5 MB

@router.post("/scan/image")
async def scan_image(file: UploadFile = File(...)):
    # Read first chunk to check size
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 5MB.")
```

---

## 5. Insecure CORS Configuration
**Severity:** LOW (Currently)
**Location:** `backend/main.py` -> `ALLOWED_ORIGINS`

### The Vulnerability
Currently, the CORS middleware allows `allow_credentials=True` and `allow_origins=ALLOWED_ORIGINS` (which maps to localhost). However, if this is ever changed to `allow_origins=["*"]` (which developers frequently do during deployment troubleshooting), it will introduce a critical misconfiguration. Setting `allow_credentials=True` along with wildcards or poorly validated Origins allows attackers to execute Cross-Origin Requests with the victim's cookies.

### Remediation
Ensure that in production, the origins are dynamically strictly validated against expected domains (e.g., `https://your-frontend-domain.com`), and avoid ever using `"*"` when `allow_credentials` is True.

```python
import os

# Use environment variables to define production origins
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"], # Restrict exactly to what is needed
    allow_headers=["Authorization", "Content-Type"],
)
```
