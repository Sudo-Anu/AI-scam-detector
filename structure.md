ai-scam-detector/ 
├── frontend/ *                 # 1. User Interaction (React) 
│   ├── public/ * 
│   ├── src/ *
│   │   ├── components/ *        # UI Elements 
│   │   │   ├── Inputs/ *         # Scan URL, Email, Text, Image forms 
│   │   │   │   ├── UrlScanner.jsx *
│   │   │   │   ├── EmailScanner.jsx *
│   │   │   │   ├── TextScanner.jsx *
│   │   │   │   └── ImageScanner.jsx *
│   │   │   └── Dashboard/ *     # Risk Score, Evidence, AI Explainer views 
│   │   │       └── ResultsDashboard.jsx *
│   │   ├── api/ *               # Axios/Fetch logic for HTTP requests 
│   │   ├── App.jsx *
│   │   └── index.jsx *
│   └── package.json *
│ 
├── backend/                    # FastAPI Application 
│   ├── main.py                 # Core app init and GET /health 
│   ├── api/                    # 2. API & Routing 
│   │   ├── __init__.py 
│   │   └── endpoints.py        # POST /scan/* and GET /report/* routes 
│   │ 
│   ├── core/                   # 4. Threat Evaluation & Logic 
│   │   ├── input_router.py     # Routes payload to correct scanner 
│   │   ├── evidence.py         # Evidence Collector logic 
│   │   └── risk_engine.py      # Calculates Risk Score (0-100) & Level 
│   │ 
│   ├── scanners/               # 3. Scanning Engines 
│   │   ├── __init__.py 
│   │   ├── url_scanner.py      # WHOIS, HTTPS, VirusTotal, Safe Browsing 
│   │   ├── email_scanner.py    # .eml parsing, header extraction 
│   │   ├── text_scanner.py     # Heuristics, Pattern matching 
│   │   └── image_scanner.py    # EasyOCR integration 
│   │ 
│   ├── integrations/           # 5. AI & 7. External Services 
│   │   ├── gemini_client.py    # Interfaces with Gemini API (AI Explainer) 
│   │   └── threat_apis.py      # Helper functions for VirusTotal/Google Safe Browsing 
│   │ 
│   ├── reporting/              # 6. Reporting System 
│   │   └── generator.py        # Compiles PDF and JSON reports 
│   │ 
│   ├── models/                 # Data validation 
│   │   └── schemas.py          # Pydantic models for structured JSON flow 
│   │ 
│   ├── storage/                # 6. File Storage 
│   │   ├── uploads/            # Temporary: images/, emails/, documents/ 
│   │   ├── reports/            # Generated: pdf/, json/ 
│   │   └── prompts/            # gemini_prompt.txt 
│   │ 
│   └── requirements.txt        # Python dependencies (fastapi, uvicorn, easyocr, etc.) 
│ 
├── .env                        # Environment variables (API Keys, etc.) 
├── .gitignore 
└── README.md                   # Project documentation