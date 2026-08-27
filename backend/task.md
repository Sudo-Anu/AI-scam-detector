# Debug Task List

- [x] Create backend/__init__.py
- [x] Create backend/core/__init__.py
- [x] Create backend/integrations/__init__.py
- [x] Create backend/models/__init__.py
- [x] Create backend/reporting/__init__.py
- [x] Fix requirements.txt (remove tracing)
- [x] Fix schemas.py (add payload_type to StandardizedEvidence)
- [x] Fix evidence.py (rewrite collect_from_* to match scanner output, add normalize(), import from schemas)
- [x] Fix risk_engine.py (fix evaluate() for EvidenceItem list, add singleton, import from schemas)
- [x] Fix scanners/__init__.py (correct function names)
- [x] Fix core/input_router.py (_SCANNER_REGISTRY correct names)
- [x] Fix url_scanner.py (make async, await threat APIs)
- [x] Fix api/endpoints.py (all 6 pipeline call bugs + schema fields)
- [x] Fix reporting/generator.py (signature + return dict)
