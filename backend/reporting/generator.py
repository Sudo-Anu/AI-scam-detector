import os
import json
import uuid
from datetime import datetime
from typing import Dict, Any
from fpdf import FPDF

class PDFReport(FPDF):
    def header(self):
        # Navy/Indigo header banner
        self.set_fill_color(30, 58, 138)
        self.rect(0, 0, 210, 30, 'F')
        self.set_y(10)
        self.set_font('helvetica', 'B', 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, 'AI Scam Detector Report', border=0, align='C')
        self.ln(20)

    def footer(self):
        # Standard footer with timestamp and page numbers
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(15, 23, 42)  # Dark Slate
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cell(0, 10, f'Generated: {timestamp} | Page {self.page_no()}/{{nb}}', align='C')

def generate_reports(
    scan_data: Dict[str, Any],
    evidence: Dict[str, Any],
    evaluation: Dict[str, Any],
    ai_explanation: Dict[str, Any],
) -> Dict[str, str]:
    """
    Generates a JSON and PDF report for the scan and returns a dict with
    keys 'pdf' and 'json' containing the /report/<filename> URL paths.
    Returns an empty dict on failure.
    """
    try:
        # Generate cryptographically unique report_id
        report_id = uuid.uuid4().hex
        
        # Define storage directories
        json_dir = os.path.join('backend', 'storage', 'reports', 'json')
        pdf_dir = os.path.join('backend', 'storage', 'reports', 'pdf')
        
        # Auto-Folder Verification: Ensure directories exist
        os.makedirs(json_dir, exist_ok=True)
        os.makedirs(pdf_dir, exist_ok=True)
        
        # File paths
        json_filename = f"report_{report_id}.json"
        pdf_filename = f"report_{report_id}.pdf"
        
        json_filepath = os.path.join(json_dir, json_filename)
        pdf_filepath = os.path.join(pdf_dir, pdf_filename)
        
        # ==========================================
        # 1. JSON Report Generation
        # ==========================================
        report_data = {
            "report_id": report_id,
            "timestamp": datetime.now().isoformat(),
            "scan_data": scan_data,
            "evidence": evidence,
            "evaluation": evaluation,
            "ai_explanation": ai_explanation
        }
        
        # Save as pretty-printed JSON
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4)
            
        # ==========================================
        # 2. PDF Report Generation
        # ==========================================
        pdf = PDFReport()
        pdf.alias_nb_pages()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Common text color (Dark Slate)
        pdf.set_text_color(15, 23, 42)
        
        # Section 1: Executive Summary
        pdf.set_font("helvetica", 'B', 16)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.ln(2)

        # Risk Level Badge
        risk_score = evaluation.get("risk_score", 0)
        try:
            risk_score = float(risk_score)
        except (ValueError, TypeError):
            risk_score = 0
            
        risk_level = str(evaluation.get("risk_level", "Unknown")).upper()

        # Conditionally color-code Risk Level
        if risk_score <= 30:
            pdf.set_fill_color(34, 197, 94)   # Green for Low Risk
        elif risk_score <= 60:
            pdf.set_fill_color(245, 158, 11)  # Yellow/Amber for Medium Risk
        else:
            pdf.set_fill_color(239, 68, 68)   # Red for High Risk

        pdf.set_font("helvetica", 'B', 14)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 12, f" Risk Level: {risk_level} ({risk_score}/100) ", ln=True, fill=True, align='C')
        pdf.ln(6)

        # Reset text color for content
        pdf.set_text_color(15, 23, 42)
        
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 8, "AI Summary:", ln=True)
        pdf.set_font("helvetica", '', 11)
        pdf.multi_cell(0, 6, str(ai_explanation.get("summary", "No summary provided.")))
        pdf.ln(3)
        
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 8, "Possible Threat:", ln=True)
        pdf.set_font("helvetica", '', 11)
        pdf.multi_cell(0, 6, str(ai_explanation.get("possible_threat", "Unknown")))
        pdf.ln(8)

        # Section 2: Detailed Evidence Log
        pdf.set_font("helvetica", 'B', 16)
        pdf.cell(0, 10, "Detailed Evidence Log", ln=True)
        pdf.ln(2)

        # Light Grey background for tables/cells
        pdf.set_fill_color(241, 245, 249)
        
        evidence_categories = ['technical_indicators', 'threat_intelligence', 'heuristic_matches']
        for category in evidence_categories:
            items = evidence.get(category)
            if items:
                pdf.set_font("helvetica", 'B', 12)
                title = category.replace('_', ' ').title()
                pdf.cell(0, 8, f"{title}:", ln=True)
                pdf.set_font("helvetica", '', 10)
                
                # Defensive text wrapping with multi_cell
                if isinstance(items, dict):
                    for k, v in items.items():
                        pdf.multi_cell(0, 6, f"{k}: {v}", fill=True)
                        pdf.ln(1)
                elif isinstance(items, list):
                    for item in items:
                        pdf.multi_cell(0, 6, f"- {item}", fill=True)
                        pdf.ln(1)
                else:
                    pdf.multi_cell(0, 6, str(items), fill=True)
                    pdf.ln(1)
                pdf.ln(3)

        pdf.ln(4)

        # Section 3: Security Recommendations
        pdf.set_font("helvetica", 'B', 16)
        pdf.cell(0, 10, "Security Recommendations", ln=True)
        pdf.ln(2)
        
        pdf.set_font("helvetica", '', 11)
        recs = ai_explanation.get("recommendations", [])
        
        # Defensive text wrapping with multi_cell
        if isinstance(recs, list):
            for rec in recs:
                pdf.multi_cell(0, 6, f"- {rec}", fill=True)
                pdf.ln(1)
        else:
            pdf.multi_cell(0, 6, str(recs), fill=True)
            pdf.ln(1)

        # Compile and save PDF
        pdf.output(pdf_filepath)
        
        # Return URL paths for both report files
        return {
            "pdf":  f"/report/{pdf_filename}",
            "json": f"/report/{json_filename}",
        }

    except Exception as e:
        # Gracefully handle IO issues or parsing errors — return empty dict
        import logging
        logging.getLogger(__name__).error(f"Report generation failed: {e}", exc_info=True)
        return {}