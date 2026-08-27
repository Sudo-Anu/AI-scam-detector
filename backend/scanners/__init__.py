"""
AI Scam Detector Backend — Scanners Package
============================================
Exposes the main scanner entry-point functions for easier imports.
"""

from .url_scanner   import scan_url
from .email_scanner import scan_email
from .text_scanner  import scan_text
from .image_scanner import scan_image

__all__ = [
    "scan_url",
    "scan_email",
    "scan_text",
    "scan_image",
]