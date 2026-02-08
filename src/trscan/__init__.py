"""
TR-Pasif Web Güvenlik Skoru

Yasal ve etik pasif web güvenlik tarama aracı.
"""

__version__ = "1.0.0"
__author__ = "TRScan Security Team"
__license__ = "MIT"

from .models import (
    CookieInfo,
    DNSInfo,
    Finding,
    HeaderAnalysis,
    PageInfo,
    ScanResult,
    SecurityScore,
    TLSInfo,
)
from .scanner import WebSecurityScanner

__all__ = [
    "WebSecurityScanner",
    "Finding",
    "CookieInfo",
    "HeaderAnalysis",
    "TLSInfo",
    "DNSInfo",
    "PageInfo",
    "SecurityScore",
    "ScanResult",
]
