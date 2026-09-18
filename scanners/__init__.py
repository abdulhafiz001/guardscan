"""
Scanner Plugin Registry for GuardScan
Provides centralized discovery and initialization of all vulnerability scanners.
"""

from typing import Dict, Type, List, Optional
from scanners.base import BaseScanner
from scanners.lfi_scanner import LFIScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.xss_scanner import XSSScanner
from scanners.or_scanner import OpenRedirectScanner
from scanners.crlf_scanner import CRLFScanner
from scanners.bola_scanner import BOLAScanner
from scanners.gateway_scanner import GatewayScanner


SCANNER_REGISTRY: Dict[str, Type[BaseScanner]] = {
    'lfi': LFIScanner,
    'sqli': SQLiScanner,
    'xss': XSSScanner,
    'or': OpenRedirectScanner,
    'crlf': CRLFScanner,
    'bola': BOLAScanner,
    'gateway': GatewayScanner,
}


def get_scanner(scan_type: str) -> Optional[BaseScanner]:
    """Retrieve an instantiated scanner instance by type key"""
    key = scan_type.lower().strip()
    if key in ['openredirect', 'open_redirect', 'redirect']:
        key = 'or'
    elif key in ['sql', 'sql_injection']:
        key = 'sqli'
    elif key in ['fintech', 'paystack', 'flutterwave', 'webhook']:
        key = 'gateway'

    scanner_cls = SCANNER_REGISTRY.get(key)
    if scanner_cls:
        return scanner_cls()
    return None


def list_scanners() -> List[Dict[str, str]]:
    """Return available scanner keys and friendly names"""
    return [
        {'id': 'lfi', 'name': 'LFI / Path Traversal', 'category': 'Web'},
        {'id': 'sqli', 'name': 'SQL Injection', 'category': 'Database'},
        {'id': 'xss', 'name': 'Cross-Site Scripting', 'category': 'Client-Side'},
        {'id': 'or', 'name': 'Open Redirect', 'category': 'Navigation'},
        {'id': 'crlf', 'name': 'CRLF / Response Splitting', 'category': 'Headers'},
        {'id': 'bola', 'name': 'BOLA / IDOR API Scanner', 'category': 'API & Auth'},
        {'id': 'gateway', 'name': 'Fintech Gateway Probe', 'category': 'Payment / Webhooks'},
    ]
