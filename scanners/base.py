"""
Base Scanner Plugin Interface for GuardScan
Provides common utilities, callback notifications, and standardized result structures.
"""

import time
import random
import requests
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse


class BaseScanner:
    """Base class for all GuardScan vulnerability modules"""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    ]

    def __init__(self, name: str, scan_type: str):
        self.name = name
        self.scan_type = scan_type
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._session: Optional[requests.Session] = None

    def add_progress_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback for real-time progress updates"""
        self.callbacks.append(callback)

    def notify_progress(self, data: Dict[str, Any]):
        """Notify registered progress listeners"""
        for callback in self.callbacks:
            try:
                callback(data)
            except Exception:
                pass

    def get_random_user_agent(self) -> str:
        """Return a random modern browser User-Agent"""
        return random.choice(self.USER_AGENTS)

    def get_session(self) -> requests.Session:
        """Get or initialize a requests session with connection pooling"""
        if self._session is None:
            self._session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=25,
                pool_maxsize=50,
                max_retries=2
            )
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
        return self._session

    def format_finding(self,
                       url: str,
                       payload: str,
                       vulnerable: bool,
                       title: str,
                       severity: str = "Medium",
                       cvss_score: float = 5.0,
                       cwe_id: str = "CWE-200",
                       owasp_category: str = "A01:2021-Broken Access Control",
                       evidence: Optional[str] = None,
                       remediation: Optional[str] = None,
                       remediation_code: Optional[str] = None,
                       response_time: float = 0.0,
                       status_code: Optional[int] = None,
                       extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Produce a standardized finding record for both UI matrix and PDF report generation"""
        finding = {
            'url': url,
            'payload': payload,
            'vulnerable': vulnerable,
            'title': title,
            'severity': severity,
            'cvss_score': cvss_score,
            'cwe_id': cwe_id,
            'owasp_category': owasp_category,
            'evidence': evidence or '',
            'remediation': remediation or '',
            'remediation_code': remediation_code or '',
            'response_time': response_time,
            'status_code': status_code,
            'timestamp': time.time(),
            'method': 'plugin'
        }
        if extra:
            finding.update(extra)
        return finding

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        """Must be implemented by sub-classes"""
        raise NotImplementedError("Subclasses of BaseScanner must implement scan()")
