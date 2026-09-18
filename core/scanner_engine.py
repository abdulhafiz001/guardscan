"""
Platform-independent scanning engine
Core scanning logic delegating to modular plugins under scanners/
Maintains 100% backwards compatibility with existing CLI and Web API callers.
"""

import time
from typing import List, Dict, Any, Optional
from scanners import get_scanner


class ScannerEngine:
    """
    Unified Vulnerability Scanner Engine
    Delegates to modular plugins in `scanners/` while maintaining legacy API signatures.
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    ]

    def __init__(self):
        self.scan_state = {
            'vulnerability_found': False,
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'current_url': '',
            'progress': 0
        }
        self.callbacks = []

    def add_progress_callback(self, callback):
        """Add callback for progress updates"""
        self.callbacks.append(callback)

    def _notify_progress(self, data: dict):
        """Notify all callbacks of progress"""
        for callback in self.callbacks:
            try:
                callback(data)
            except Exception:
                pass

    def _bind_scanner(self, scanner):
        """Bind internal callbacks to modular scanner plugin"""
        for cb in self.callbacks:
            scanner.add_progress_callback(cb)
        return scanner

    def scan_lfi(self, urls: List[str], payloads: List[str],
                 success_criteria: List[str] = None, threads: int = 3) -> Dict[str, Any]:
        """Local File Inclusion scanner"""
        scanner = self._bind_scanner(get_scanner('lfi'))
        return scanner.scan(urls=urls, payloads=payloads, success_criteria=success_criteria, threads=threads)

    def scan_sqli(self, urls: List[str], payloads: List[str],
                  threads: int = 3, time_threshold: int = 5) -> Dict[str, Any]:
        """SQL Injection scanner"""
        scanner = self._bind_scanner(get_scanner('sqli'))
        return scanner.scan(urls=urls, payloads=payloads, threads=threads, time_threshold=time_threshold)

    def scan_xss(self, urls: List[str], payloads: List[str],
                 threads: int = 3) -> Dict[str, Any]:
        """Cross-Site Scripting scanner"""
        scanner = self._bind_scanner(get_scanner('xss'))
        return scanner.scan(urls=urls, payloads=payloads, threads=threads)

    def scan_or(self, urls: List[str], payloads: List[str],
                threads: int = 3) -> Dict[str, Any]:
        """Open Redirect scanner"""
        scanner = self._bind_scanner(get_scanner('or'))
        return scanner.scan(urls=urls, payloads=payloads, threads=threads)

    def scan_crlf(self, urls: List[str], threads: int = 3) -> Dict[str, Any]:
        """CRLF Injection scanner"""
        scanner = self._bind_scanner(get_scanner('crlf'))
        return scanner.scan(urls=urls, threads=threads)

    def scan_bola(self, urls: List[str], token_a: str, token_b: str,
                  id_variations: Optional[List[str]] = None, threads: int = 5) -> Dict[str, Any]:
        """Broken Object Level Authorization (BOLA / IDOR) API scanner"""
        scanner = self._bind_scanner(get_scanner('bola'))
        return scanner.scan(urls=urls, token_a=token_a, token_b=token_b,
                            id_variations=id_variations, threads=threads)

    def scan_gateway(self, urls: List[str], threads: int = 5) -> Dict[str, Any]:
        """Fintech Gateway & Payment Webhook scanner"""
        scanner = self._bind_scanner(get_scanner('gateway'))
        return scanner.scan(urls=urls, threads=threads)
