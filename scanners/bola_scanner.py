"""
Broken Object Level Authorization (BOLA / IDOR) API Scanner Plugin
Tests REST API endpoints for horizontal authorization bypass using dual-token context switching.
Includes response structure key comparison and length delta heuristics to prevent false positives.
"""

import time
import json
import re
import requests
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.base import BaseScanner


class BOLAScanner(BaseScanner):
    """
    Scanner plugin for Broken Object Level Authorization (OWASP API1:2023 / CWE-639)
    """

    def __init__(self):
        super().__init__(name="BOLA / API Scanner", scan_type="BOLA")

    @staticmethod
    def _extract_json_keys(data: Any, prefix: str = "") -> Set[str]:
        """Recursively collect keys/structure from a JSON payload"""
        keys = set()
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else str(k)
                keys.add(full_key)
                if isinstance(v, (dict, list)):
                    keys.update(BOLAScanner._extract_json_keys(v, full_key))
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):  # Sample first 5 items
                full_key = f"{prefix}[]"
                keys.add(full_key)
                if isinstance(item, (dict, list)):
                    keys.update(BOLAScanner._extract_json_keys(item, full_key))
        return keys

    @staticmethod
    def _is_error_payload(data: Any) -> bool:
        """Heuristic check if JSON payload indicates an error despite a 200 HTTP status"""
        if isinstance(data, dict):
            # Check common error indicators
            status_val = str(data.get('status', '')).lower()
            if status_val in ['error', 'fail', 'failed', 'unauthorized', 'forbidden', 'denied']:
                return True
            if 'error' in data and data['error']:
                return True
            if 'errors' in data and data['errors']:
                return True
            msg = str(data.get('message', '')).lower()
            if any(term in msg for term in ['unauthorized', 'forbidden', 'denied', 'permission', 'not found', 'invalid token']):
                return True
        return False

    def check_endpoint_bola(self,
                            endpoint_url: str,
                            token_a: str,
                            token_b: str,
                            session: Optional[requests.Session] = None,
                            auth_header_format: str = "Bearer {token}") -> Dict[str, Any]:
        """
        Check a single REST API endpoint for BOLA / IDOR vulnerability.
        
        Step 1: Baseline Request with User A token (Resource owner)
        Step 2: Attack Request with User B token (Secondary/unauthorized user)
        Step 3: Unauthenticated Request (No token)
        
        False-Positive Mitigation:
        - Compares response status codes (reject 401, 403, 404)
        - Parses JSON response bodies
        - Verifies User B's response isn't a 200 OK error payload
        - Compares key structure similarity (>70% overlap required)
        - Computes response body length delta
        """
        session = session or self.get_session()
        start_time = time.time()

        header_name = "Authorization"
        headers_a = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
            header_name: auth_header_format.format(token=token_a) if token_a else ""
        }
        headers_b = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
            header_name: auth_header_format.format(token=token_b) if token_b else ""
        }
        headers_anon = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json"
        }

        # Step 1: User A Baseline Request
        try:
            resp_a = session.get(endpoint_url, headers=headers_a, timeout=12, allow_redirects=False)
            status_a = resp_a.status_code
            body_a = resp_a.text
            len_a = len(body_a)
        except Exception as e:
            return self.format_finding(
                url=endpoint_url,
                payload=f"User A baseline failed: {str(e)[:80]}",
                vulnerable=False,
                title="BOLA / IDOR Authorization Check",
                severity="Info",
                cvss_score=0.0,
                extra={'error': f"Baseline request failed: {str(e)}"}
            )

        if status_a not in [200, 201, 204]:
            # Resource cannot even be accessed by legitimate User A
            return self.format_finding(
                url=endpoint_url,
                payload="User A baseline returned non-200",
                vulnerable=False,
                title="BOLA / IDOR Authorization Check",
                severity="Info",
                cvss_score=0.0,
                status_code=status_a,
                extra={'note': f"User A baseline returned HTTP {status_a}; cannot verify BOLA"}
            )

        # Parse User A JSON
        json_a = None
        keys_a = set()
        try:
            json_a = resp_a.json()
            keys_a = self._extract_json_keys(json_a)
        except Exception:
            pass

        # Step 2: User B Attack Request
        try:
            resp_b = session.get(endpoint_url, headers=headers_b, timeout=12, allow_redirects=False)
            status_b = resp_b.status_code
            body_b = resp_b.text
            len_b = len(body_b)
        except Exception as e:
            return self.format_finding(
                url=endpoint_url,
                payload=f"User B request failed: {str(e)[:80]}",
                vulnerable=False,
                title="BOLA / IDOR Authorization Check",
                severity="Info",
                cvss_score=0.0,
                extra={'error': str(e)}
            )

        response_time = round(time.time() - start_time, 2)

        # Step 3: Unauthenticated request (informative)
        status_anon = None
        try:
            resp_anon = session.get(endpoint_url, headers=headers_anon, timeout=10, allow_redirects=False)
            status_anon = resp_anon.status_code
        except Exception:
            pass

        # Evaluation & False-Positive Mitigation Logic
        is_vulnerable = False
        evidence_lines = []
        severity = "High"
        cvss_score = 7.5

        if status_b in [401, 403, 404]:
            is_vulnerable = False
            evidence_lines.append(f"Properly protected: User B received HTTP {status_b}")
        elif status_b == 200:
            json_b = None
            try:
                json_b = resp_b.json()
            except Exception:
                pass

            if json_b is not None:
                # Check for 200 OK disguised error pages
                if self._is_error_payload(json_b):
                    is_vulnerable = False
                    evidence_lines.append(f"HTTP 200 returned but JSON payload indicates application-level error (Mitigated False-Positive)")
                else:
                    keys_b = self._extract_json_keys(json_b)
                    # Structure comparison: Calculate Jaccard similarity or key intersection
                    if keys_a and keys_b:
                        intersection = keys_a.intersection(keys_b)
                        similarity = len(intersection) / max(len(keys_a), 1)
                        length_delta = abs(len_a - len_b)
                        length_ratio = min(len_a, len_b) / max(max(len_a, len_b), 1)

                        evidence_lines.append(f"Key overlap: {len(intersection)}/{len(keys_a)} ({similarity:.1%})")
                        evidence_lines.append(f"Length Delta: {length_delta} bytes (User A: {len_a}B, User B: {len_b}B)")

                        # Only flag if structure matches significantly and lengths are comparable
                        if similarity >= 0.70 and (length_delta < 2000 or length_ratio > 0.40):
                            is_vulnerable = True
                            evidence_lines.append("User B successfully accessed User A's object with identical data schema.")
                        else:
                            is_vulnerable = False
                            evidence_lines.append(f"Payload structure delta too large ({similarity:.1%} similarity); treated as safe.")
                    else:
                        # Fallback if keys cannot be extracted (plain string or numeric)
                        length_delta = abs(len_a - len_b)
                        if length_delta < 150:
                            is_vulnerable = True
                            evidence_lines.append(f"HTTP 200 with minimal body length delta ({length_delta}B)")
            else:
                # Non-JSON 200 response (e.g. HTML or CSV)
                length_delta = abs(len_a - len_b)
                if length_delta < 100 and len_b > 20:
                    is_vulnerable = True
                    evidence_lines.append(f"HTTP 200 non-JSON response matched User A (delta {length_delta}B)")
                else:
                    is_vulnerable = False
                    evidence_lines.append("HTTP 200 received but content diverged from User A's payload.")

        # Additional severity bump if unauthenticated user can also read it
        if is_vulnerable and status_anon == 200:
            severity = "Critical"
            cvss_score = 9.1
            evidence_lines.append("CRITICAL: Resource is also exposed to unauthenticated callers (No Token required)!")

        evidence_str = "\n".join(evidence_lines)

        finding = self.format_finding(
            url=endpoint_url,
            payload=f"User B Token Replay: {token_b[:12]}... (vs User A: {token_a[:12]}...)",
            vulnerable=is_vulnerable,
            title="Broken Object Level Authorization (BOLA / IDOR)",
            severity=severity if is_vulnerable else "Info",
            cvss_score=cvss_score if is_vulnerable else 0.0,
            cwe_id="CWE-639",
            owasp_category="API1:2023-Broken Object Level Authorization",
            evidence=evidence_str,
            remediation=(
                "Implement granular object-level access control checks. Ensure that the authenticated "
                "user session ID or tenant ID strictly matches the owner of the requested object ID before returning data."
            ),
            remediation_code=(
                "# Python / FastAPI Object-Level Permission Pattern\n"
                "from fastapi import Depends, HTTPException, status\n\n"
                "@app.get('/api/v1/orders/{order_id}')\n"
                "async def get_order(order_id: int, current_user: User = Depends(get_current_active_user)):\n"
                "    order = db.query(Order).filter(Order.id == order_id).first()\n"
                "    if not order:\n"
                "        raise HTTPException(status_code=404, detail='Order not found')\n"
                "    if order.owner_id != current_user.id and not current_user.is_admin:\n"
                "        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Unauthorized access to object')\n"
                "    return order"
            ),
            response_time=response_time,
            status_code=status_b,
            extra={
                'status_a': status_a,
                'status_b': status_b,
                'status_anon': status_anon,
                'len_a': len_a,
                'len_b': len_b,
                'method': 'api-http'
            }
        )
        return finding

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None,
             token_a: str = "", token_b: str = "",
             id_variations: Optional[List[str]] = None,
             threads: int = 5, **kwargs) -> Dict[str, Any]:
        """
        Execute BOLA scans across specified API endpoints.
        Supports automatic ID perturbation if endpoints contain numeric or UUID path parameters.
        """
        results = {
            'scan_type': 'BOLA',
            'start_time': time.time(),
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'results': []
        }

        # Generate endpoint list including ID fuzzing variations if provided
        expanded_urls = []
        id_variations = id_variations or []

        for u in urls:
            u_clean = u.strip()
            if not u_clean:
                continue
            expanded_urls.append(u_clean)

            # If user provided specific ID list and URL has an ID pattern (e.g. /100 or ?id=100)
            for var_id in id_variations:
                # Replace trailing digits
                fuzzed = re.sub(r'/(\d+)(/?)$', rf'/{var_id}\2', u_clean)
                if fuzzed != u_clean and fuzzed not in expanded_urls:
                    expanded_urls.append(fuzzed)
                # Replace id query param
                fuzzed_q = re.sub(r'([?&]id=)(\d+)', rf'\g<1>{var_id}', u_clean)
                if fuzzed_q != u_clean and fuzzed_q not in expanded_urls:
                    expanded_urls.append(fuzzed_q)

        session = self.get_session()
        total_work = max(len(expanded_urls), 1)

        with ThreadPoolExecutor(max_workers=min(threads, 10)) as executor:
            future_to_url = {
                executor.submit(self.check_endpoint_bola, url, token_a, token_b, session): url
                for url in expanded_urls
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results['total_scanned'] += 1
                    if result.get('vulnerable'):
                        results['total_found'] += 1
                        results['vulnerable_urls'].append(url)
                    results['results'].append(result)

                    self.notify_progress({
                        'type': 'bola',
                        'current_url': url,
                        'scanned': results['total_scanned'],
                        'total': total_work,
                        'found': results['total_found'],
                        'results': [result]
                    })
                except Exception as e:
                    results['total_scanned'] += 1
                    results['results'].append(self.format_finding(
                        url=url,
                        payload=f"Error executing scan: {str(e)}",
                        vulnerable=False,
                        title="BOLA Scanner",
                        severity="Info",
                        extra={'error': str(e)}
                    ))

        results['end_time'] = time.time()
        results['duration'] = int(results['end_time'] - results['start_time'])
        return results
