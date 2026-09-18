"""
Localized / Payment Gateway Scanner Plugin
Probes fintech & e-commerce endpoints for missing cryptographic signature verification (Paystack, Flutterwave, Monnify),
unverified webhook acceptance, and price/currency tampering vulnerabilities.
"""

import time
import json
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.base import BaseScanner


class GatewayScanner(BaseScanner):
    """
    Scanner plugin for Nigerian & African Fintech Gateway Integrations
    Tests webhook verification, signature bypasses, and currency tampering.
    """

    def __init__(self):
        super().__init__(name="Payment Gateway Scanner", scan_type="Gateway")

    def load_gateway_payloads(self) -> List[Dict[str, Any]]:
        """Load localized gateway vulnerability test vectors"""
        payload_file = Path(__file__).parent.parent / "payloads" / "gateway_payloads.json"
        if not payload_file.exists():
            return []
        try:
            with open(payload_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def check_gateway_vector(self,
                             url: str,
                             vector: Dict[str, Any],
                             session: Optional[requests.Session] = None) -> Dict[str, Any]:
        """Test a specific webhook or checkout endpoint against a gateway vector"""
        session = session or self.get_session()
        start_time = time.time()

        method = vector.get("method", "POST").upper()
        headers = dict(vector.get("headers", {}))
        headers["User-Agent"] = self.get_random_user_agent()
        body = vector.get("body", {})

        is_vulnerable = False
        evidence_lines = []
        status_code = None
        resp_text = ""

        try:
            if method == "POST":
                resp = session.post(url, headers=headers, json=body, timeout=12, allow_redirects=False)
            elif method == "GET":
                resp = session.get(url, headers=headers, params=body, timeout=12, allow_redirects=False)
            else:
                resp = session.request(method, url, headers=headers, json=body, timeout=12, allow_redirects=False)

            status_code = resp.status_code
            resp_text = resp.text
            response_time = round(time.time() - start_time, 2)

            vuln_statuses = vector.get("vuln_indicator_status", [200])
            expected_safe = vector.get("expected_safe_statuses", [400, 401, 403])

            if status_code in vuln_statuses:
                # Further inspect body: check if it's an error page disguised as 200
                is_err = False
                try:
                    data = resp.json()
                    status_val = str(data.get("status", "")).lower()
                    if status_val in ["error", "fail", "failed", "unauthorized", "invalid"]:
                        is_err = True
                    msg = str(data.get("message", "")).lower()
                    if any(term in msg for term in ["signature", "unauthorized", "invalid", "forbidden"]):
                        is_err = True
                except Exception:
                    pass

                if not is_err:
                    is_vulnerable = True
                    evidence_lines.append(f"Endpoint responded with HTTP {status_code} to unverified/forged payload.")
                    evidence_lines.append(f"Attack Vector: {vector.get('name')}")
                    evidence_lines.append(f"Response Excerpt: {resp_text[:150]}")
                else:
                    evidence_lines.append(f"HTTP 200 returned but rejected with application-level signature error message.")
            else:
                evidence_lines.append(f"Endpoint safely rejected test with HTTP {status_code} (Expected safe: {expected_safe})")

        except Exception as e:
            response_time = round(time.time() - start_time, 2)
            return self.format_finding(
                url=url,
                payload=vector.get("name", "Gateway Test"),
                vulnerable=False,
                title="Payment Gateway Verification",
                severity="Info",
                cvss_score=0.0,
                extra={"error": str(e), "category": vector.get("category")}
            )

        category = vector.get("category", "Webhook Insecurity")
        severity = "Critical" if "Signature" in category or "Webhook" in category else "High"
        cvss = 9.3 if severity == "Critical" else 8.2

        finding = self.format_finding(
            url=url,
            payload=f"{vector.get('name')} [{vector.get('gateway', 'general').upper()}]",
            vulnerable=is_vulnerable,
            title=f"Fintech Gateway Flaw: {vector.get('name')}",
            severity=severity if is_vulnerable else "Info",
            cvss_score=cvss if is_vulnerable else 0.0,
            cwe_id="CWE-347",
            owasp_category="A02:2021-Cryptographic Failures",
            evidence="\n".join(evidence_lines),
            remediation=(
                "Compute and verify cryptographic signatures on raw webhook bodies prior to parsing. "
                "For Paystack, verify HMAC-SHA512 using your secret key against the 'x-paystack-signature' header. "
                "For Flutterwave, verify the 'verif-hash' header matches your secret hash."
            ),
            remediation_code=(
                "# Paystack Webhook Verification in Python (Flask/FastAPI)\n"
                "import hmac, hashlib\n"
                "def verify_paystack_webhook(request_body_bytes, signature_header, secret_key):\n"
                "    expected_sig = hmac.new(\n"
                "        secret_key.encode('utf-8'),\n"
                "        request_body_bytes,\n"
                "        hashlib.sha512\n"
                "    ).hexdigest()\n"
                "    return hmac.compare_digest(expected_sig, signature_header)"
            ),
            response_time=response_time,
            status_code=status_code,
            extra={
                "gateway": vector.get("gateway"),
                "category": category,
                "method": "gateway-probe"
            }
        )
        return finding

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None,
             threads: int = 5, **kwargs) -> Dict[str, Any]:
        """Scan webhook and checkout endpoints for gateway vulnerabilities"""
        vectors = self.load_gateway_payloads()
        results = {
            'scan_type': 'Gateway',
            'start_time': time.time(),
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'results': []
        }

        total_work = max(len(urls) * len(vectors), 1)
        session = self.get_session()

        with ThreadPoolExecutor(max_workers=min(threads, 8)) as executor:
            future_to_task = {}
            for url in urls:
                for vector in vectors:
                    f = executor.submit(self.check_gateway_vector, url.strip(), vector, session)
                    future_to_task[f] = (url, vector)

            for future in as_completed(future_to_task):
                url, vector = future_to_task[future]
                try:
                    res = future.result()
                    results['total_scanned'] += 1
                    if res.get('vulnerable'):
                        results['total_found'] += 1
                        results['vulnerable_urls'].append(url)
                    results['results'].append(res)

                    self.notify_progress({
                        'type': 'gateway',
                        'current_url': url,
                        'scanned': results['total_scanned'],
                        'total': total_work,
                        'found': results['total_found'],
                        'results': [res]
                    })
                except Exception as e:
                    results['total_scanned'] += 1
                    results['results'].append(self.format_finding(
                        url=url,
                        payload=vector.get('name', 'Gateway Probe'),
                        vulnerable=False,
                        title="Gateway Scanner",
                        severity="Info",
                        extra={'error': str(e)}
                    ))

        results['end_time'] = time.time()
        results['duration'] = int(results['end_time'] - results['start_time'])
        return results
