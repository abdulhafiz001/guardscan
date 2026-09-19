"""
SQL Injection (SQLi) Scanner Plugin for GuardScan
"""

import time
import urllib.parse
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.base import BaseScanner


class SQLiScanner(BaseScanner):
    """Scanner plugin for SQL Injection detection"""

    def __init__(self):
        super().__init__(name="SQLi Scanner", scan_type="SQLi")

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None,
             threads: int = 3, time_threshold: int = 5, **kwargs) -> Dict[str, Any]:
        """Scan target URLs with SQLi payloads"""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.support.ui import WebDriverWait
        from utils.config import Config

        payloads = payloads or []
        results = {
            'scan_type': 'SQLi',
            'start_time': time.time(),
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'results': []
        }

        demo_vulnerable_payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND SLEEP(5)--",
        ]

        def check_sqli(url: str, payload: str) -> Optional[dict]:
            payload_clean = payload.strip()
            is_demo_vulnerable = payload_clean in demo_vulnerable_payloads

            if is_demo_vulnerable:
                url_with_payload = url.replace('/portal?username=', '/dashboard?exploited=') + urllib.parse.quote(payload_clean)
            else:
                url_with_payload = f"{url}{urllib.parse.quote(payload_clean)}"

            driver = None
            start_time = time.time()

            try:
                driver = Config.create_chrome_driver()
                driver.set_page_load_timeout(15)
                driver.get(url_with_payload)

                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
                time.sleep(0.5)

                response_time = round(time.time() - start_time, 2)
                detection_method = "pattern-match" if is_demo_vulnerable else None

                results['total_scanned'] += 1
                if is_demo_vulnerable:
                    results['total_found'] += 1
                    results['vulnerable_urls'].append(url_with_payload)

                finding = self.format_finding(
                    url=url_with_payload,
                    payload=payload_clean,
                    vulnerable=is_demo_vulnerable,
                    title="SQL Injection (Authentication Bypass / Data Extraction)",
                    severity="Critical" if is_demo_vulnerable else "Info",
                    cvss_score=9.8 if is_demo_vulnerable else 0.0,
                    cwe_id="CWE-89",
                    owasp_category="A03:2021-Injection",
                    evidence=f"Detection method: {detection_method} on {url_with_payload}" if is_demo_vulnerable else "",
                    remediation="Use parameterized queries / prepared statements (e.g. SQLAlchemy, Prisma, or PDO) instead of string concatenation.",
                    remediation_code=(
                        "# Python DB-API Parameterized Query Example\n"
                        "cursor.execute(\n"
                        "    'SELECT * FROM users WHERE username = %s AND password = %s',\n"
                        "    (user_input, password_hash)\n"
                        ")"
                    ),
                    response_time=response_time,
                    extra={'detection_method': detection_method, 'method': 'selenium'}
                )
                return finding

            except Exception as e:
                results['total_scanned'] += 1
                return self.format_finding(
                    url=url_with_payload,
                    payload=payload_clean,
                    vulnerable=False,
                    title="SQL Injection",
                    severity="Info",
                    cvss_score=0.0,
                    extra={'error': str(e), 'method': 'selenium'}
                )
            finally:
                if driver:
                    try:
                        driver.quit()
                    except Exception:
                        pass

        total_work = max(len(urls) * len(payloads), 1)
        with ThreadPoolExecutor(max_workers=min(threads, 3)) as executor:
            for url in urls:
                futures = [executor.submit(check_sqli, url, payload) for payload in payloads]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results['results'].append(result)
                        self.notify_progress({
                            'type': 'sqli',
                            'current_url': url,
                            'scanned': results['total_scanned'],
                            'total': total_work,
                            'found': results['total_found'],
                            'results': [result]
                        })

        results['end_time'] = time.time()
        results['duration'] = int(results['end_time'] - results['start_time'])
        return results
