"""
Cross-Site Scripting (XSS) Scanner Plugin for GuardScan
"""

import time
import urllib.parse
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.base import BaseScanner


class XSSScanner(BaseScanner):
    """Scanner plugin for Cross-Site Scripting (Reflected & DOM XSS)"""

    def __init__(self):
        super().__init__(name="XSS Scanner", scan_type="XSS")

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None,
             threads: int = 3, **kwargs) -> Dict[str, Any]:
        """Scan target URLs with XSS payloads"""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.common.exceptions import TimeoutException
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from utils.config import Config

        payloads = payloads or []
        results = {
            'scan_type': 'XSS',
            'start_time': time.time(),
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'results': []
        }

        def check_xss(url: str, payload: str) -> Optional[dict]:
            target_url = f"{url}{urllib.parse.quote(payload.strip())}"
            driver = None
            is_vulnerable = False
            start_time = time.time()

            try:
                driver = Config.create_chrome_driver()
                driver.set_page_load_timeout(10)
                driver.get(target_url)

                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
                time.sleep(0.5)

                try:
                    WebDriverWait(driver, 2).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    alert.accept()
                    is_vulnerable = True
                except TimeoutException:
                    page_source = driver.page_source
                    payload_clean = payload.strip()
                    if payload_clean in page_source:
                        is_vulnerable = True
                    elif any(pattern in page_source.lower() for pattern in [
                        'onerror=', 'onload=', 'onclick=', 'onmouseover=',
                        '<script>', '<img src=x', '<svg onload', '<body onload',
                        'javascript:', 'alert(', 'confirm(', 'prompt('
                    ]):
                        if 'src=x' in page_source or 'onerror=' in page_source.lower():
                            is_vulnerable = True

                response_time = round(time.time() - start_time, 2)
                results['total_scanned'] += 1
                if is_vulnerable:
                    results['total_found'] += 1
                    results['vulnerable_urls'].append(target_url)

                finding = self.format_finding(
                    url=target_url,
                    payload=payload.strip(),
                    vulnerable=is_vulnerable,
                    title="Cross-Site Scripting (XSS)",
                    severity="High" if is_vulnerable else "Info",
                    cvss_score=7.1 if is_vulnerable else 0.0,
                    cwe_id="CWE-79",
                    owasp_category="A03:2021-Injection",
                    evidence=f"Payload reflected/executed: {payload.strip()[:100]}" if is_vulnerable else "",
                    remediation="Contextually encode all untrusted output (HTML, attribute, JS contexts) and enforce a strong Content Security Policy (CSP).",
                    remediation_code=(
                        "# Python / Jinja2 Contextual Escaping\n"
                        "from markupsafe import escape\n"
                        "safe_output = escape(user_input)\n"
                        "# HTTP Header CSP\n"
                        "Content-Security-Policy: default-src 'self'; script-src 'self'"
                    ),
                    response_time=response_time,
                    extra={'method': 'selenium'}
                )
                return finding

            except Exception as e:
                results['total_scanned'] += 1
                return self.format_finding(
                    url=target_url,
                    payload=payload.strip(),
                    vulnerable=False,
                    title="Cross-Site Scripting",
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
                futures = [executor.submit(check_xss, url, payload) for payload in payloads]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results['results'].append(result)
                        self.notify_progress({
                            'type': 'xss',
                            'current_url': url,
                            'scanned': results['total_scanned'],
                            'total': total_work,
                            'found': results['total_found'],
                            'results': [result]
                        })

        results['end_time'] = time.time()
        results['duration'] = int(results['end_time'] - results['start_time'])
        return results
