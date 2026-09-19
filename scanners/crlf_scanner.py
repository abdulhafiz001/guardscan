"""
CRLF Injection / HTTP Response Splitting Scanner Plugin for GuardScan
"""

import time
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.base import BaseScanner


class CRLFScanner(BaseScanner):
    """Scanner plugin for CRLF Injection / HTTP Response Splitting"""

    def __init__(self):
        super().__init__(name="CRLF Scanner", scan_type="CRLF")

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None,
             threads: int = 3, **kwargs) -> Dict[str, Any]:
        """Scan target URLs with CRLF payloads"""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from utils.config import Config

        payloads = payloads or [
            '%0d%0aSet-Cookie:crlf=injection',
            '%0aSet-Cookie:crlf=injection',
            '%0dSet-Cookie:crlf=injection',
            '%0d%0a%0d%0aHTTP/1.1%20200%20OK',
            '%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection',
            '\r\nSet-Cookie:crlf=injection',
            '\nSet-Cookie:crlf=injection',
            '\rSet-Cookie:crlf=injection'
        ]

        results = {
            'scan_type': 'CRLF',
            'start_time': time.time(),
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'results': []
        }

        def check_crlf(url: str, payload: str) -> Optional[dict]:
            target_url = f"{url}{payload}"
            driver = None
            start_time = time.time()

            try:
                driver = Config.create_chrome_driver()
                driver.set_page_load_timeout(15)
                driver.get(target_url)

                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
                time.sleep(0.5)

                response_time = round(time.time() - start_time, 2)
                page_text = driver.find_element(By.TAG_NAME, "body").text.lower()

                crlf_indicators = [
                    'crlf injection',
                    'http response splitting',
                    'header injection',
                    'injected headers',
                    'set-cookie',
                ]

                injected_part = ""
                if "Set-Cookie" in payload:
                    injected_part = "Set-Cookie"

                is_vulnerable = False
                if injected_part and injected_part.lower() in page_text:
                    if any(indicator in page_text for indicator in crlf_indicators):
                        is_vulnerable = True
                elif '%0d%0aHTTP/1.1' in payload and 'HTTP/1.1 200 OK' in page_text:
                    is_vulnerable = True

                results['total_scanned'] += 1
                if is_vulnerable:
                    results['total_found'] += 1
                    results['vulnerable_urls'].append(target_url)

                finding = self.format_finding(
                    url=target_url,
                    payload=payload,
                    vulnerable=is_vulnerable,
                    title="CRLF Injection / HTTP Response Splitting",
                    severity="Medium" if is_vulnerable else "Info",
                    cvss_score=6.5 if is_vulnerable else 0.0,
                    cwe_id="CWE-113",
                    owasp_category="A03:2021-Injection",
                    evidence=f"Injected header/status reflected in response" if is_vulnerable else "",
                    remediation="Strip CR (\\r) and LF (\\n) characters from all user-supplied input before using in HTTP response headers.",
                    remediation_code=(
                        "# Header sanitization in Python\n"
                        "import re\n"
                        "safe_header_value = re.sub(r'[\\r\\n]', '', user_input)\n"
                        "response.headers['X-Custom-Header'] = safe_header_value"
                    ),
                    response_time=response_time,
                    extra={'method': 'selenium'}
                )
                return finding

            except Exception as e:
                results['total_scanned'] += 1
                return self.format_finding(
                    url=target_url,
                    payload=payload,
                    vulnerable=False,
                    title="CRLF Injection",
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
                futures = [executor.submit(check_crlf, url, payload) for payload in payloads]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results['results'].append(result)
                        self.notify_progress({
                            'type': 'crlf',
                            'current_url': url,
                            'scanned': results['total_scanned'],
                            'total': total_work,
                            'found': results['total_found'],
                            'results': [result]
                        })

        results['end_time'] = time.time()
        results['duration'] = int(results['end_time'] - results['start_time'])
        return results
