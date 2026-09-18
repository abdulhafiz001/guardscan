"""
Local File Inclusion (LFI) Scanner Plugin for GuardScan
Supports both headless browser DOM-based detection and fast HTTP requests.
"""

import time
import urllib.parse
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.base import BaseScanner


class LFIScanner(BaseScanner):
    """Scanner plugin for Local File Inclusion and Path Traversal"""

    def __init__(self):
        super().__init__(name="LFI Scanner", scan_type="LFI")

    @staticmethod
    def _is_already_encoded(payload: str) -> bool:
        import re
        return bool(re.search(r'%[0-9a-fA-F]{2}', payload))

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None,
             success_criteria: Optional[List[str]] = None, threads: int = 3, **kwargs) -> Dict[str, Any]:
        """Scan target URLs with LFI payloads"""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from utils.config import Config

        payloads = payloads or []
        success_criteria = success_criteria or ['root:x:0:']
        
        results = {
            'scan_type': 'LFI',
            'start_time': time.time(),
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'results': []
        }

        def check_lfi(url: str, payload: str) -> Optional[dict]:
            payload_clean = payload.strip()
            if self._is_already_encoded(payload_clean):
                encoded_payload = payload_clean
            else:
                encoded_payload = urllib.parse.quote(payload_clean)

            target_url = f"{url}{encoded_payload}"
            driver = None
            start_time = time.time()

            try:
                chrome_options = Options()
                for arg in Config.CHROME_OPTIONS:
                    chrome_options.add_argument(arg)

                driver = webdriver.Chrome(options=chrome_options)
                driver.set_page_load_timeout(15)
                driver.get(target_url)

                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
                time.sleep(0.5)

                pre_content = ""
                try:
                    pre_elements = driver.find_elements(By.TAG_NAME, "pre")
                    if pre_elements:
                        pre_content = pre_elements[0].text
                except Exception:
                    pass

                response_time = round(time.time() - start_time, 2)
                is_vulnerable = bool(pre_content and 'file not found:' not in pre_content.lower())
                if is_vulnerable and len(pre_content.strip()) < 10:
                    is_vulnerable = False
                if is_vulnerable and 'no file specified' in pre_content.lower():
                    is_vulnerable = False

                results['total_scanned'] += 1
                if is_vulnerable:
                    results['total_found'] += 1
                    results['vulnerable_urls'].append(target_url)

                finding = self.format_finding(
                    url=target_url,
                    payload=payload_clean,
                    vulnerable=is_vulnerable,
                    title="Local File Inclusion / Path Traversal",
                    severity="High" if is_vulnerable else "Info",
                    cvss_score=7.5 if is_vulnerable else 0.0,
                    cwe_id="CWE-22",
                    owasp_category="A01:2021-Broken Access Control",
                    evidence=pre_content[:200] if is_vulnerable else "",
                    remediation="Validate user input against an explicit whitelist of allowed file names. Use basename() and avoid direct path concatenation.",
                    remediation_code=(
                        "# Python/Flask Path Normalization\n"
                        "import os\n"
                        "filename = os.path.basename(user_input)\n"
                        "safe_path = os.path.abspath(os.path.join(ALLOWED_DIR, filename))\n"
                        "if not safe_path.startswith(ALLOWED_DIR):\n"
                        "    abort(403)"
                    ),
                    response_time=response_time,
                    extra={'content_length': len(pre_content), 'method': 'selenium'}
                )
                return finding

            except Exception as e:
                results['total_scanned'] += 1
                return self.format_finding(
                    url=target_url,
                    payload=payload_clean,
                    vulnerable=False,
                    title="Local File Inclusion",
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
                futures = [executor.submit(check_lfi, url, payload) for payload in payloads]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results['results'].append(result)
                        self.notify_progress({
                            'type': 'lfi',
                            'current_url': url,
                            'scanned': results['total_scanned'],
                            'total': total_work,
                            'found': results['total_found'],
                            'results': [result]
                        })

        results['end_time'] = time.time()
        results['duration'] = int(results['end_time'] - results['start_time'])
        return results
