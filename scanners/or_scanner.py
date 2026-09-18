"""
Open Redirect (OR) Scanner Plugin for GuardScan
"""

import time
import urllib.parse
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanners.base import BaseScanner


class OpenRedirectScanner(BaseScanner):
    """Scanner plugin for Open URL Redirection"""

    def __init__(self):
        super().__init__(name="Open Redirect Scanner", scan_type="Open Redirect")

    def scan(self, urls: List[str], payloads: Optional[List[str]] = None,
             threads: int = 3, **kwargs) -> Dict[str, Any]:
        """Scan target URLs with Open Redirect payloads"""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from utils.config import Config

        payloads = payloads or []
        results = {
            'scan_type': 'Open Redirect',
            'start_time': time.time(),
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'results': []
        }

        def check_or(url: str, payload: str) -> Optional[dict]:
            target_url = f"{url}{urllib.parse.quote(payload.strip())}"
            raw_payload = payload.strip()
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

                response_time = round(time.time() - start_time, 2)
                page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
                current_url = driver.current_url

                is_vulnerable = False
                redirect_location = None

                # Method 1: Check for Meta Refresh
                if 'http-equiv="refresh"' in driver.page_source.lower() and raw_payload in driver.page_source:
                    is_vulnerable = True
                    redirect_location = "Meta Refresh detected"

                # Method 2: Check if browser actually navigated to payload URL
                cur_decoded = urllib.parse.unquote(current_url).rstrip('/')
                tgt_decoded = urllib.parse.unquote(target_url).rstrip('/')
                url_changed = cur_decoded != tgt_decoded

                if not is_vulnerable and url_changed and raw_payload in current_url:
                    is_vulnerable = True
                    redirect_location = current_url

                # Method 3: Check for open redirect indicators in page
                or_indicators = [
                    'redirecting',
                    'destination:',
                    'redirect to',
                    'unvalidated',
                ]
                if not is_vulnerable and any(ind in page_text for ind in or_indicators):
                    if raw_payload.replace('https://', '').replace('http://', '').lower() in page_text:
                        is_vulnerable = True
                        redirect_location = raw_payload

                results['total_scanned'] += 1
                if is_vulnerable:
                    results['total_found'] += 1
                    results['vulnerable_urls'].append(target_url)

                finding = self.format_finding(
                    url=target_url,
                    payload=raw_payload,
                    vulnerable=is_vulnerable,
                    title="Unvalidated Open Redirect",
                    severity="Medium" if is_vulnerable else "Info",
                    cvss_score=6.1 if is_vulnerable else 0.0,
                    cwe_id="CWE-601",
                    owasp_category="A01:2021-Broken Access Control",
                    evidence=f"Redirect destination observed: {redirect_location}" if is_vulnerable else "",
                    remediation="Validate redirect destinations against a strict internal domain whitelist or relative path verification.",
                    remediation_code=(
                        "# Python/Flask Safe Redirect Whitelist\n"
                        "from urllib.parse import urlparse, urljoin\n"
                        "from flask import request, redirect, abort\n"
                        "def is_safe_url(target):\n"
                        "    ref_url = urlparse(request.host_url)\n"
                        "    test_url = urlparse(urljoin(request.host_url, target))\n"
                        "    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc"
                    ),
                    response_time=response_time,
                    extra={'redirect_location': redirect_location, 'method': 'selenium'}
                )
                return finding

            except Exception as e:
                results['total_scanned'] += 1
                return self.format_finding(
                    url=target_url,
                    payload=raw_payload,
                    vulnerable=False,
                    title="Open Redirect",
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
                futures = [executor.submit(check_or, url, payload) for payload in payloads]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results['results'].append(result)
                        self.notify_progress({
                            'type': 'or',
                            'current_url': url,
                            'scanned': results['total_scanned'],
                            'total': total_work,
                            'found': results['total_found'],
                            'results': [result]
                        })

        results['end_time'] = time.time()
        results['duration'] = int(results['end_time'] - results['start_time'])
        return results
