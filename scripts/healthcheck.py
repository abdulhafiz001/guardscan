#!/usr/bin/env python3
"""
GuardScan Healthcheck Script
Dynamically tests the active web server port (PORT env var, 3000, or 5000)
Exits with 0 if server is responding, 1 if offline.
"""

import os
import sys
import urllib.request

def check_health():
    env_port = os.environ.get("PORT", "").strip()
    ports_to_test = []
    
    if env_port and env_port.isdigit():
        ports_to_test.append(int(env_port))
    
    for fallback in [3000, 5000]:
        if fallback not in ports_to_test:
            ports_to_test.append(fallback)
            
    for port in ports_to_test:
        url = f"http://127.0.0.1:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "GuardScan-HealthCheck"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status in (200, 301, 302):
                    return True
        except Exception:
            continue
            
    return False

if __name__ == "__main__":
    if check_health():
        sys.exit(0)
    else:
        sys.exit(1)
