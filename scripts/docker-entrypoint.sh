#!/bin/bash
set -e

# Ensure permissions on persistent volumes (needed for Coolify volume mounts)
mkdir -p /app/reports /app/output /home/scanner/.cache
chown -R scanner:scanner /app/reports /app/output /home/scanner 2>/dev/null || chmod -R 777 /app/reports /app/output /home/scanner 2>/dev/null || true

# Start Xvfb virtual framebuffer for headless browser testing
Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset > /dev/null 2>&1 &
sleep 1

# If command passed as argument, run it
if [ $# -gt 0 ]; then
    if [ "$(id -u)" = "0" ]; then
        exec gosu scanner "$@"
    else
        exec "$@"
    fi
fi

# Default: check MODE environment variable
if [ "$MODE" = "cli" ]; then
    if [ "$(id -u)" = "0" ]; then
        exec gosu scanner python3 scanner_cli.py
    else
        exec python3 scanner_cli.py
    fi
else
    # Default is web mode for Coolify / production PaaS deployment
    if [ "$(id -u)" = "0" ]; then
        exec gosu scanner python3 app.py
    else
        exec python3 app.py
    fi
fi
