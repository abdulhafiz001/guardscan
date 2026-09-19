# Multi-architecture base image (supports both amd64 and arm64 without platform warnings)
FROM python:3.11-slim-bookworm

# Metadata
LABEL maintainer="zahidoverflow"
LABEL description="GuardScan - Web Vulnerability Scanner & Security Operations Dashboard"
LABEL version="2.5"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:99 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    MODE=web \
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver

# Install system dependencies, Chromium, ChromeDriver, and Xvfb
# Note: Debian Bookworm provides chromium and chromium-driver natively for both amd64 and arm64
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    gnupg \
    unzip \
    xvfb \
    gosu \
    git \
    build-essential \
    ca-certificates \
    fonts-liberation \
    chromium \
    chromium-driver \
    libnss3 \
    libgbm1 \
    libasound2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && ln -sf /usr/bin/chromium /usr/bin/google-chrome \
    && ln -sf /usr/bin/chromium /usr/bin/chrome \
    && ln -sf /usr/bin/chromedriver /usr/local/bin/chromedriver

# Verify Chromium and ChromeDriver installation
RUN chromium --version && chromedriver --version

# Set working directory
WORKDIR /app

# Copy and install Python dependencies first (layer caching)
COPY requirements.txt .

RUN pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Copy application modules and source files
COPY app.py scanner_cli.py ./
COPY scripts/ ./scripts/
COPY payloads/ ./payloads/
COPY core/ ./core/
COPY utils/ ./utils/
COPY web/ ./web/
COPY scanners/ ./scanners/

# Create non-root user and persistent directories
RUN useradd -m -u 1000 scanner \
    && mkdir -p /app/output /app/reports /home/scanner/.cache \
    && chown -R scanner:scanner /app /home/scanner \
    && chmod -R 777 /app/output /app/reports \
    && chmod +x scripts/*.sh 2>/dev/null || true

# Expose port for web interface
EXPOSE 5000

# Healthcheck for Coolify / Docker monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/ || python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/')" || exit 1

# Entrypoint manages Xvfb and runs as non-root user
ENTRYPOINT ["/bin/bash", "/app/scripts/docker-entrypoint.sh"]
