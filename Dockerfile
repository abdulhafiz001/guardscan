# Use Python 3.11 slim as base image (pinned to linux/amd64 for Chrome compatibility)
FROM --platform=linux/amd64 python:3.11-slim-bookworm

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
    MODE=web

# Install system dependencies, build tools, Xvfb, gosu, and Google Chrome via official signed repository
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    curl \
    xvfb \
    gosu \
    git \
    build-essential \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libgbm1 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    xdg-utils \
    && install -m 0755 -d /usr/share/keyrings \
    && curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor --yes -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Verify Chrome installation
RUN google-chrome --version

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
