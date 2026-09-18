# Use Python 3.11 slim as base image
FROM python:3.11-slim

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

# Install system dependencies & gosu for volume permission handling
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    curl \
    xvfb \
    gosu \
    fonts-liberation \
    libnss3 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libatspi2.0-0 \
    libwayland-client0 \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Google Chrome
RUN wget -q -O /tmp/google-chrome-stable_current_amd64.deb \
    https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/google-chrome-stable_current_amd64.deb \
    && rm /tmp/google-chrome-stable_current_amd64.deb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Verify Chrome installation
RUN google-chrome --version

# Set working directory
WORKDIR /app

# Copy and install Python dependencies first (layer caching)
COPY requirements-docker.txt .

RUN pip install --upgrade pip==24.3.1 setuptools==75.6.0 wheel==0.45.1 \
    && pip install --no-cache-dir -r requirements-docker.txt \
    && pip list

# Copy application modules and source files
COPY app.py scanner_cli.py ./
COPY scripts/ ./scripts/
COPY payloads/ ./payloads/
COPY core/ ./core/
COPY utils/ ./utils/
COPY web/ ./web/
COPY scanners/ ./scanners/
COPY bin/chromedriver-linux64/ /usr/local/bin/

# Create non-root user and persistent directories
RUN useradd -m -u 1000 scanner \
    && mkdir -p /app/output /app/reports /home/scanner/.cache \
    && chown -R scanner:scanner /app /home/scanner \
    && chmod -R 777 /app/output /app/reports \
    && chmod +x scripts/*.sh 2>/dev/null || true \
    && if [ -f /usr/local/bin/chromedriver ]; then chmod +x /usr/local/bin/chromedriver; fi

# Expose port for web interface
EXPOSE 5000

# Healthcheck for Coolify / Docker monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/ || python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/')" || exit 1

# Entrypoint manages Xvfb and runs as non-root user
ENTRYPOINT ["/bin/bash", "/app/scripts/docker-entrypoint.sh"]
