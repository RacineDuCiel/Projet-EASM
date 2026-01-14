# =============================================================================
# Stage 1: Tool Installer - Download and prepare external tools
# =============================================================================
FROM python:3.10-slim AS tools-installer

# Install download tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download ProjectDiscovery Tools (Binaries)
# Using pre-compiled binaries is faster and more reliable than compiling from source.

# Subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip \
    && chmod +x /usr/local/bin/subfinder

# Naabu
RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip \
    && unzip naabu_2.3.1_linux_amd64.zip \
    && mv naabu /usr/local/bin/ \
    && rm naabu_2.3.1_linux_amd64.zip \
    && chmod +x /usr/local/bin/naabu

# Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip \
    && unzip nuclei_3.2.9_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.2.9_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei

# httpx (for technology detection)
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip \
    && unzip -o httpx_1.6.8_linux_amd64.zip \
    && mv httpx /usr/local/bin/ \
    && rm httpx_1.6.8_linux_amd64.zip \
    && chmod +x /usr/local/bin/httpx

# Update Nuclei Templates
RUN nuclei -update-templates

# =============================================================================
# Stage 2: Python Builder - Install Python dependencies
# =============================================================================
FROM python:3.10-slim AS python-builder

WORKDIR /app

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 3: Runtime - Minimal production image
# =============================================================================
FROM python:3.10-slim AS runtime

# Install only runtime dependencies (minimal footprint)
# libpcap0.8 is required for Naabu network scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy tools from builder
COPY --from=tools-installer /usr/local/bin/subfinder /usr/local/bin/
COPY --from=tools-installer /usr/local/bin/naabu /usr/local/bin/
COPY --from=tools-installer /usr/local/bin/nuclei /usr/local/bin/
COPY --from=tools-installer /usr/local/bin/httpx /usr/local/bin/

# Copy nuclei templates
COPY --from=tools-installer /root/nuclei-templates /root/nuclei-templates

# Copy virtual environment from python builder
COPY --from=python-builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy application code
COPY . .

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# TODO: Security hardening for production
# The non-root setup with capabilities causes issues in WSL2/Docker Desktop
# For production on real Linux servers, uncomment the following:
#
# RUN groupadd -r easm-worker && useradd -r -g easm-worker easm-worker
# RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/local/bin/naabu
# RUN chown -R easm-worker:easm-worker /app
# RUN mkdir -p /home/easm-worker/.config && chown -R easm-worker:easm-worker /home/easm-worker
# USER easm-worker
#
# TEMPORARY: Running as root for dev/testing in WSL2/Docker Desktop environment

# Health check for worker process
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD celery -A src.celery_app inspect ping -d celery@$HOSTNAME || exit 1

CMD ["celery", "-A", "src.tasks", "worker", "--loglevel=info"]