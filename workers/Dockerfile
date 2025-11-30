FROM python:3.10-slim

# Install system dependencies
# libpcap-dev is required for Naabu
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery Tools (Binaries)
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

# Update Nuclei Templates
RUN nuclei -update-templates

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

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

CMD ["celery", "-A", "src.tasks", "worker", "--loglevel=info"]