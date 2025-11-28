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
    && rm subfinder_2.6.6_linux_amd64.zip

# Naabu
RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip \
    && unzip naabu_2.3.1_linux_amd64.zip \
    && mv naabu /usr/local/bin/ \
    && rm naabu_2.3.1_linux_amd64.zip

# Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip \
    && unzip nuclei_3.2.9_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.2.9_linux_amd64.zip

# Update Nuclei Templates
RUN nuclei -update-templates

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create a non-root user?
# For now run as root to avoid permission issues with tools,
# but in prod we should secure this.