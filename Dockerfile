# ==============================================================================
# V10 Autonomous Bug Hunter Platform - Enterprise Container Image
# Pre-packaged with official pre-compiled industry-standard bug hunting binaries:
# Subfinder, Katana, HTTPX, Naabu, Nuclei, FFUF, GAU, Waybackurls, TruffleHog,
# Nmap, Dirsearch, Arjun, Python 3.11 FastAPI Backend, and Web Frontend.
# ==============================================================================

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:${PATH}"

WORKDIR /app

# 1. Install Essential System Packages, Network Recon Tools, and Extraction Utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    tar \
    unzip \
    nmap \
    dnsutils \
    iputils-ping \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Python Dependencies & Python Security Packages (Dirsearch, Arjun)
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install dirsearch arjun

# 3. Install Pre-Compiled Official Security Binaries (Fast, Zero-Compile Overhead)
RUN mkdir -p /tmp/tools && cd /tmp/tools && \
    # Subfinder (ProjectDiscovery)
    curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_linux_amd64.zip -o subfinder.zip && \
    unzip -q subfinder.zip -d /tmp/subfinder && mv /tmp/subfinder/subfinder /usr/local/bin/ && \
    # Katana (ProjectDiscovery)
    curl -sL https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip -o katana.zip && \
    unzip -q katana.zip -d /tmp/katana && mv /tmp/katana/katana /usr/local/bin/ && \
    # Naabu (ProjectDiscovery)
    curl -sL https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip -o naabu.zip && \
    unzip -q naabu.zip -d /tmp/naabu && mv /tmp/naabu/naabu /usr/local/bin/ && \
    # Nuclei (ProjectDiscovery)
    curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_amd64.zip -o nuclei.zip && \
    unzip -q nuclei.zip -d /tmp/nuclei && mv /tmp/nuclei/nuclei /usr/local/bin/ && \
    # FFUF
    curl -sL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o ffuf.tar.gz && \
    tar -xzf ffuf.tar.gz -C /tmp && mv /tmp/ffuf /usr/local/bin/ && \
    # GAU (GetAllUrls)
    curl -sL https://github.com/lc/gau/releases/download/v2.2.3/gau_2.2.3_linux_amd64.tar.gz -o gau.tar.gz && \
    tar -xzf gau.tar.gz -C /tmp && mv /tmp/gau /usr/local/bin/ && \
    # Waybackurls
    curl -sL https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz -o waybackurls.tgz && \
    tar -xzf waybackurls.tgz -C /tmp && mv /tmp/waybackurls /usr/local/bin/ && \
    # TruffleHog
    curl -sL https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.0/trufflehog_3.82.0_linux_amd64.tar.gz -o trufflehog.tar.gz && \
    tar -xzf trufflehog.tar.gz -C /tmp && mv /tmp/trufflehog /usr/local/bin/ && \
    # HTTPX (ProjectDiscovery) - Overwrites python httpx CLI stub
    curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip -o httpx.zip && \
    unzip -q httpx.zip -d /tmp/httpx && mv /tmp/httpx/httpx /usr/local/bin/httpx && \
    ln -sf /usr/local/bin/httpx /usr/local/bin/pd-httpx && \
    # Cleanup temporary downloads
    rm -rf /tmp/tools /tmp/subfinder /tmp/katana /tmp/httpx /tmp/naabu /tmp/nuclei && \
    chmod +x /usr/local/bin/*

# 4. Create Storage & Quarantine Volumes
RUN mkdir -p /app/storage/quarantine /app/storage/artifacts /app/data /app/wordlists /app/logs

# 5. Copy Application Source Code, Frontend, and Wordlists
COPY app /app/app
COPY frontend /app/frontend
COPY wordlists /app/wordlists

# Expose Web & API Port
EXPOSE 9001

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9001/api/health || exit 1

# Default Launch Command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9001"]