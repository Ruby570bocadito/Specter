# T-100AI - AI-Powered Offensive Security Terminal
# Multi-stage build: Kali Linux base + Python app
# Ollama runs separately (host or separate container)

# ── Stage 1: Build dependencies ──────────────────────────────────────────
FROM kalilinux/kali-rolling AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    gcc g++ libffi-dev libssl-dev pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV VIRTUAL_ENV=/opt/t100ai-venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev,ollama,export,workflows]"

COPY src/ src/
COPY tests/ tests/
COPY .github/ .github/
RUN pip install --no-cache-dir -e .

# ── Stage 2: Runtime ─────────────────────────────────────────────────────
FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    nmap masscan rustscan \
    gobuster ffuf nikto nuclei httpx \
    dnsrecon subfinder amass \
    whois curl wget theharvester \
    sqlmap \
    crackmapexec impacket-scripts kerbrute \
    git jq net-tools iputils-ping traceroute dnsutils \
    exiftool binwalk \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/t100ai-venv /opt/t100ai-venv
ENV PATH="/opt/t100ai-venv/bin:$PATH"

RUN groupadd -r t100ai && useradd -r -g t100ai -d /home/t100ai -s /bin/bash t100ai \
    && mkdir -p /home/t100ai \
    && chown -R t100ai:t100ai /home/t100ai

WORKDIR /app

RUN mkdir -p /app/sessions /app/plugins /app/output /app/logs \
    && chown -R t100ai:t100ai /app

COPY --from=builder /build/src/ /app/src/
COPY --from=builder /build/tests/ /app/tests/
COPY --from=builder /build/.github/ /app/.github/
COPY pyproject.toml /app/

ENV T100AI_OLLAMA_HOST=http://host.docker.internal:11434
ENV T100AI_DATA_DIR=/app
ENV PYTHONUNBUFFERED=1

USER t100ai

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

ENTRYPOINT ["python", "-m", "t100ai.cli.main"]
CMD []
