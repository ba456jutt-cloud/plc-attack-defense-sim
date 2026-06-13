# Dockerfile
# CPSS Project — Water Treatment Plant Attack Simulation Stack
#
# Builds a container for all Python tools:
#   - Modbus firewall (defense/modbus_firewall.py)
#   - Countermeasures engine (defense/countermeasures.py)
#   - SIS (defense/sis.py)
#   - Physics engine (water_treatment/physics.py)
#   - Dashboard (dashboard/server.py)
#   - Auth proxy (auth_proxy.py)
#   - Attacker tools (attacker/*.py)
#
# OpenPLC Runtime runs in a SEPARATE container (openplc service in
# docker-compose.yml) because it needs its own build environment.
#
# USAGE:
#   docker build -t cpss-tools .
#   docker run --rm cpss-tools python3 attacker/attack_tool.py --help
#
# Or via docker-compose (recommended):
#   docker-compose up
#
# NETWORK NOTE:
#   Inside docker-compose, the PLC is reachable at hostname "openplc"
#   on port 502. The tools container sets PLC_HOST=openplc via environment.
#   This gives us two network-separated "hosts" for lateral movement demo.

FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────────
# libpcap-dev: needed by scapy for raw packet capture
# build-essential: needed by scipy (C extensions)
# libcairo2, pango: needed by weasyprint for PDF report generation
# libgdk-pixbuf-xlib-2.0-0: replaces libgdk-pixbuf2.0-0 (renamed in Debian Trixie)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    build-essential \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    iproute2 \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────────
WORKDIR /app

# ── Install Python dependencies ────────────────────────────────────────────────
# Copy requirements first so Docker caches this layer until requirements change
COPY requirements.txt .
RUN pip install --default-timeout=1000 --retries=10 --no-cache-dir -r requirements.txt

# ── Copy project files ─────────────────────────────────────────────────────────
COPY . .

# ── Create output directories ──────────────────────────────────────────────────
RUN mkdir -p /app/logs /app/evidence /app/results

# ── Environment defaults ───────────────────────────────────────────────────────
# These are overridden by docker-compose environment: blocks per service
ENV PLC_HOST=openplc \
    PLC_PORT=502 \
    OPENPLC_URL=http://openplc:8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ── Default command: run the dashboard ────────────────────────────────────────
# Override in docker-compose per-service or via docker run command
CMD ["python3", "dashboard/server.py"]