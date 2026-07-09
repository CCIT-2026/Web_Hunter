# CTF A/D Recon Suite — container di analisi
# Build: docker build -t ctf-recon-suite:latest .
# Build (Podman): podman build -t ctf-recon-suite:latest .
#
# Tutti i tool sono installati nell'immagine.
# Il sorgente del servizio viene montato in /service (read-only) a runtime da start.py.
# I report vengono scritti in /reports/<service> (bind-mount verso l'host).

FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/.local/bin:/usr/local/go/bin:/root/go/bin:/opt/tools/bin:${PATH}"
# pip: più tentativi e timeout più lungo per connessioni instabili durante il build
ENV PIP_RETRIES=10
ENV PIP_DEFAULT_TIMEOUT=120

# ── System deps ─────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    git curl wget unzip tar \
    build-essential \
    ruby ruby-dev \
    nodejs npm \
    php php-cli \
    golang-go \
    libxml2-utils \
    exiftool \
    ripgrep \
    jq \
    ca-certificates \
    ssh \
    && rm -rf /var/lib/apt/lists/*

# ── Python tools (solo pacchetti effettivamente su PyPI) ─────────────────────
# ESCLUSI: gitleaks (Go), nuclei (Go), trufflehog (usiamo v3 Go), jwt_tool (no PyPI),
#           sstimap (no PyPI), nodejsscan → si chiama njsscan su PyPI
RUN pip3 install --no-cache-dir --break-system-packages \
    sqlmap \
    semgrep \
    fickling \
    commix \
    njsscan \
    requests \
    pytest \
    jsonschema

# ── ghauri (non è su PyPI — usa setup.py con entry_points, non ha ghauri.py) ─
RUN git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri \
 && pip3 install --no-cache-dir --break-system-packages /opt/ghauri

# ── jwt_tool (non è su PyPI — clona da GitHub) ───────────────────────────────
# retry loop: pycryptodomex (2.3 MB) viene talvolta troncato per instabilità di rete
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
 && for i in 1 2 3 4 5; do \
      pip3 install --no-cache-dir --break-system-packages -r /opt/jwt_tool/requirements.txt \
      && break || { echo "pip retry $i/5..."; sleep 5; }; \
    done \
 && chmod +x /opt/jwt_tool/jwt_tool.py \
 && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# ── SSTImap (non è su PyPI — clona da GitHub) ────────────────────────────────
RUN git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/SSTImap \
 && pip3 install --no-cache-dir --break-system-packages -r /opt/SSTImap/requirements.txt \
 && chmod +x /opt/SSTImap/sstimap.py \
 && ln -sf /opt/SSTImap/sstimap.py /usr/local/bin/sstimap

# ── Go tools (jsluice, grpcurl, gitleaks, nuclei) ────────────────────────────
RUN go install github.com/BishopFox/jsluice/cmd/jsluice@latest \
 && go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest \
 && go install github.com/zricethezav/gitleaks/v8@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ── trufflehog v3 (usa replace directives in go.mod → go install non funziona)
# Soluzione: clona e builda come main module, dove i replace sono validi
RUN git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /opt/trufflehog \
 && cd /opt/trufflehog && go build -o /usr/local/bin/trufflehog . \
 && rm -rf /opt/trufflehog

# ── phpggc ───────────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc \
 && ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc

# ── XXEExploiter ─────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages xxeexploiter 2>/dev/null || \
    git clone --depth 1 https://github.com/luisfontes19/xxeexploiter.git /opt/xxeexploiter \
 && cd /opt/xxeexploiter && pip3 install --no-cache-dir --break-system-packages -e . 2>/dev/null || true

# ── slipit ───────────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages slipit 2>/dev/null || \
    git clone --depth 1 https://github.com/nicowillis/slipit.git /opt/slipit \
 && ln -sf /opt/slipit/slipit.py /usr/local/bin/slipit 2>/dev/null || true

# ── nosqli scanner ───────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages nosqli 2>/dev/null || true

# ── SecLists + other wordlists ───────────────────────────────────────────────
RUN mkdir -p /home/wordlists && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /home/wordlists/SecLists

# ── Assets (payload library + logo) ──────────────────────────────────────────
COPY assets/payloads_all_the_things.json /assets/payloads_all_the_things.json
COPY assets/.logo/ascii_art.txt          /assets/.logo/ascii_art.txt

# ── Suite source ──────────────────────────────────────────────────────────────
COPY orchestrator/     /app/orchestrator/
COPY modules/          /app/modules/
COPY schemas/          /app/schemas/
COPY settings.json     /app/settings.json

WORKDIR /app

# ── Container entrypoint ──────────────────────────────────────────────────────
# Letto da start.py tramite env vars (SERVICE_NAME, SERVICE_ROOT, REPORT_DIR,
# RECON_SETTINGS, opz. SINGLE_MODULE, VERBOSE, DEBUG).
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
