FROM python:3.12-slim

ARG TRIVY_VERSION=0.76.1
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.7.0
ARG SEMGREP_VERSION=1.182.1

RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Scanner binaries from official releases (pinned)
RUN set -eux; arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) T=Linux-64bit; G=linux_x64; O=linux_amd64 ;; arm64) T=Linux-ARM64; G=linux_arm64; O=linux_arm64 ;; esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${T}.tar.gz" | tar -xz -C /usr/local/bin trivy; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${G}.tar.gz" | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${O}"; \
    chmod 0755 /usr/local/bin/trivy /usr/local/bin/gitleaks /usr/local/bin/osv-scanner

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

COPY . .

# Unprivileged runtime user; scanners inherit it.
RUN useradd --create-home --uid 10001 trace && mkdir -p /app/storage && chown -R trace /app/storage
USER trace

ENV TOOLS_DIR=/usr/local/bin PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fs http://localhost:${PORT:-8000}/health || exit 1
# PORT is set by hosts such as Render; 8000 otherwise.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
