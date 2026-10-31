# TRACE API on a Hugging Face Docker Space (free CPU: 2 vCPU, 16 GB RAM, no card required).
#
# The Space only holds this Dockerfile and README.md: the build clones the public GitHub repo,
# so a "Factory rebuild" in the Space settings deploys the latest `main`.
# Keep the scanner versions in step with backend/Dockerfile.
FROM python:3.12-slim

ARG REPO=https://github.com/atique-ahmad-01/trace.git
ARG REF=main
ARG TRIVY_VERSION=0.76.1
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.7.0
ARG SEMGREP_VERSION=1.182.1

RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) T=Linux-64bit; G=linux_x64; O=linux_amd64 ;; arm64) T=Linux-ARM64; G=linux_arm64; O=linux_arm64 ;; esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${T}.tar.gz" | tar -xz -C /usr/local/bin trivy; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${G}.tar.gz" | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${O}"; \
    chmod 0755 /usr/local/bin/trivy /usr/local/bin/gitleaks /usr/local/bin/osv-scanner

# Spaces run the container as uid 1000.
RUN useradd --create-home --uid 1000 trace

RUN git clone --depth 1 --branch "${REF}" "${REPO}" /src && mv /src/backend /app && rm -rf /src
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && mkdir -p /app/storage && chown -R trace /app/storage

USER trace
ENV TOOLS_DIR=/usr/local/bin PYTHONUNBUFFERED=1 PORT=7860 HOME=/home/trace
EXPOSE 7860
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
