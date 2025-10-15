FROM python:3.10-slim

WORKDIR /app

# ---- Versions (override at build time if you want) ----
ARG GITLEAKS_VERSION=8.18.4   # set to a known good release to avoid API/rate limit
# -------------------------------------------------------

# Install system deps, add Trivy repo (with keyrings), install Trivy + Gitleaks + Trufflehog
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget gnupg lsb-release git; \
    \
    # --- Trivy repo (keyrings, no apt-key) ---
    install -m 0755 -d /etc/apt/keyrings; \
    curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg; \
    chmod 0644 /etc/apt/keyrings/trivy.gpg; \
    echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
      > /etc/apt/sources.list.d/trivy.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends trivy; \
    \
    # (optional) prefetch DBs so first run is fast
    trivy fs --download-db-only || true; \
    trivy fs --download-java-db-only || true; \
    \
    # --- Gitleaks (static binary) ---
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64)  gl_arch=linux_x64 ;; \
      arm64)  gl_arch=linux_arm64 ;; \
      armhf)  gl_arch=linux_armv6 ;; \
      *) echo "Unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${gl_arch}.tar.gz"; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks.tgz; \
    gitleaks version; \
    \
    # --- TruffleHog ---
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
      | sh -s -- -b /usr/local/bin; \
    trufflehog --version; \
    \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# Copy source
COPY . .

# Python deps
RUN pip install --no-cache-dir -r requirements.txt

ENV FLASK_APP=run.py
ENV FLASK_ENV=production

RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
