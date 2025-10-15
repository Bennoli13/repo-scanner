FROM python:3.10-slim

WORKDIR /app

# Install system dependencies & Trivy
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl ca-certificates git wget gnupg lsb-release apt-transport-https && \
    \
    # --- Install Trivy ---
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y trivy && \
    trivy fs --download-db-only && \
    trivy fs --download-java-db-only && \
    \
    # --- Install Gitleaks (official binary from GitHub) ---
    GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    curl -sSL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    \
    # --- Install TruffleHog ---
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin && \
    \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Environment
ENV FLASK_APP=run.py
ENV FLASK_ENV=production

# Entry point
RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
