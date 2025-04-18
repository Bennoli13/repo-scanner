FROM python:3.10-slim

WORKDIR /app

# Install system dependencies & Trivy
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl ca-certificates git wget gnupg lsb-release apt-transport-https && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y trivy && \
    trivy fs --download-db-only && \
    trivy fs --download-java-db-only && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

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
