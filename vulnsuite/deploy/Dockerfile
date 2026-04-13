# VulnSuite — production image
#
# Bakes in every scanner binary the worker queue may invoke, so the
# Celery worker container can run any collector without runtime fetches.
# The same image runs API, worker, beat, and dashboard — the command in
# docker-compose selects the role.
#
# Build:  docker build -t vulnsuite:latest -f deploy/Dockerfile .
# Size budget: ~2.5GB. If you need slimmer images for API/dashboard,
# split this into a base+scanner-tools image and a base-only image.
#
# Reproducibility: pin every binary version below. Bumps need a
# corresponding security review and dependency-graph diff.

# ---------- 1) Builder: pull pinned scanner binaries ----------
FROM debian:bookworm-slim AS scanners

ARG TRIVY_VERSION=0.50.1
ARG GITLEAKS_VERSION=8.18.2
ARG OSV_SCANNER_VERSION=1.7.4
ARG TRUFFLEHOG_VERSION=3.74.0
ARG DOCKLE_VERSION=0.4.14
ARG KUBESCAPE_VERSION=3.0.8
ARG SUBFINDER_VERSION=2.6.6
ARG HTTPX_VERSION=1.6.5
ARG NUCLEI_VERSION=3.2.4
ARG SYFT_VERSION=1.2.0
ARG COSIGN_VERSION=2.2.4
ARG ZAP_VERSION=2.15.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl tar unzip gnupg jq xz-utils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /scanners
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) gh_arch=Linux_64bit; alt_arch=linux_amd64;; \
                    arm64) gh_arch=Linux_arm64;  alt_arch=linux_arm64;; \
                    *) echo "unsupported arch: $arch"; exit 1;; esac; \
    # Trivy
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${gh_arch}.tar.gz" | tar -xz -C /usr/local/bin trivy; \
    # gitleaks
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${alt_arch//_/_}.tar.gz" | tar -xz -C /usr/local/bin gitleaks; \
    # osv-scanner
    curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${alt_arch}"; \
    chmod +x /usr/local/bin/osv-scanner; \
    # trufflehog
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${alt_arch}.tar.gz" | tar -xz -C /usr/local/bin trufflehog; \
    # dockle
    curl -fsSL "https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin dockle; \
    # kubescape
    curl -fsSL -o /usr/local/bin/kubescape "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape-ubuntu-latest"; \
    chmod +x /usr/local/bin/kubescape; \
    # ProjectDiscovery (subfinder, httpx, nuclei) — single-binary tarballs
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_${alt_arch}.zip" -o /tmp/subfinder.zip; \
    unzip -j /tmp/subfinder.zip subfinder -d /usr/local/bin; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_${alt_arch}.zip" -o /tmp/httpx.zip; \
    unzip -j /tmp/httpx.zip httpx -d /usr/local/bin; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${alt_arch}.zip" -o /tmp/nuclei.zip; \
    unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    # syft + cosign
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${alt_arch}.tar.gz" | tar -xz -C /usr/local/bin syft; \
    curl -fsSL -o /usr/local/bin/cosign "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-${alt_arch//_/-}"; \
    chmod +x /usr/local/bin/cosign; \
    rm -f /tmp/*.zip

# OWASP ZAP — pulls the official tarball and installs into /opt/zap
RUN curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
      | tar -xz -C /opt && \
    ln -s "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zap.sh

# ---------- 2) Runtime ----------
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# System deps:
# - libpango/cairo for WeasyPrint PDF rendering
# - openjdk-17 for ZAP
# - nmap + bsdmainutils for the network module
# - testssl.sh's runtime deps (bash, openssl, dnsutils)
# - kubectl + helm + bicep + aws/gcloud CLIs are scripted below
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl gnupg openssl dnsutils nmap \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 fonts-dejavu-core \
        openjdk-17-jre-headless git tar unzip apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh — pinned to a tagged release
ARG TESTSSL_VERSION=3.0.9
RUN curl -fsSL "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" \
      | tar -xz -C /opt && \
    ln -s "/opt/testssl.sh-${TESTSSL_VERSION}/testssl.sh" /usr/local/bin/testssl.sh

# kubectl
ARG KUBECTL_VERSION=1.30.0
RUN curl -fsSL -o /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    chmod +x /usr/local/bin/kubectl

# helm — Checkov needs it to render charts before scanning
ARG HELM_VERSION=3.14.4
RUN curl -fsSL "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" \
      | tar -xz -C /tmp && \
    mv /tmp/linux-amd64/helm /usr/local/bin/helm && \
    rm -rf /tmp/linux-amd64

# Azure Bicep — for IaC scanning of Azure-native templates
RUN curl -fsSL -o /usr/local/bin/bicep \
      "https://github.com/Azure/bicep/releases/latest/download/bicep-linux-x64" && \
    chmod +x /usr/local/bin/bicep

# AWS CLI v2
RUN curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/aws.zip && \
    unzip -q /tmp/aws.zip -d /tmp && \
    /tmp/aws/install && \
    rm -rf /tmp/aws /tmp/aws.zip

# gcloud (slim, no app-engine extras)
RUN curl -fsSL "https://sdk.cloud.google.com" | bash -s -- --disable-prompts --install-dir=/opt && \
    ln -s /opt/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud

# Bring in scanner binaries from stage 1
COPY --from=scanners /usr/local/bin/ /usr/local/bin/
COPY --from=scanners /opt/ZAP_2.15.0/ /opt/ZAP_2.15.0/

# Python deps + pip-installed scanners (semgrep, bandit, pip-audit, prowler, checkov)
WORKDIR /app
COPY pyproject.toml README.md ./
COPY vulnsuite ./vulnsuite
RUN pip install --upgrade pip && \
    pip install . prowler==4.2.0 checkov==3.2.55

# Reports + offline DBs live on persistent volumes (declared in compose)
RUN mkdir -p /var/lib/vulnsuite/reports /var/lib/vulnsuite/offline

# Default to Celery worker; compose overrides for api/beat/dashboard
CMD ["celery", "-A", "vulnsuite.workers.celery_app", "worker", "--loglevel=INFO"]
