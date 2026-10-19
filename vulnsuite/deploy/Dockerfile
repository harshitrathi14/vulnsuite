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
# Supply chain:
# - Every download goes through deploy/fetch-verified.sh and must match the
#   SHA-256 pinned for its exact URL in deploy/checksums.sha256. Bump an
#   ARG *_VERSION, run deploy/pin-checksums.sh, review the diff, rebuild.
#   A missing or mismatched pin fails the build. ALLOW_UNVERIFIED_DOWNLOADS=1
#   downgrades a missing pin to a warning for emergencies only.
# - Python dependencies install from requirements.lock (--require-hashes)
#   when it exists; run deploy/lock-deps.sh to produce it.
# - The runtime user is unprivileged (uid 10001). nmap uses -sT connect
#   scans so no capabilities are needed.
# Only linux/amd64 is pinned.

# ---------- 1) Builder: pull pinned scanner binaries ----------
FROM debian:bookworm-slim AS scanners

ARG TARGETARCH
RUN [ "${TARGETARCH:-amd64}" = "amd64" ] || { echo "only linux/amd64 is pinned (got ${TARGETARCH}); re-pin checksums first"; exit 1; }

# 0.50.1 is no longer published by Aqua (releases before v0.69.2 were
# removed), so the previous pin could not be downloaded at all.
ARG TRIVY_VERSION=0.76.0
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
ARG ZAP_VERSION=2.17.0
ARG ALLOW_UNVERIFIED_DOWNLOADS=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl tar unzip && \
    rm -rf /var/lib/apt/lists/*

COPY deploy/fetch-verified.sh /usr/local/bin/fetch-verified
COPY deploy/checksums.sha256 /build/checksums.sha256
RUN chmod 0755 /usr/local/bin/fetch-verified

WORKDIR /tmp/dl
RUN set -eux; \
    fetch-verified "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy.tgz; \
    tar -xzf trivy.tgz -C /usr/local/bin trivy; \
    fetch-verified "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks.tgz; \
    tar -xzf gitleaks.tgz -C /usr/local/bin gitleaks; \
    fetch-verified "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" /usr/local/bin/osv-scanner; \
    chmod 0755 /usr/local/bin/osv-scanner; \
    fetch-verified "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" trufflehog.tgz; \
    tar -xzf trufflehog.tgz -C /usr/local/bin trufflehog; \
    fetch-verified "https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz" dockle.tgz; \
    tar -xzf dockle.tgz -C /usr/local/bin dockle; \
    fetch-verified "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape-ubuntu-latest" /usr/local/bin/kubescape; \
    chmod 0755 /usr/local/bin/kubescape; \
    fetch-verified "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" subfinder.zip; \
    unzip -j subfinder.zip subfinder -d /usr/local/bin; \
    fetch-verified "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" httpx.zip; \
    unzip -j httpx.zip httpx -d /usr/local/bin; \
    fetch-verified "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" nuclei.zip; \
    unzip -j nuclei.zip nuclei -d /usr/local/bin; \
    fetch-verified "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" syft.tgz; \
    tar -xzf syft.tgz -C /usr/local/bin syft; \
    fetch-verified "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" /usr/local/bin/cosign; \
    chmod 0755 /usr/local/bin/cosign; \
    rm -rf /tmp/dl/*

# OWASP ZAP — official tarball into /opt. 2.15.0 is no longer published
# (ZAP removes superseded stable releases); 2.17.0 is the current stable.
RUN fetch-verified "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" /tmp/zap.tgz && \
    tar -xzf /tmp/zap.tgz -C /opt && \
    ln -s "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zap.sh && \
    rm -f /tmp/zap.tgz

# ---------- 2) Runtime ----------
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

ARG ALLOW_UNVERIFIED_DOWNLOADS=0

# System deps:
# - libpango/cairo for WeasyPrint PDF rendering
# - openjdk-17 for ZAP
# - nmap + dnsutils for the network module (connect scans, no raw sockets)
# - testssl.sh's runtime deps (bash, openssl, dnsutils)
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl openssl dnsutils nmap \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 fonts-dejavu-core \
        openjdk-17-jre-headless git tar unzip \
    && rm -rf /var/lib/apt/lists/*

COPY deploy/fetch-verified.sh /usr/local/bin/fetch-verified
COPY deploy/checksums.sha256 /build/checksums.sha256
RUN chmod 0755 /usr/local/bin/fetch-verified

# testssl.sh — pinned to a tagged release
ARG TESTSSL_VERSION=3.0.9
RUN fetch-verified "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" /tmp/testssl.tgz && \
    tar -xzf /tmp/testssl.tgz -C /opt && \
    ln -s "/opt/testssl.sh-${TESTSSL_VERSION}/testssl.sh" /usr/local/bin/testssl.sh && \
    rm -f /tmp/testssl.tgz

# kubectl
ARG KUBECTL_VERSION=1.30.0
RUN fetch-verified "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" /usr/local/bin/kubectl && \
    chmod 0755 /usr/local/bin/kubectl

# helm — Checkov needs it to render charts before scanning
ARG HELM_VERSION=3.14.4
RUN fetch-verified "https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz" /tmp/helm.tgz && \
    tar -xzf /tmp/helm.tgz -C /tmp && \
    mv /tmp/linux-amd64/helm /usr/local/bin/helm && \
    rm -rf /tmp/linux-amd64 /tmp/helm.tgz

# Azure Bicep — pinned (was releases/latest)
ARG BICEP_VERSION=0.26.170
RUN fetch-verified "https://github.com/Azure/bicep/releases/download/v${BICEP_VERSION}/bicep-linux-x64" /usr/local/bin/bicep && \
    chmod 0755 /usr/local/bin/bicep

# AWS CLI v2 — pinned (was the unversioned "latest" zip)
ARG AWSCLI_VERSION=2.15.40
RUN fetch-verified "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWSCLI_VERSION}.zip" /tmp/aws.zip && \
    unzip -q /tmp/aws.zip -d /tmp && \
    /tmp/aws/install && \
    rm -rf /tmp/aws /tmp/aws.zip

# gcloud — pinned tarball (was `curl | bash` of an unversioned installer)
ARG GCLOUD_VERSION=474.0.0
RUN fetch-verified "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-${GCLOUD_VERSION}-linux-x86_64.tar.gz" /tmp/gcloud.tgz && \
    tar -xzf /tmp/gcloud.tgz -C /opt && \
    /opt/google-cloud-sdk/install.sh --quiet --usage-reporting=false --path-update=false --command-completion=false && \
    ln -s /opt/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud && \
    rm -f /tmp/gcloud.tgz

# Bring in scanner binaries from stage 1
ARG ZAP_VERSION=2.17.0
COPY --from=scanners /usr/local/bin/ /usr/local/bin/
COPY --from=scanners /opt/ZAP_${ZAP_VERSION}/ /opt/ZAP_${ZAP_VERSION}/

# Python deps + pip-installed scanners (semgrep, bandit, pip-audit, prowler, checkov)
WORKDIR /app
# requirements.lock is optional at COPY time (the glob may match nothing)
# but its absence is reported loudly at install time.
COPY pyproject.toml README.md requirements.lock* ./
# The checkout's build context is the package directory itself. Recreate the
# installable /app/vulnsuite package explicitly; do not copy private deployment
# configuration, local databases, documents or generated artifacts into it.
COPY __init__.py cli.py ./vulnsuite/
COPY ai/ ./vulnsuite/ai/
COPY api/ ./vulnsuite/api/
COPY collectors/ ./vulnsuite/collectors/
COPY compliance/ ./vulnsuite/compliance/
COPY core/ ./vulnsuite/core/
COPY dashboard/ ./vulnsuite/dashboard/
COPY integrations/ ./vulnsuite/integrations/
COPY protection/ ./vulnsuite/protection/
COPY reporting/ ./vulnsuite/reporting/
COPY workers/ ./vulnsuite/workers/
RUN if [ -f requirements.lock ]; then \
        pip install --require-hashes -r requirements.lock && pip install --no-deps . ; \
    else \
        echo "WARNING: requirements.lock not found; installing unpinned dependency ranges (run deploy/lock-deps.sh)" >&2; \
        pip install . prowler==4.2.0 checkov==3.2.55 ; \
    fi

# Unprivileged runtime user. Reports + offline DBs live on persistent
# volumes (declared in compose) and are owned by it; HOME holds scanner
# caches (semgrep, pip-audit, ZAP).
RUN groupadd --gid 10001 vulnsuite && \
    useradd --uid 10001 --gid 10001 --create-home --home-dir /home/vulnsuite \
            --shell /usr/sbin/nologin vulnsuite && \
    mkdir -p /var/lib/vulnsuite/reports /var/lib/vulnsuite/offline && \
    chown -R vulnsuite:vulnsuite /var/lib/vulnsuite /home/vulnsuite
ENV HOME=/home/vulnsuite
USER 10001:10001

# Default to Celery worker; compose overrides for api/beat/dashboard
CMD ["celery", "-A", "vulnsuite.workers.celery_app", "worker", "--loglevel=INFO"]
