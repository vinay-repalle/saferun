# SafeRun analyzer image (Phase 5B): Semgrep + OSV-Scanner + gitleaks for the isolated analyzer checks.
# Everything is pinned: base image by digest, Semgrep by exact version + per-wheel SHA-256 (semgrep-requirements.txt),
# OSV-Scanner by exact version + SHA-256 of the release binary, gitleaks by exact version + SHA-256 of the release archive, the Semgrep
# rules and the gitleaks configuration by SHA-256 (each recorded as a label that SafeRun compares with its own copy before every use). Any mismatch fails the build.
# The ARG defaults below must equal saferun/sandbox/images.py (tests/test_image_pins.py enforces it).
# Build with docker/analyzer/build.sh (it stages a minimal build context). Target: linux/amd64.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG SEMGREP_VERSION=1.182.1
ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_SHA256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_TARBALL_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG RULES_SHA256
ARG SECRETS_RULES_SHA256

ENV SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONDONTWRITEBYTECODE=1

COPY fetch_verified.py semgrep-requirements.txt /build/
RUN python /build/fetch_verified.py \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
        "${OSV_SCANNER_SHA256}" /usr/local/bin/osv-scanner \
 && python /build/fetch_verified.py \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        "${GITLEAKS_TARBALL_SHA256}" /build/gitleaks.tar.gz \
 && tar -xzf /build/gitleaks.tar.gz -C /usr/local/bin --no-same-owner gitleaks \
 && chmod 0755 /usr/local/bin/gitleaks \
 && pip install --no-cache-dir --require-hashes --no-deps --only-binary=:all: -r /build/semgrep-requirements.txt \
 && rm -rf /build \
 && test "$(semgrep --version)" = "${SEMGREP_VERSION}" \
 && osv-scanner --version | grep -q "osv-scanner version: ${OSV_SCANNER_VERSION}" \
 && test "$(gitleaks version)" = "${GITLEAKS_VERSION}"

# Rules are baked in: a scanned project can never supply or shadow them.
COPY python.yml /opt/saferun/rules/python.yml
RUN test -n "${RULES_SHA256}" \
 && echo "${RULES_SHA256}  /opt/saferun/rules/python.yml" | sha256sum -c - \
 && chmod 0555 /opt/saferun /opt/saferun/rules && chmod 0444 /opt/saferun/rules/python.yml
# Same for the gitleaks configuration (secrets check).
COPY gitleaks.toml /opt/saferun/rules/gitleaks.toml
RUN test -n "${SECRETS_RULES_SHA256}" \
 && echo "${SECRETS_RULES_SHA256}  /opt/saferun/rules/gitleaks.toml" | sha256sum -c - \
 && chmod 0444 /opt/saferun/rules/gitleaks.toml

# Licenses and notices of the redistributed third-party software (Semgrep, OSV-Scanner, gitleaks, Python packages): see THIRD_PARTY_NOTICES.md.
COPY LICENSE /usr/share/doc/saferun-analyzer/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/saferun-analyzer/THIRD_PARTY_NOTICES.md
COPY licenses/ /usr/share/doc/saferun-analyzer/licenses/
RUN chmod -R a=rX /usr/share/doc/saferun-analyzer

LABEL saferun.analyzer="1" \
      saferun.semgrep.version="${SEMGREP_VERSION}" \
      saferun.osv-scanner.version="${OSV_SCANNER_VERSION}" \
      saferun.rules.sha256="${RULES_SHA256}" \
      saferun.gitleaks.version="${GITLEAKS_VERSION}" \
      saferun.secrets-rules.sha256="${SECRETS_RULES_SHA256}"

# Defence in depth: the image itself runs unprivileged. SafeRun still passes --user 65534:65534 and the other restrictions explicitly.
USER 65534:65534
