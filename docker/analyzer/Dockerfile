# SafeRun analyzer image (Phase 5B): Semgrep + OSV-Scanner for the isolated analyzer checks.
# Everything is pinned: base image by digest, Semgrep by exact version + per-wheel SHA-256 (semgrep-requirements.txt),
# OSV-Scanner by exact version + SHA-256 of the release binary, the Semgrep rules by SHA-256 (recorded as a label that
# SafeRun compares with its own copy before every use). Any mismatch fails the build.
# The ARG defaults below must equal saferun/sandbox/images.py (tests/test_image_pins.py enforces it).
# Build with docker/analyzer/build.sh (it stages a minimal build context). Target: linux/amd64.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG SEMGREP_VERSION=1.182.1
ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_SHA256=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG RULES_SHA256

ENV SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONDONTWRITEBYTECODE=1

COPY fetch_verified.py semgrep-requirements.txt /build/
RUN python /build/fetch_verified.py \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
        "${OSV_SCANNER_SHA256}" /usr/local/bin/osv-scanner \
 && pip install --no-cache-dir --require-hashes --no-deps --only-binary=:all: -r /build/semgrep-requirements.txt \
 && rm -rf /build \
 && test "$(semgrep --version)" = "${SEMGREP_VERSION}" \
 && osv-scanner --version | grep -q "osv-scanner version: ${OSV_SCANNER_VERSION}"

# Rules are baked in: a scanned project can never supply or shadow them.
COPY python.yml /opt/saferun/rules/python.yml
RUN test -n "${RULES_SHA256}" \
 && echo "${RULES_SHA256}  /opt/saferun/rules/python.yml" | sha256sum -c - \
 && chmod 0555 /opt/saferun /opt/saferun/rules && chmod 0444 /opt/saferun/rules/python.yml

# Licenses and notices of the redistributed third-party software (Semgrep, OSV-Scanner, Python packages): see THIRD_PARTY_NOTICES.md.
COPY LICENSE /usr/share/doc/saferun-analyzer/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/saferun-analyzer/THIRD_PARTY_NOTICES.md
COPY licenses/ /usr/share/doc/saferun-analyzer/licenses/
RUN chmod -R a=rX /usr/share/doc/saferun-analyzer

LABEL saferun.analyzer="1" \
      saferun.semgrep.version="${SEMGREP_VERSION}" \
      saferun.osv-scanner.version="${OSV_SCANNER_VERSION}" \
      saferun.rules.sha256="${RULES_SHA256}"

# Defence in depth: the image itself runs unprivileged. SafeRun still passes --user 65534:65534 and the other restrictions explicitly.
USER 65534:65534
