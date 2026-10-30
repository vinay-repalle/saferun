# Third-party software in the SafeRun analyzer image

The SafeRun analyzer image (`ghcr.io/vinay-repalle/saferun-analyzer`) is built from `docker/analyzer/Dockerfile` and **redistributes the third-party
software listed here, unmodified**, each under its own license. This file is installed in the image as
`/usr/share/doc/saferun-analyzer/THIRD_PARTY_NOTICES.md`; the texts it references are in `/usr/share/doc/saferun-analyzer/licenses/`.

SafeRun's own code and rules are covered by the MIT License (`/usr/share/doc/saferun-analyzer/LICENSE`, Copyright (c) 2026 Vinay Repalle). The MIT License does
not apply to the third-party software below, which stays under its own licenses. This list is a good-faith inventory, not legal advice.

## Components that carry their own license text

| Component | Version | License | Where the text is |
|---|---|---|---|
| Semgrep (CLI and bundled `semgrep-core`) | 1.182.1 | LGPL-2.1-or-later (as declared in the package metadata) | `licenses/semgrep-LICENSE` |
| OSV-Scanner (single Go binary, includes OSV-SCALIBR 0.5.3) | 2.7.0 | Apache-2.0 | `licenses/osv-scanner-v2.7.0-LICENSE` |

* **Semgrep** is installed unmodified from the hash-locked PyPI wheel (`docker/analyzer/semgrep-requirements.txt`). Its wheel does not ship a license file, so the
  LGPL-2.1 text was taken from the upstream repository (`github.com/semgrep/semgrep`, file `LICENSE`, branch `develop`, git blob `8000a6fa…`, verified against the
  hash GitHub reports for that repository's detected license). The release tag for 1.182.1 could not be located when this was written, so the text may differ from
  that release in wording only if upstream changed it; the package metadata declares LGPL-2.1-or-later. **Corresponding source** for the version used is available
  from `https://github.com/semgrep/semgrep` and from the PyPI source distribution of `semgrep==1.182.1`; SafeRun makes no changes to it. SafeRun uses only its own rules
  (`/opt/saferun/rules/python.yml`); no Semgrep Registry rules are included.
* **OSV-Scanner** is downloaded as the official `osv-scanner_linux_amd64` release binary and checked against a pinned SHA-256 at build time. The license text is
  `LICENSE` of `github.com/google/osv-scanner` at tag `v2.7.0` (git blob `d6456956…`, identical to the hash GitHub reports for the repository's Apache-2.0 license). The
  repository has no `NOTICE` file at that tag. The binary statically includes Go modules under their own licenses; their notices are in the upstream source
  (`go.mod` / `go.sum` at the same tag). They have **not** been enumerated here.

## Python packages installed with Semgrep

These 66 packages (plus `pip`, which comes from the base image) are installed from hash-locked wheels. The license is the one declared in each package's metadata inside
the image; every package except those marked "no" ships its own license file in its `*.dist-info` directory under `/usr/local/lib/python3.12/site-packages/`.
(`opentelemetry-util-http` carries no separate file; it is part of the Apache-2.0 `opentelemetry-python-contrib` project. `semgrep` is covered above.)

| Package | Version | Declared license | License file in image |
|---|---|---|---|
| annotated-types | 0.8.0 | MIT | yes |
| anyio | 4.15.1 | MIT | yes |
| attrs | 26.1.0 | MIT | yes |
| boltons | 21.0.0 | BSD | yes |
| bracex | 3.2 | MIT | yes |
| certifi | 2026.10.23 | MPL-2.0 | yes |
| cffi | 2.1.1 | MIT-0 | yes |
| charset-normalizer | 3.5.2 | MIT | yes |
| click | 8.4.2 | BSD-3-Clause | yes |
| click-option-group | 0.5.9 | BSD-3-Clause | yes |
| colorama | 0.4.6 | BSD License | yes |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | yes |
| exceptiongroup | 1.2.2 | MIT License | yes |
| face | 26.0.1 | not declared in metadata (see license file) | yes |
| glom | 25.12.0 | BSD License | yes |
| googleapis-common-protos | 1.76.0 | Apache-2.0 | yes |
| h11 | 0.16.0 | MIT | yes |
| httpcore | 1.0.9 | BSD-3-Clause | yes |
| httpx | 0.28.1 | BSD-3-Clause | yes |
| httpx-sse | 0.4.3 | MIT | yes |
| idna | 3.20 | BSD-3-Clause | yes |
| importlib_metadata | 8.7.1 | Apache-2.0 | yes |
| jsonschema | 4.25.1 | MIT | yes |
| jsonschema-specifications | 2025.9.1 | MIT | yes |
| markdown-it-py | 4.2.0 | MIT License | yes |
| mcp | 1.29.0 | MIT | yes |
| mdurl | 0.1.2 | MIT License | yes |
| opentelemetry-api | 1.37.0 | Apache-2.0 | yes |
| opentelemetry-exporter-otlp-proto-common | 1.37.0 | Apache-2.0 | yes |
| opentelemetry-exporter-otlp-proto-http | 1.37.0 | Apache-2.0 | yes |
| opentelemetry-instrumentation | 0.58b0 | Apache-2.0 | yes |
| opentelemetry-instrumentation-requests | 0.58b0 | Apache-2.0 | yes |
| opentelemetry-instrumentation-threading | 0.58b0 | Apache-2.0 | yes |
| opentelemetry-proto | 1.37.0 | Apache-2.0 | yes |
| opentelemetry-sdk | 1.37.0 | Apache-2.0 | yes |
| opentelemetry-semantic-conventions | 0.58b0 | Apache-2.0 | yes |
| opentelemetry-util-http | 0.58b0 | Apache-2.0 | no |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | yes |
| peewee | 3.19.0 | not declared in metadata (see license file) | yes |
| pip | 25.0.1 | MIT | yes |
| protobuf | 6.33.6 | 3-Clause BSD License | yes |
| pycparser | 3.12 | BSD-3-Clause | yes |
| pydantic | 2.14.1 | MIT | yes |
| pydantic-settings | 2.16.2 | MIT | yes |
| pydantic_core | 2.50.1 | MIT | yes |
| Pygments | 2.21.0 | BSD-2-Clause | yes |
| PyJWT | 2.15.1 | MIT | yes |
| python-dotenv | 1.2.4 | BSD-3-Clause | yes |
| python-multipart | 0.0.32 | Apache-2.0 | yes |
| referencing | 0.37.0 | MIT | yes |
| requests | 2.34.2 | Apache-2.0 | yes |
| rich | 15.0.0 | MIT | yes |
| rpds-py | 2026.9.1 | MIT | yes |
| ruamel.yaml | 0.19.1 | MIT | yes |
| ruamel.yaml.clib | 0.2.15 | MIT | yes |
| semantic-version | 2.10.0 | BSD | yes |
| semgrep | 1.182.1 | LGPL-2.1-or-later | no |
| sse-starlette | 3.6.0 | BSD-3-Clause | yes |
| starlette | 1.10.0 | BSD-3-Clause | yes |
| tomli | 2.4.1 | MIT | yes |
| typing-inspection | 0.4.4 | MIT | yes |
| typing_extensions | 4.16.0 | PSF-2.0 | yes |
| urllib3 | 2.8.0 | MIT | yes |
| uvicorn | 0.54.0 | BSD-3-Clause | yes |
| wcmatch | 8.5.2 | MIT | yes |
| wrapt | 1.17.3 | BSD | yes |
| zipp | 4.1.2 | MIT | yes |

Collected by reading the package metadata inside an analyzer image built from the same `semgrep-requirements.txt`. Re-check this table whenever that file changes.

## Base image

`python:3.12-slim` (pinned by digest in the Dockerfile): CPython under the PSF license and Debian packages under their own licenses. Debian's copyright files are
under `/usr/share/doc/<package>/copyright` in the base image and are left in place. Debian source packages are available from Debian.

## Not in the image

The OSV vulnerability data is downloaded by the user with `saferun osv-db update` and is not part of this image.
