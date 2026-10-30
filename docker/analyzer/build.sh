#!/bin/sh
# Build the pinned analyzer image as saferun-analyzer:local and record its image ID in the local lock file
# (${XDG_DATA_HOME:-~/.local/share}/saferun/analyzer-image-id; override with SAFERUN_ANALYZER_LOCK). The lock is written by
# saferun.sandbox.analyzer.write_lock: file 0600, directory 0700 (created if missing, never chmod'ed if it exists: it must already be
# owner-only or the write is refused). SafeRun refuses to use an analyzer
# image whose ID differs from the lock, or whose labels differ from the pins in saferun/sandbox/images.py.
# Needs network for the build only (pip wheels, OSV-Scanner release). Refuses to build unless the pinned base images are
# present locally with the pinned digests.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
py=${PYTHON:-python3}
( cd "$root" && "$py" -m saferun verify-images --only python ) || { echo "build.sh: pinned base images not verified; aborting" >&2; exit 1; }
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
cp "$here/Dockerfile" "$here/fetch_verified.py" "$here/semgrep-requirements.txt" "$here/THIRD_PARTY_NOTICES.md" "$root/LICENSE" "$root/saferun/engine/rules/python.yml" "$ctx/"
cp -r "$here/licenses" "$ctx/licenses"
rules_sha=$(sha256sum "$ctx/python.yml" | cut -d' ' -f1)
docker build --pull=false --build-arg "RULES_SHA256=$rules_sha" -t saferun-analyzer:local "$ctx"
id=$(docker image inspect --format '{{.Id}}' saferun-analyzer:local)
lock=$( cd "$root" && "$py" -c '
import sys
from saferun.sandbox.analyzer import write_lock
print(write_lock(sys.argv[1]))' "$id" ) || { echo "build.sh: could not write the analyzer lock (see the message above); the image was built but is NOT trusted" >&2; exit 1; }
echo "build.sh: built saferun-analyzer:local id=$id (recorded in $lock, mode 0600)"
