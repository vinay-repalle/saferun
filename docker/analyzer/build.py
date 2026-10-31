#!/usr/bin/env python3
"""Build the pinned analyzer image as saferun-analyzer:local and record its image ID in the local lock file.

The lock file lives in the per-user data directory (Linux: ${XDG_DATA_HOME:-~/.local/share}/saferun/analyzer-image-id, macOS:
~/Library/Application Support/saferun/..., Windows: %LOCALAPPDATA%\\saferun\\...; override with SAFERUN_ANALYZER_LOCK). It is written by
saferun.sandbox.analyzer.write_lock: owner-only (file 0600 / dir 0700 on POSIX, a protected ACL on Windows); an EXISTING directory is
never chmod'ed, it must already be owner-only or the write is refused. SafeRun refuses to use an analyzer image whose ID differs from the
lock, or whose labels differ from the pins in saferun/sandbox/images.py.
Needs network for the build only (pip wheels, OSV-Scanner release). Refuses to build unless the pinned base images are present locally
with the pinned digests. This is the cross-platform port of the former build.sh (which now just runs this file).
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PY = os.environ.get("PYTHON") or sys.executable
FILES = ("Dockerfile", "fetch_verified.py", "semgrep-requirements.txt", "THIRD_PARTY_NOTICES.md")


def die(msg: str):
    print(f"build.py: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    docker = shutil.which("docker")
    if not docker:
        die("docker executable not found on PATH")
    if subprocess.run([PY, "-m", "saferun", "verify-images", "--only", "python"], cwd=ROOT).returncode != 0:
        die("pinned base images not verified; aborting")
    with tempfile.TemporaryDirectory(prefix="saferun-analyzer-ctx-") as ctx:
        ctx = Path(ctx)
        for name in FILES:
            shutil.copy(HERE / name, ctx / name)
        shutil.copy(ROOT / "LICENSE", ctx / "LICENSE")
        shutil.copy(ROOT / "saferun" / "engine" / "rules" / "python.yml", ctx / "python.yml")
        shutil.copytree(HERE / "licenses", ctx / "licenses")
        rules_sha = hashlib.sha256((ctx / "python.yml").read_bytes()).hexdigest()
        if subprocess.run([docker, "build", "--pull=false", "--build-arg", f"RULES_SHA256={rules_sha}",
                           "-t", "saferun-analyzer:local", str(ctx)]).returncode != 0:
            die("docker build failed")
    r = subprocess.run([docker, "image", "inspect", "--format", "{{.Id}}", "saferun-analyzer:local"], capture_output=True, text=True)
    image_id = r.stdout.strip()
    if r.returncode != 0 or not image_id:
        die("cannot read the id of the image that was just built")
    r = subprocess.run([PY, "-c", "import sys\nfrom saferun.sandbox.analyzer import write_lock\nprint(write_lock(sys.argv[1]))", image_id],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        die("could not write the analyzer lock (see the message above); the image was built but is NOT trusted")
    print(f"build.py: built saferun-analyzer:local id={image_id} (recorded in {r.stdout.strip()}, owner-only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
