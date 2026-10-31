#!/bin/sh
# Thin wrapper: the build recipe is docker/analyzer/build.py (Python, so it also runs on Windows). Same behaviour as before.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
exec "${PYTHON:-python3}" "$here/build.py"
