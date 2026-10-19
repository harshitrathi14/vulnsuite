#!/usr/bin/env bash
# Produce requirements.lock — every dependency pinned to an exact version
# with its hash — from pyproject.toml plus the pip-installed scanners.
# The Dockerfile installs from the lock with --require-hashes when it is
# present, so a compromised or yanked upstream release cannot slip into
# the image unnoticed. Re-run after editing dependencies; commit the diff.
#
#   pip install pip-tools && deploy/lock-deps.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

python -m piptools --version >/dev/null 2>&1 || {
    echo "pip-tools is not installed: pip install pip-tools" >&2
    exit 1
}
python -m piptools compile \
    --generate-hashes --strip-extras --allow-unsafe \
    --output-file requirements.lock \
    pyproject.toml deploy/requirements-scanners.in
echo "wrote requirements.lock" >&2
