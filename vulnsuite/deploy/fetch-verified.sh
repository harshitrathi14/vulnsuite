#!/bin/sh
# fetch-verified URL DEST
#
# Download URL to DEST and verify it against the SHA-256 pinned for that
# exact URL in deploy/checksums.sha256 (pinned by deploy/pin-checksums.sh).
# A missing or mismatched pin fails the build. ALLOW_UNVERIFIED_DOWNLOADS=1
# downgrades a *missing* pin to a loud warning — for emergencies only; a
# mismatch is never bypassable.
set -eu

url="$1"
dest="$2"
db="${CHECKSUMS_FILE:-/build/checksums.sha256}"

curl -fsSL --connect-timeout 20 --max-time 900 --retry 3 --retry-delay 2 -o "$dest" "$url"

expected="$(awk -v u="$url" '$1 !~ /^#/ && $2 == u { print $1; exit }' "$db" 2>/dev/null || true)"
if [ -z "$expected" ]; then
    if [ "${ALLOW_UNVERIFIED_DOWNLOADS:-0}" = "1" ]; then
        echo "WARNING: no pinned checksum for $url; proceeding because ALLOW_UNVERIFIED_DOWNLOADS=1" >&2
        exit 0
    fi
    echo "ERROR: no pinned checksum for $url in $db (run deploy/pin-checksums.sh)" >&2
    rm -f "$dest"
    exit 1
fi

actual="$(sha256sum "$dest" | awk '{print $1}')"
if [ "$actual" != "$expected" ]; then
    echo "ERROR: checksum mismatch for $url" >&2
    echo "  expected $expected" >&2
    echo "  actual   $actual" >&2
    rm -f "$dest"
    exit 1
fi
echo "verified $(basename "$url")" >&2
