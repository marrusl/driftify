#!/usr/bin/env bash
# Run all driftify profiles against the inspectah Go binary, produce fleet tarball.
# Expects the inspectah binary in the current working directory.
# Self-contained: fetches driftify from GitHub; no local checkout required.
set -euo pipefail

INSPECTAH="$(pwd)/inspectah"
if [[ ! -x "$INSPECTAH" ]]; then
    echo "Error: inspectah binary not found in current directory." >&2
    echo "Place the Go binary at ./inspectah and make it executable." >&2
    exit 1
fi

PROFILES=(minimal standard kitchen-sink)
HOSTNAMES=(web-01 web-02 web-03)

DRIFTIFY_SCRIPT="$(mktemp)"
FLEET_DIR="$(mktemp -d -t fleet-aggregate.XXXXXX)"
curl -fsSL https://raw.githubusercontent.com/marrusl/driftify/refs/heads/main/driftify.py -o "$DRIFTIFY_SCRIPT"
chmod +x "$DRIFTIFY_SCRIPT"
trap 'rm -f "$DRIFTIFY_SCRIPT"; rm -rf "$FLEET_DIR"' EXIT

# Start from a clean slate (undo any previous driftify run)
echo "=== Undoing previous driftify state ==="
sudo "$DRIFTIFY_SCRIPT" --undo -yq

for i in "${!PROFILES[@]}"; do
    profile="${PROFILES[$i]}"
    hostname="${HOSTNAMES[$i]}"
    echo "=== Profile: $profile (hostname: $hostname) ==="
    sudo "$DRIFTIFY_SCRIPT" -yq --profile "$profile"
    sudo INSPECTAH_HOSTNAME="$hostname" "$INSPECTAH" scan --yes
done

echo ""
echo "=== Aggregating fleet ==="
# shellcheck disable=SC2012
ls -1t *.tar.gz | head -3 | xargs -I{} cp {} "$FLEET_DIR/"
"$INSPECTAH" fleet "$FLEET_DIR" -p 66

echo ""
echo "=== Fleet tarball ==="
realpath -- "$(ls -1t ./*.tar.gz | head -1)"
