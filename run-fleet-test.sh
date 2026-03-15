#!/usr/bin/env bash
# Run all driftify profiles, yoinkc each, produce fleet-ready tarballs.
set -euo pipefail
cd "$(dirname "$0")"

PROFILES=(minimal standard kitchen-sink)
HOSTNAMES=(web-01 web-02 web-03)

YOINKC_SCRIPT="$(mktemp)"
FLEET_SCRIPT="$(mktemp)"
FLEET_DIR="$(mktemp -d -t fleet-aggregate.XXXXXX)"
curl -fsSL https://raw.githubusercontent.com/marrusl/yoinkc/refs/heads/main/run-yoinkc.sh -o "$YOINKC_SCRIPT"
curl -fsSL https://raw.githubusercontent.com/marrusl/yoinkc/refs/heads/main/run-yoinkc-fleet.sh -o "$FLEET_SCRIPT"
chmod +x "$YOINKC_SCRIPT"
trap 'rm -f "$YOINKC_SCRIPT" "$FLEET_SCRIPT"; rm -rf "$FLEET_DIR"' EXIT

for i in "${!PROFILES[@]}"; do
    profile="${PROFILES[$i]}"
    hostname="${HOSTNAMES[$i]}"
    echo "=== Profile: $profile (hostname: $hostname) ==="
    sudo ./driftify.py -yq --profile "$profile"
    YOINKC_HOSTNAME="$hostname" bash "$YOINKC_SCRIPT"
done

echo ""
echo "=== Aggregating fleet ==="
# shellcheck disable=SC2012
ls -1t *.tar.gz | head -3 | xargs -I{} cp {} "$FLEET_DIR/"
bash "$FLEET_SCRIPT" "$FLEET_DIR" -p 67

echo ""
echo "=== Fleet tarball ==="
realpath -- "$(ls -1t ./*.tar.gz | head -1)"
