#!/usr/bin/env bash
# Run all driftify profiles against the inspectah Rust binary, produce fleet tarball.
# Prefers ./inspectah in the current directory; falls back to inspectah in $PATH.
# Self-contained: fetches driftify from GitHub; no local checkout required.
#
# Flags:
#   --no-undo                  Skip undoing previous driftify state (for fresh VMs)
#   --no-redaction             Skip redaction entirely (implies --ack-sensitive)
#   --preserve ITEMS           Preserve specific sensitive data: password-hashes,
#                              ssh-keys, subscription, all (implies --ack-sensitive)
set -euo pipefail

NO_UNDO=false
NO_REDACTION=false
PRESERVE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-undo) NO_UNDO=true; shift ;;
        --no-redaction) NO_REDACTION=true; shift ;;
        --preserve) PRESERVE="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

SCAN_FLAGS=()
AGGREGATE_FLAGS=()
if $NO_REDACTION; then
    SCAN_FLAGS+=(--no-redaction --ack-sensitive)
    AGGREGATE_FLAGS+=(--ack-sensitive)
elif [[ -n "$PRESERVE" ]]; then
    SCAN_FLAGS+=(--preserve "$PRESERVE" --ack-sensitive)
    AGGREGATE_FLAGS+=(--ack-sensitive)
fi

# Prefer a local binary in cwd; fall back to $PATH.
if [[ -x "./inspectah" ]]; then
    INSPECTAH="$(pwd)/inspectah"
elif command -v inspectah &>/dev/null; then
    INSPECTAH="$(command -v inspectah)"
else
    echo "Error: inspectah binary not found in current directory or \$PATH." >&2
    exit 1
fi
echo "Using: $INSPECTAH"

PROFILES=(minimal standard kitchen-sink)
HOSTNAMES=(web-01 web-02 web-03)

FLEET_DIR="$(mktemp -d -t fleet-aggregate.XXXXXX)"
ORIGINAL_HOSTNAME="$(hostname)"

# Use local driftify.py if present, otherwise fetch from GitHub.
if [[ -f "$(pwd)/driftify.py" ]]; then
    DRIFTIFY_SCRIPT="$(pwd)/driftify.py"
    DRIFTIFY_FETCHED=false
else
    DRIFTIFY_SCRIPT="$(mktemp)"
    DRIFTIFY_FETCHED=true
    curl -fsSL https://raw.githubusercontent.com/marrusl/driftify/refs/heads/main/driftify.py -o "$DRIFTIFY_SCRIPT"
    chmod +x "$DRIFTIFY_SCRIPT"
fi
trap 'sudo hostnamectl set-hostname "$ORIGINAL_HOSTNAME" 2>/dev/null; $DRIFTIFY_FETCHED && rm -f "$DRIFTIFY_SCRIPT"; rm -rf "$FLEET_DIR"' EXIT

# Start from a clean slate (undo any previous driftify run)
if ! $NO_UNDO; then
    echo "=== Undoing previous driftify state ==="
    sudo "$DRIFTIFY_SCRIPT" --undo -yq
fi

for i in "${!PROFILES[@]}"; do
    profile="${PROFILES[$i]}"
    hostname="${HOSTNAMES[$i]}"
    echo "=== Profile: $profile (hostname: $hostname) ==="
    sudo "$DRIFTIFY_SCRIPT" -yq --profile "$profile"
    # Rust binary reads hostname from the system (no INSPECTAH_HOSTNAME env var),
    # so we set it directly before each scan and restore it on exit via the trap.
    sudo hostnamectl set-hostname "$hostname"
    sudo "$INSPECTAH" scan "${SCAN_FLAGS[@]}"
done

# Restore hostname before aggregation (not strictly needed, but tidy)
sudo hostnamectl set-hostname "$ORIGINAL_HOSTNAME"

echo ""
echo "=== Aggregating fleet ==="
# Rust fleet uses: inspectah fleet aggregate <inputs...>
# Collect the 3 most recent tarballs into the staging directory.
# shellcheck disable=SC2012
ls -1t *.tar.gz | head -3 | xargs -I{} cp {} "$FLEET_DIR/"
"$INSPECTAH" fleet aggregate "${AGGREGATE_FLAGS[@]}" "$FLEET_DIR"

echo ""
echo "=== Fleet tarball ==="
realpath -- "$(ls -1t ./*.tar.gz | head -1)"
