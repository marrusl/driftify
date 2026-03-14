#!/usr/bin/env bash
# Run all driftify profiles, yoinkc each, produce fleet-ready tarballs.
set -euo pipefail
cd "$(dirname "$0")"

PROFILES=(minimal standard kitchen-sink)
HOSTNAMES=(web-01 web-02 web-03)

for i in "${!PROFILES[@]}"; do
    profile="${PROFILES[$i]}"
    hostname="${HOSTNAMES[$i]}"
    echo "=== Profile: $profile (hostname: $hostname) ==="
    sudo ./driftify.py --profile "$profile"
    YOINKC_HOSTNAME="$hostname" ../yoinkc/run-yoinkc.sh
done

echo ""
echo "=== Fleet tarballs ready ==="
ls -1t *.tar.gz | head -3
echo ""
echo "To aggregate on your workstation:"
echo "  mkdir fleet-test && mv *.tar.gz fleet-test/"
echo "  yoinkc-fleet aggregate ./fleet-test/ -p 67 -o merged.json"
echo "  yoinkc --from-snapshot merged.json --output-dir /tmp/fleet-output"
