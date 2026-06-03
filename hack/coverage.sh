#!/usr/bin/env bash
set -euo pipefail

profile="${1:-/tmp/oci-cas-issuer-cover.out}"
filtered="${2:-/tmp/oci-cas-issuer-cover-unit.out}"
cache="${GOCACHE:-/tmp/oci-cas-issuer-cover-cache}"
threshold="${COVERAGE_THRESHOLD:-100.0}"

GOCACHE="$cache" go test ./... -coverprofile="$profile"

awk 'NR==1 || ($0 !~ /zz_generated\.deepcopy\.go/ && $0 !~ /cmd\/manager\/main\.go/ && $0 !~ /internal\/controller\/setup\.go/)' "$profile" > "$filtered"

echo "Unfiltered coverage:"
GOCACHE="$cache" go tool cover -func="$profile" | tail -1

echo "Unit coverage:"
unit_line="$(GOCACHE="$cache" go tool cover -func="$filtered" | tail -1)"
echo "$unit_line"
unit_percent="$(awk '{gsub(/%/, "", $3); print $3}' <<<"$unit_line")"

awk -v actual="$unit_percent" -v threshold="$threshold" 'BEGIN {
	if (actual + 0 < threshold + 0) {
		printf("unit coverage %.1f%% is below required %.1f%%\n", actual, threshold) > "/dev/stderr"
		exit 1
	}
}'
