#!/usr/bin/env bash
#
# gen-urls.sh — generate a file of request lines for the e2e benchmark runner.
#
# Each output line is "METHOD /path?query" using the RequestURI (path + query)
# of a MinIO-style path-style presigned URL produced by ./cmd/presign-url. A
# configurable fraction of lines have their X-Amz-Signature tampered so the
# corpus mixes valid (expected 200/404) and invalid (expected 403) traffic.
#
# The generated Host header is the presign endpoint; pass it to bench.sh so the
# requests route to the right NGINX server block.
#
# Example:
#   scripts/bench/gen-urls.sh \
#     -n 500 -o /tmp/urls.txt \
#     --host assets.example.test \
#     --access-key e2e-access-key --secret-key e2e-secret-key \
#     --bucket my-bucket --object public/file.txt \
#     --invalid-ratio 0.2

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

count=200
out=""
host="assets.example.test"
access_key="${SIGV4_ACCESS_KEY:-e2e-access-key}"
secret_key="${SIGV4_SECRET_KEY:-e2e-secret-key}"
bucket="my-bucket"
object="public/file.txt"
method="GET"
region="us-east-1"
expiry="10m"
invalid_ratio="0.2"

usage() {
    sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--count) count="$2"; shift 2 ;;
        -o|--out) out="$2"; shift 2 ;;
        --host) host="$2"; shift 2 ;;
        --access-key) access_key="$2"; shift 2 ;;
        --secret-key) secret_key="$2"; shift 2 ;;
        --bucket) bucket="$2"; shift 2 ;;
        --object) object="$2"; shift 2 ;;
        --method) method="$2"; shift 2 ;;
        --region) region="$2"; shift 2 ;;
        --expiry) expiry="$2"; shift 2 ;;
        --invalid-ratio) invalid_ratio="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done

if [ -z "$out" ]; then
    echo "output file is required (-o)" >&2
    usage 1
fi

# One invalid line for every 1/invalid_ratio lines, deterministically spaced.
invalid_every="$(awk -v r="$invalid_ratio" 'BEGIN { if (r <= 0) { print 0 } else { print int(1 / r + 0.5) } }')"

tamper() {
    # Flip the last hex digit of the X-Amz-Signature value.
    local line="$1"
    local sig hex last new
    sig="$(printf '%s' "$line" | grep -oE 'X-Amz-Signature=[0-9a-fA-F]+' | head -1 || true)"
    if [ -z "$sig" ]; then
        printf '%s' "$line"
        return
    fi
    hex="${sig#X-Amz-Signature=}"
    last="${hex: -1}"
    case "$last" in
        0) new=1 ;;
        *) new=0 ;;
    esac
    printf '%s' "${line/X-Amz-Signature=$hex/X-Amz-Signature=${hex%?}$new}"
}

: > "$out"
made=0
for i in $(seq 1 "$count"); do
    url="$(SIGV4_ACCESS_KEY="$access_key" SIGV4_SECRET_KEY="$secret_key" \
        go run "$ROOT/cmd/presign-url" \
        -endpoint "$host" \
        -bucket "$bucket" \
        -object "$object" \
        -method "$method" \
        -region "$region" \
        -expiry "$expiry" \
        -secure=false)"
    # Strip scheme + host to leave the RequestURI (path + query).
    path="$(printf '%s' "$url" | sed -E 's#^https?://[^/]+##')"

    line="$method $path"
    if [ "$invalid_every" -gt 0 ] && [ $((i % invalid_every)) -eq 0 ]; then
        line="$method $(tamper "$path")"
    fi
    printf '%s\n' "$line" >> "$out"
    made=$((made + 1))
done

echo "wrote $made request lines to $out (host: $host)" >&2
