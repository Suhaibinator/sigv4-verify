#!/usr/bin/env bash
#
# bench.sh — drive an HTTP load test against a running NGINX endpoint using a
# pre-generated file of request lines (see gen-urls.sh) and report p50/p90/p99/
# p99.9 latency plus throughput.
#
# Primary driver is wrk with multi-url.lua, which replays the mixed valid/
# invalid corpus round-robin and prints the percentile summary. If wrk is not
# installed, an oha fallback runs a single representative URL (it cannot replay
# the full mix or report p99.9) so the script is still useful for a smoke test.
#
# Example:
#   scripts/bench/bench.sh \
#     --base http://127.0.0.1:8080 \
#     --urls /tmp/urls.txt \
#     --host assets.example.test \
#     --duration 30s --connections 64 --threads 4

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

base=""
urls=""
host="assets.example.test"
duration="30s"
connections="64"
threads="4"

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --base) base="$2"; shift 2 ;;
        --urls) urls="$2"; shift 2 ;;
        --host) host="$2"; shift 2 ;;
        -d|--duration) duration="$2"; shift 2 ;;
        -c|--connections) connections="$2"; shift 2 ;;
        -t|--threads) threads="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done

if [ -z "$base" ] || [ -z "$urls" ]; then
    echo "--base and --urls are required" >&2
    usage 1
fi
if [ ! -f "$urls" ]; then
    echo "urls file not found: $urls" >&2
    exit 1
fi

if command -v wrk >/dev/null 2>&1; then
    echo "== wrk: replaying $(wc -l < "$urls" | tr -d ' ') request lines against $base =="
    URLS_FILE="$urls" BENCH_HOST="$host" \
        wrk -t"$threads" -c"$connections" -d"$duration" --latency \
        -s "$HERE/multi-url.lua" "$base"
    exit 0
fi

if command -v oha >/dev/null 2>&1; then
    echo "== wrk not found; oha fallback (single URL, no mix, no p99.9) ==" >&2
    first="$(awk 'NF {print; exit}' "$urls")"
    method="${first%% *}"
    path="${first#* }"
    if [ "$method" = "$path" ]; then
        method="GET"
    fi
    oha --no-tui -m "$method" -H "Host: $host" -z "$duration" -c "$connections" "$base$path"
    exit 0
fi

echo "neither wrk nor oha is installed." >&2
echo "install wrk (https://github.com/wg/wrk) for full percentile + mixed-corpus support," >&2
echo "or oha (https://github.com/hatoo/oha) for a single-URL fallback." >&2
exit 1
