#!/usr/bin/env bash
#
# e2e-linux.sh — self-contained Linux NGINX e2e benchmark reproducer.
#
# Builds the native module image and the Go sidecar image, stands up three
# stacks on a private docker network (baseline nginx / Rust module in-process /
# Go sidecar over a unix socket behind auth_request), replays a corpus with
# cmd/loadgen from an in-network container, and prints RPS, p50/p90/p99/p99.9,
# average CPU cores (cgroup cpu.stat delta), sampled RSS, and — for the sidecar —
# Go GC cycles. Reproduces the "Results (Linux, NGINX e2e ...)" tables in
# docs/benchmarks.md. Everything is torn down on exit.
#
# Requires: docker (cgroup v2 host for CPU/RSS/GC accounting) and go. Run from
# the repository root. Tunables (env): DUR_FIRST C_FIRST DUR_BARR C_BARR N.
#
#   scripts/bench/e2e-linux.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

HOST=assets.example.test
NGINX_VERSION="${NGINX_VERSION:-1.28.0}"
DUR_FIRST="${DUR_FIRST:-20}"; C_FIRST="${C_FIRST:-128}"
DUR_BARR="${DUR_BARR:-60}";   C_BARR="${C_BARR:-64}"
N="${N:-500}"

IMG_MOD="sigv4-verify-nginx:${NGINX_VERSION}"
IMG_SIDE="sigv4-verify-sidecar:e2e-bench"
IMG_LOAD="sigv4-verify-loadgen:e2e-bench"
NET=sigv4-e2e-bench-net
SOCK=sigv4-e2e-bench-sock
C_BASE=sigv4-e2e-baseline; C_MOD=sigv4-e2e-module; C_SNGX=sigv4-e2e-snginx; C_SIDE=sigv4-e2e-sidecar
WORK="$(mktemp -d)"

cleanup() {
  docker rm -f "$C_BASE" "$C_MOD" "$C_SNGX" "$C_SIDE" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$SOCK" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Fixtures + configs (embedded, mirroring e2e/nginx_unix_socket_test.go)
# ---------------------------------------------------------------------------
mkdir -p "$WORK/origin/my-bucket/public" "$WORK/origin/my-bucket/private"
printf 'hello from e2e\n' > "$WORK/origin/my-bucket/public/file.txt"
printf 'secret should not be served\n' > "$WORK/origin/my-bucket/private/file.txt"

cat > "$WORK/baseline.conf" <<'EOF'
worker_processes 1;
events { worker_connections 1024; }
http {
    access_log off;
    error_log /dev/stderr error;
    server {
        listen 8080;
        server_name assets.example.test;
        location / { root /usr/share/nginx/html; try_files $uri =404; }
    }
}
EOF

cat > "$WORK/module.conf" <<'EOF'
load_module /etc/nginx/modules/ngx_http_sigv4_verify_module.so;
worker_processes 1;
events { worker_connections 1024; }
http {
    access_log off;
    error_log /dev/stderr error;
    sigv4_verify_clock_skew 5m;
    sigv4_verify_default_max_expires 10m;
    sigv4_verify_methods GET HEAD;
    sigv4_verify_log_denies on;
    sigv4_verify_credential e2e-access-key
        secret_key=e2e-secret-key
        allowed_host=assets.example.test
        allowed_method=GET allowed_method=HEAD
        allowed_prefix=/my-bucket/public/;
    server {
        listen 8080;
        server_name assets.example.test;
        location / {
            sigv4_verify on;
            root /usr/share/nginx/html;
            try_files $uri =404;
        }
    }
}
EOF

cat > "$WORK/sidecar.conf" <<'EOF'
worker_processes 1;
events { worker_connections 1024; }
http {
    access_log off;
    error_log /dev/stderr notice;
    upstream sigv4_verify { server unix:/sock/sigv4-verify.sock; keepalive 16; }
    server {
        listen 8080;
        server_name assets.example.test;
        location = /_sidecar_health {
            proxy_pass http://sigv4_verify/healthz;
            proxy_method GET; proxy_http_version 1.1; proxy_set_header Connection "";
            proxy_pass_request_body off; proxy_set_header Content-Length "";
            proxy_connect_timeout 100ms; proxy_send_timeout 250ms; proxy_read_timeout 250ms;
        }
        location = /_verify_sigv4 {
            internal;
            proxy_pass http://sigv4_verify/verify;
            proxy_method GET; proxy_http_version 1.1; proxy_set_header Connection "";
            proxy_pass_request_body off; proxy_set_header Content-Length "";
            proxy_set_header X-Original-Method $request_method;
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Original-Host $host;
            proxy_set_header X-Original-Scheme $scheme;
            proxy_connect_timeout 100ms; proxy_send_timeout 250ms; proxy_read_timeout 250ms;
        }
        location / {
            auth_request /_verify_sigv4;
            root /usr/share/nginx/html;
            try_files $uri =404;
        }
    }
}
EOF

cat > "$WORK/sidecar.yaml" <<'EOF'
server:
  network: "unix"
  listen: "/sock/sigv4-verify.sock"
  socket_mode: "666"
  read_header_timeout: 1s
  read_timeout: 2s
  write_timeout: 2s
  idle_timeout: 30s
verification:
  allowed_clock_skew: 5m
  default_max_expires: 10m
logging:
  log_denies: true
credentials:
  - access_key: "e2e-access-key"
    secret_key: "e2e-secret-key"
    enabled: true
    max_expires: 10m
    allowed_hosts:
      - "assets.example.test"
    allowed_methods:
      - GET
      - HEAD
    allowed_prefixes:
      - "/my-bucket/public/"
EOF

# ---------------------------------------------------------------------------
# Build images
# ---------------------------------------------------------------------------
echo "==> building module image ($IMG_MOD) ..."
docker build -f build/nginx-module/Dockerfile -t "$IMG_MOD" . >/dev/null

echo "==> building sidecar image ..."
mkdir -p "$WORK/side"
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o "$WORK/side/sigv4-verify" ./cmd/sigv4-verify
printf 'FROM scratch\nCOPY sigv4-verify /sigv4-verify\nENTRYPOINT ["/sigv4-verify"]\n' > "$WORK/side/Dockerfile"
docker build -t "$IMG_SIDE" "$WORK/side" >/dev/null

echo "==> building loadgen image ..."
mkdir -p "$WORK/load"
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o "$WORK/load/loadgen" ./cmd/loadgen
printf 'FROM scratch\nCOPY loadgen /loadgen\nENTRYPOINT ["/loadgen"]\n' > "$WORK/load/Dockerfile"
docker build -t "$IMG_LOAD" "$WORK/load" >/dev/null

# ---------------------------------------------------------------------------
# Bring up stacks
# ---------------------------------------------------------------------------
docker network create "$NET" >/dev/null
docker volume create "$SOCK" >/dev/null

docker run -d --name "$C_BASE" --network "$NET" \
  -v "$WORK/baseline.conf:/etc/nginx/nginx.conf:ro" -v "$WORK/origin:/usr/share/nginx/html:ro" \
  "nginx:${NGINX_VERSION}" >/dev/null
docker run -d --name "$C_MOD" --network "$NET" \
  -v "$WORK/module.conf:/etc/nginx/nginx.conf:ro" -v "$WORK/origin:/usr/share/nginx/html:ro" \
  "$IMG_MOD" >/dev/null
docker run -d --name "$C_SIDE" --network "$NET" \
  -e CONFIG_PATH=/config.yaml -e GODEBUG=gctrace=1 \
  -v "$WORK/sidecar.yaml:/config.yaml:ro" -v "$SOCK:/sock" "$IMG_SIDE" >/dev/null
docker run -d --name "$C_SNGX" --network "$NET" \
  -v "$WORK/sidecar.conf:/etc/nginx/nginx.conf:ro" -v "$WORK/origin:/usr/share/nginx/html:ro" -v "$SOCK:/sock" \
  "nginx:${NGINX_VERSION}" >/dev/null

echo "==> waiting for stacks ..."
sleep 4
for c in "$C_BASE" "$C_MOD" "$C_SNGX" "$C_SIDE"; do
  [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = "true" ] || { echo "container $c not running"; docker logs "$c" | tail -20; exit 1; }
done

# ---------------------------------------------------------------------------
# Corpora
# ---------------------------------------------------------------------------
URL="$(SIGV4_ACCESS_KEY=e2e-access-key SIGV4_SECRET_KEY=e2e-secret-key \
  go run ./cmd/presign-url -endpoint "$HOST" -bucket my-bucket -object public/file.txt \
  -method GET -region us-east-1 -expiry 9m -secure=false)"
printf 'GET %s\n' "${URL#http://$HOST}" > "$WORK/corpus-single.txt"
go run ./cmd/gen-barrage -n "$N" -o "$WORK/corpus.txt"

# ---------------------------------------------------------------------------
# Measurement engine
# ---------------------------------------------------------------------------
cgdir()   { local id; id="$(docker inspect -f '{{.Id}}' "$1")"; find /sys/fs/cgroup -maxdepth 4 -type d -name "*$id*" 2>/dev/null | head -1; }
cpuusec() { awk '/usage_usec/{print $2}' "$1/cpu.stat" 2>/dev/null || echo 0; }
memcur()  { cat "$1/memory.current" 2>/dev/null || echo 0; }
field()   { awk -v k="$1" '/^requests=/{for(i=1;i<=NF;i++){n=index($i,"=");if(substr($i,1,n-1)==k)print substr($i,n+1)}}' "$2"; }

# run_stack <label> <corpus> <conns> <dur> <nginx-container> [sidecar-container]
run_stack() {
  local label=$1 corpus=$2 conns=$3 dur=$4 ngx=$5 side=${6:-}
  local out="$WORK/$label.out"
  local ngxdir sidedir; ngxdir="$(cgdir "$ngx")"; [ -n "$side" ] && sidedir="$(cgdir "$side")"

  local gc0=0; [ -n "$side" ] && gc0="$(docker logs "$side" 2>&1 | grep -c '^gc ' || true)"
  local rssf; rssf="$(mktemp)"
  ( for _ in $(seq 1 $((dur+2))); do printf '%s %s\n' "$(memcur "$ngxdir")" "${sidedir:+$(memcur "$sidedir")}" >> "$rssf"; sleep 1; done ) &
  local sampler=$!

  local t0 c0n c0s; t0="$(date +%s.%N)"; c0n="$(cpuusec "$ngxdir")"; [ -n "$side" ] && c0s="$(cpuusec "$sidedir")"
  docker run --rm --network "$NET" -v "$corpus:/urls.txt:ro" "$IMG_LOAD" \
    -corpus /urls.txt -base "http://$ngx:8080" -host "$HOST" -c "$conns" -warmup 5s -d "${dur}s" > "$out" 2>&1
  local t1 c1n c1s; t1="$(date +%s.%N)"; c1n="$(cpuusec "$ngxdir")"; [ -n "$side" ] && c1s="$(cpuusec "$sidedir")"
  kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true

  local gcd="—"; [ -n "$side" ] && gcd="$(( $(docker logs "$side" 2>&1 | grep -c '^gc ' || true) - gc0 ))"
  local wall coresn rssn; wall="$(awk "BEGIN{print $t1-$t0}")"
  coresn="$(awk "BEGIN{printf \"%.2f\",($c1n-$c0n)/1e6/$wall}")"
  rssn="$(awk '{if($1>m)m=$1}END{printf "%.1f",m/1048576}' "$rssf")"
  local rps p50 p90 p99 p999 status
  rps="$(field rps "$out")"; p50="$(field p50 "$out")"; p90="$(field p90 "$out")"; p99="$(field p99 "$out")"; p999="$(field p99.9 "$out")"
  status="$(sed -nE 's/^status: (.*)/\1/p' "$out")"

  if [ -n "$side" ]; then
    local coress rsss; coress="$(awk "BEGIN{printf \"%.2f\",($c1s-$c0s)/1e6/$wall}")"; rsss="$(awk '{if($2>m)m=$2}END{printf "%.1f",m/1048576}' "$rssf")"
    printf '%-9s RPS=%-8s p50=%s p90=%s p99=%s p99.9=%s ms | CPU=%s+%s cores | RSS=%s+%s MiB | GC=%s\n' "$label" "$rps" "$p50" "$p90" "$p99" "$p999" "$coresn" "$coress" "$rssn" "$rsss" "$gcd"
  else
    printf '%-9s RPS=%-8s p50=%s p90=%s p99=%s p99.9=%s ms | CPU=%s cores | RSS=%s MiB\n' "$label" "$rps" "$p50" "$p90" "$p99" "$p999" "$coresn" "$rssn"
  fi
  printf '          decisions: %s\n' "$status"
  rm -f "$rssf"
}

echo
echo "=== FIRST PASS: single hot valid GET, all-200 (c=$C_FIRST, ${DUR_FIRST}s) ==="
run_stack baseline "$WORK/corpus-single.txt" "$C_FIRST" "$DUR_FIRST" "$C_BASE"
run_stack module   "$WORK/corpus-single.txt" "$C_FIRST" "$DUR_FIRST" "$C_MOD"
run_stack sidecar  "$WORK/corpus-single.txt" "$C_FIRST" "$DUR_FIRST" "$C_SNGX" "$C_SIDE"

echo
echo "=== BARRAGE: 500-line mixed corpus, ~35% reject (c=$C_BARR, ${DUR_BARR}s) ==="
run_stack baseline "$WORK/corpus.txt" "$C_BARR" "$DUR_BARR" "$C_BASE"
run_stack module   "$WORK/corpus.txt" "$C_BARR" "$DUR_BARR" "$C_MOD"
run_stack sidecar  "$WORK/corpus.txt" "$C_BARR" "$DUR_BARR" "$C_SNGX" "$C_SIDE"
echo
echo "done."
