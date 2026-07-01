//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	publicHost = "assets.example.test"
	accessKey  = "e2e-access-key"
	secretKey  = "e2e-secret-key"
	region     = "us-east-1"
	bucket     = "my-bucket"
)

func TestNginxUnixSocketE2E(t *testing.T) {
	runNginxE2E(t, transportUnixSocket)
}

func TestNginxTCPE2E(t *testing.T) {
	runNginxE2E(t, transportTCP)
}

type transportMode string

const (
	transportUnixSocket transportMode = "unix_socket"
	transportTCP        transportMode = "tcp"
)

func runNginxE2E(t *testing.T, mode transportMode) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	requireDocker(t, ctx)

	root := repoRoot(t)
	workDir := tempWorkDir(t)
	defer os.RemoveAll(workDir)

	originDir := filepath.Join(workDir, "origin")
	writeOriginFixtures(t, originDir)

	configPath := filepath.Join(workDir, "config.yaml")
	writeFile(t, configPath, []byte(sidecarConfig(mode)))

	nginxPath := filepath.Join(workDir, "nginx.conf")
	writeFile(t, nginxPath, []byte(nginxConfig(mode)))

	id := uniqueID()
	sidecarImage := "sigv4-verify-e2e:" + id
	sidecarName := "sigv4-verify-e2e-sidecar-" + id
	nginxName := "sigv4-verify-e2e-nginx-" + id
	socketVolume := "sigv4-verify-e2e-sock-" + id
	networkName := "sigv4-verify-e2e-net-" + id

	if mode == transportUnixSocket {
		run(t, ctx, "", "docker", "volume", "create", socketVolume)
		t.Cleanup(func() { cleanupDocker("volume", "rm", "-f", socketVolume) })
	}
	if mode == transportTCP {
		run(t, ctx, "", "docker", "network", "create", networkName)
		t.Cleanup(func() { cleanupDocker("network", "rm", networkName) })
	}

	buildSidecarImage(t, ctx, root, workDir, sidecarImage)
	t.Cleanup(func() { cleanupDocker("image", "rm", "-f", sidecarImage) })

	sidecarArgs := []string{"run", "-d",
		"--name", sidecarName,
		"-e", "CONFIG_PATH=/config.yaml",
		"-v", configPath + ":/config.yaml:ro",
	}
	switch mode {
	case transportUnixSocket:
		sidecarArgs = append(sidecarArgs, "-v", socketVolume+":/sock")
	case transportTCP:
		sidecarArgs = append(sidecarArgs, "--network", networkName, "--network-alias", "sigv4-sidecar")
	default:
		t.Fatalf("unsupported transport mode %q", mode)
	}
	sidecarArgs = append(sidecarArgs, sidecarImage)
	run(t, ctx, "", "docker", sidecarArgs...)
	t.Cleanup(func() { cleanupDocker("rm", "-f", sidecarName) })
	dumpLogsOnFailure(t, sidecarName)

	port := freePort(t)
	nginxImage := getenvDefault("E2E_NGINX_IMAGE", "nginx:1.27-alpine")
	nginxArgs := []string{"run", "-d",
		"--name", nginxName,
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", port),
		"-v", nginxPath + ":/etc/nginx/nginx.conf:ro",
		"-v", originDir + ":/usr/share/nginx/html:ro",
	}
	switch mode {
	case transportUnixSocket:
		nginxArgs = append(nginxArgs, "-v", socketVolume+":/sock")
	case transportTCP:
		nginxArgs = append(nginxArgs, "--network", networkName)
	}
	nginxArgs = append(nginxArgs, nginxImage)
	run(t, ctx, "", "docker", nginxArgs...)
	t.Cleanup(func() { cleanupDocker("rm", "-f", nginxName) })
	dumpLogsOnFailure(t, nginxName)

	client := &http.Client{Timeout: 5 * time.Second}
	waitForStatus(t, client, port, "GET", "/_sidecar_health", publicHost, "", http.StatusOK)

	p := newPresigner(t, publicHost)
	otherHostPresigner := newPresigner(t, "other.example.test")

	expiredURI := p.presign(t, http.MethodGet, "public/file.txt", time.Second, nil)
	time.Sleep(2100 * time.Millisecond)

	tests := []struct {
		name       string
		method     string
		requestURI string
		host       string
		body       string
		wantStatus int
		wantBody   string
		wantNoBody bool
	}{
		{
			name:       "happy GET",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusOK,
			wantBody:   "hello from e2e\n",
		},
		{
			name:       "happy HEAD",
			method:     http.MethodHead,
			requestURI: p.presign(t, http.MethodHead, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusOK,
			wantNoBody: true,
		},
		{
			name:       "valid auth with origin miss",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "public/missing.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusNotFound,
		},
		{
			name:   "raw path and query are preserved",
			method: http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "public/a b+file.txt", 5*time.Minute, url.Values{
				"response-content-disposition": {`attachment; filename="a b+file.txt"`},
			}),
			host:       publicHost,
			wantStatus: http.StatusOK,
			wantBody:   "encoded path fixture\n",
		},
		{
			name:       "method binding enforced",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodHead, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unsupported client method",
			method:     http.MethodPost,
			requestURI: p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			body:       "body must not be forwarded to auth",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing SigV4 query",
			method:     http.MethodGet,
			requestURI: "/my-bucket/public/file.txt",
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "tampered signature",
			method:     http.MethodGet,
			requestURI: tamperSignature(p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil)),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "expired presign",
			method:     http.MethodGet,
			requestURI: expiredURI,
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "host mismatch",
			method:     http.MethodGet,
			requestURI: otherHostPresigner.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "prefix policy denial",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "private/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "internal auth endpoint is not public",
			method:     http.MethodGet,
			requestURI: "/_verify_sigv4",
			host:       publicHost,
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := requestThroughNginx(t, client, port, tt.method, tt.requestURI, tt.host, tt.body)
			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%q", status, tt.wantStatus, body)
			}
			if tt.wantBody != "" && string(body) != tt.wantBody {
				t.Fatalf("body = %q, want %q", body, tt.wantBody)
			}
			if tt.wantNoBody && len(body) != 0 {
				t.Fatalf("body length = %d, want 0, body=%q", len(body), body)
			}
		})
	}

	t.Run("verifier unavailable fails closed", func(t *testing.T) {
		run(t, ctx, "", "docker", "rm", "-f", sidecarName)
		requestURI := p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil)

		status, body := requestThroughNginx(t, client, port, http.MethodGet, requestURI, publicHost, "")
		if status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d, body=%q", status, http.StatusInternalServerError, body)
		}
	})
}

type presigner struct {
	client *minio.Client
}

func newPresigner(t *testing.T, endpoint string) presigner {
	t.Helper()
	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       false,
		Region:       region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("minio.New(%q): %v", endpoint, err)
	}
	return presigner{client: client}
}

func (p presigner) presign(t *testing.T, method, object string, expiry time.Duration, params url.Values) string {
	t.Helper()
	var (
		u   *url.URL
		err error
	)
	switch method {
	case http.MethodGet:
		u, err = p.client.PresignedGetObject(context.Background(), bucket, object, expiry, params)
	case http.MethodHead:
		u, err = p.client.PresignedHeadObject(context.Background(), bucket, object, expiry, params)
	default:
		t.Fatalf("unsupported presign method %q", method)
	}
	if err != nil {
		t.Fatalf("presign %s %s: %v", method, object, err)
	}
	return u.RequestURI()
}

func sidecarConfig(mode transportMode) string {
	server := `server:
  network: "tcp"
  listen: ":8080"
`
	if mode == transportUnixSocket {
		server = `server:
  network: "unix"
  listen: "/sock/sigv4-verify.sock"
  socket_mode: "666"
`
	}
	return fmt.Sprintf(`%s  read_header_timeout: 1s
  read_timeout: 2s
  write_timeout: 2s
  idle_timeout: 30s

verification:
  allowed_clock_skew: 5m
  default_max_expires: 10m

logging:
  log_denies: true

credentials:
  - access_key: %q
    secret_key: %q
    enabled: true
    max_expires: 10m
    allowed_hosts:
      - %q
    allowed_methods:
      - GET
      - HEAD
    allowed_prefixes:
      - "/my-bucket/public/"
`, server, accessKey, secretKey, publicHost)
}

func nginxConfig(mode transportMode) string {
	upstreamServer := "sigv4-sidecar:8080"
	if mode == transportUnixSocket {
		upstreamServer = "unix:/sock/sigv4-verify.sock"
	}
	return fmt.Sprintf(`worker_processes 1;

events {
    worker_connections 1024;
}

http {
    access_log off;
    error_log /dev/stderr notice;

    upstream sigv4_verify {
        server %s;
        keepalive 16;
    }

    server {
        listen 8080;
        server_name assets.example.test;

        location = /_sidecar_health {
            proxy_pass http://sigv4_verify/healthz;
            proxy_method GET;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_connect_timeout 100ms;
            proxy_send_timeout 250ms;
            proxy_read_timeout 250ms;
        }

        location = /_verify_sigv4 {
            internal;

            proxy_pass http://sigv4_verify/verify;
            proxy_method GET;
            proxy_http_version 1.1;
            proxy_set_header Connection "";

            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            proxy_set_header X-Original-Method $request_method;
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Original-Host $host;
            proxy_set_header X-Original-Scheme $scheme;

            proxy_connect_timeout 100ms;
            proxy_send_timeout 250ms;
            proxy_read_timeout 250ms;
        }

        location / {
            auth_request /_verify_sigv4;
            root /usr/share/nginx/html;
            try_files $uri =404;
        }
    }
}
`, upstreamServer)
}

func buildSidecarImage(t *testing.T, ctx context.Context, root, workDir, image string) {
	t.Helper()
	buildDir := filepath.Join(workDir, "image")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		t.Fatalf("create docker build dir: %v", err)
	}

	goarch := getenvDefault("E2E_GOARCH", runtime.GOARCH)
	binaryPath := filepath.Join(buildDir, "sigv4-verify")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", binaryPath, "./cmd/sigv4-verify")
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+goarch,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build sidecar image binary: %v\n%s", err, out)
	}

	writeFile(t, filepath.Join(buildDir, "Dockerfile"), []byte(`FROM scratch
COPY sigv4-verify /sigv4-verify
ENTRYPOINT ["/sigv4-verify"]
`))
	run(t, ctx, "", "docker", "build", "-t", image, buildDir)
}

func writeOriginFixtures(t *testing.T, originDir string) {
	t.Helper()
	writeFile(t, filepath.Join(originDir, "my-bucket", "public", "file.txt"), []byte("hello from e2e\n"))
	writeFile(t, filepath.Join(originDir, "my-bucket", "public", "a b+file.txt"), []byte("encoded path fixture\n"))
	writeFile(t, filepath.Join(originDir, "my-bucket", "private", "file.txt"), []byte("secret should not be served\n"))
}

func requestThroughNginx(t *testing.T, client *http.Client, port int, method, requestURI, host, body string) (int, []byte) {
	t.Helper()
	if !strings.HasPrefix(requestURI, "/") {
		t.Fatalf("request URI %q must start with /", requestURI)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, requestURI), strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, requestURI, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, data
}

func waitForStatus(t *testing.T, client *http.Client, port int, method, requestURI, host, body string, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastStatus int
	var lastBody []byte
	var lastErr error
	for time.Now().Before(deadline) {
		func() {
			req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, requestURI), strings.NewReader(body))
			if err != nil {
				lastErr = err
				return
			}
			req.Host = host
			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				return
			}
			defer resp.Body.Close()
			lastStatus = resp.StatusCode
			lastBody, _ = io.ReadAll(resp.Body)
			lastErr = nil
		}()
		if lastErr == nil && lastStatus == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to return %d, last status=%d err=%v body=%q", requestURI, want, lastStatus, lastErr, lastBody)
}

func tamperSignature(requestURI string) string {
	const key = "X-Amz-Signature="
	idx := strings.Index(requestURI, key)
	if idx < 0 {
		return requestURI
	}
	start := idx + len(key)
	end := strings.IndexByte(requestURI[start:], '&')
	if end < 0 {
		end = len(requestURI)
	} else {
		end += start
	}
	if start == end {
		return requestURI
	}
	last := requestURI[end-1]
	replacement := byte('0')
	if last == '0' {
		replacement = '1'
	}
	var b bytes.Buffer
	b.Grow(len(requestURI))
	b.WriteString(requestURI[:end-1])
	b.WriteByte(replacement)
	b.WriteString(requestURI[end:])
	return b.String()
}

func requireDocker(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		dockerUnavailable(t, "docker is not installed: %v", err)
	}
	cmd := exec.CommandContext(ctx, "docker", "info")
	if out, err := cmd.CombinedOutput(); err != nil {
		dockerUnavailable(t, "docker daemon is not available: %v\n%s", err, out)
	}
}

func dockerUnavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	if truthy(os.Getenv("CI")) || truthy(os.Getenv("E2E_STRICT")) {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(file))
}

func tempWorkDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		if info, err := os.Stat("/private/tmp"); err == nil && info.IsDir() {
			base = "/private/tmp"
		}
	}
	dir, err := os.MkdirTemp(base, "sigv4-verify-e2e-")
	if err != nil {
		t.Fatalf("create temp work dir: %v", err)
	}
	return dir
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create parent dir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func run(t *testing.T, ctx context.Context, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func cleanupDocker(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", args...).Run()
}

func dumpLogsOnFailure(t *testing.T, container string) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "logs", container)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("docker logs %s failed: %v\n%s", container, err, out)
			return
		}
		t.Logf("docker logs %s:\n%s", container, out)
	})
}

func uniqueID() string {
	raw := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	raw = strings.ReplaceAll(raw, "-", "")
	if len(raw) > 20 {
		return raw[len(raw)-20:]
	}
	return raw
}

func getenvDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	default:
		return false
	}
}
