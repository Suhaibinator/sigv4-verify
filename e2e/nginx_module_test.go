//go:build e2e

package e2e

// End-to-end tests for the native Rust NGINX module
// (ngx_http_sigv4_verify_module). Unlike the sidecar tests, there is no
// separate verifier process: the module runs inside the NGINX worker in the
// access phase. The module image is built from build/nginx-module/Dockerfile.
//
// Shared helpers, constants, and the minio presigner come from
// nginx_unix_socket_test.go (same package).

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	shadowHost = "shadow.example.test"
	openHost   = "open.example.test"

	reloadAccessKeyA = "reload-access-key-a"
	reloadSecretKeyA = "reload-secret-key-a"
	reloadAccessKeyB = "reload-access-key-b"
	reloadSecretKeyB = "reload-secret-key-b"
)

func TestNginxModuleE2E(t *testing.T) {
	// The docker build downloads the nginx source and Rust crates and compiles
	// the module; that dominates the runtime. Run with a generous timeout,
	// e.g. `go test -tags e2e -run TestNginxModuleE2E -timeout 30m ./e2e/`.
	ctx, cancel := context.WithTimeout(context.Background(), 28*time.Minute)
	defer cancel()

	requireDocker(t, ctx)

	root := repoRoot(t)
	image := "sigv4-verify-module-e2e:" + uniqueID()
	buildModuleImage(t, ctx, root, image)
	t.Cleanup(func() { cleanupDocker("image", "rm", "-f", image) })

	t.Run("config validation", func(t *testing.T) {
		testModuleConfigValidation(t, ctx, image)
	})
	t.Run("verification", func(t *testing.T) {
		testModuleVerification(t, ctx, image)
	})
	t.Run("reload swaps credentials", func(t *testing.T) {
		testModuleReload(t, ctx, image)
	})
}

// testModuleVerification runs the enforce/shadow/off request matrix against a
// single running container.
func testModuleVerification(t *testing.T, ctx context.Context, image string) {
	workDir := tempWorkDir(t)
	defer os.RemoveAll(workDir)

	confDir := filepath.Join(workDir, "conf")
	writeFile(t, filepath.Join(confDir, "nginx.conf"), []byte(moduleNginxConf(accessKey)))
	writeFile(t, filepath.Join(confDir, "secret"), []byte(secretKey+"\n"))

	originDir := filepath.Join(workDir, "origin")
	writeOriginFixtures(t, originDir)

	port := freePort(t)
	name := "sigv4-module-e2e-" + uniqueID()
	runModuleContainer(t, ctx, image, name, port, confDir, originDir, false)

	client := &http.Client{Timeout: 10 * time.Second}
	// The "off" server always serves without a signature; use it as a readiness
	// probe that never expires.
	waitForStatus(t, client, port, http.MethodGet, "/my-bucket/public/file.txt", openHost, "", http.StatusOK)

	p := newPresigner(t, publicHost)
	otherHostPresigner := newPresigner(t, "other.example.test")

	expiredURI := p.presign(t, http.MethodGet, "public/file.txt", time.Second, nil)
	// Also presign the shadow case (valid signature bound to publicHost, but
	// delivered to the shadow vhost) up front for a stable comparison.
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
			name:       "valid presigned GET returns 200 with body",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusOK,
			wantBody:   "hello from e2e\n",
		},
		{
			name:       "valid presigned HEAD returns 200 no body",
			method:     http.MethodHead,
			requestURI: p.presign(t, http.MethodHead, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusOK,
			wantNoBody: true,
		},
		{
			name:       "valid auth with origin miss returns 404",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "public/missing.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusNotFound,
		},
		{
			name:   "raw path and response query params preserved",
			method: http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "public/a b+file.txt", 5*time.Minute, url.Values{
				"response-content-disposition": {`attachment; filename="a b+file.txt"`},
			}),
			host:       publicHost,
			wantStatus: http.StatusOK,
			wantBody:   "encoded path fixture\n",
		},
		{
			name:       "GET on HEAD-signed URL returns 403",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodHead, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unsupported method POST returns 403",
			method:     http.MethodPost,
			requestURI: p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			body:       "body must not be read",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing SigV4 query returns 403",
			method:     http.MethodGet,
			requestURI: "/my-bucket/public/file.txt",
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "tampered signature returns 403",
			method:     http.MethodGet,
			requestURI: tamperSignature(p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil)),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "expired presign returns 403",
			method:     http.MethodGet,
			requestURI: expiredURI,
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "host mismatch returns 403",
			method:     http.MethodGet,
			requestURI: otherHostPresigner.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "prefix policy denial returns 403",
			method:     http.MethodGet,
			requestURI: p.presign(t, http.MethodGet, "private/file.txt", 5*time.Minute, nil),
			host:       publicHost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "disabled module location passes through",
			method:     http.MethodGet,
			requestURI: "/my-bucket/public/file.txt",
			host:       openHost,
			wantStatus: http.StatusOK,
			wantBody:   "hello from e2e\n",
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

	t.Run("shadow mode allows and records result in access log", func(t *testing.T) {
		// A signature bound to publicHost delivered to the shadow vhost fails
		// verification (host not allowed), but shadow mode allows the request
		// and the file is served. The module still records the outcome.
		requestURI := p.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil)
		status, body := requestThroughNginx(t, client, port, http.MethodGet, requestURI, shadowHost, "")
		if status != http.StatusOK {
			t.Fatalf("shadow status = %d, want 200, body=%q", status, body)
		}
		if string(body) != "hello from e2e\n" {
			t.Fatalf("shadow body = %q, want served file", body)
		}

		line := waitForAccessLogLine(t, ctx, name, func(line string) bool {
			return strings.Contains(line, "host="+shadowHost) && strings.Contains(line, "result=shadow")
		})
		if !strings.Contains(line, "reason=unauthorized") {
			t.Fatalf("shadow access log line missing expected reason: %q", line)
		}
	})

	t.Run("good config passes nginx -t", func(t *testing.T) {
		out, err := dockerRun(ctx, "--rm",
			"-v", confDir+":/etc/sigv4:ro",
			"-v", originDir+":/usr/share/nginx/html:ro",
			image, "nginx", "-t", "-c", "/etc/sigv4/nginx.conf")
		if err != nil {
			t.Fatalf("nginx -t on good config failed: %v\n%s", err, out)
		}
	})
}

// testModuleConfigValidation asserts that an invalid module configuration is
// rejected by `nginx -t` (fail-closed at config time, not at request time).
func testModuleConfigValidation(t *testing.T, ctx context.Context, image string) {
	workDir := tempWorkDir(t)
	defer os.RemoveAll(workDir)

	// sigv4_verify is enabled but no credential is configured: the module must
	// reject this at config load rather than fail open per-request.
	badConf := `load_module /etc/nginx/modules/ngx_http_sigv4_verify_module.so;
worker_processes 1;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 8080;
        server_name assets.example.test;
        location / {
            sigv4_verify on;
        }
    }
}
`
	confDir := filepath.Join(workDir, "conf")
	writeFile(t, filepath.Join(confDir, "nginx.conf"), []byte(badConf))

	out, err := dockerRun(ctx, "--rm",
		"-v", confDir+":/etc/sigv4:ro",
		image, "nginx", "-t", "-c", "/etc/sigv4/nginx.conf")
	if err == nil {
		t.Fatalf("nginx -t accepted an invalid config; output:\n%s", out)
	}
	if !strings.Contains(out, "sigv4_verify") {
		t.Fatalf("nginx -t failed but not for the expected reason; output:\n%s", out)
	}
}

// testModuleReload rewrites the mounted secret + credential, reloads NGINX, and
// asserts the swap took effect without crashing a worker.
func testModuleReload(t *testing.T, ctx context.Context, image string) {
	workDir := tempWorkDir(t)
	defer os.RemoveAll(workDir)

	confDir := filepath.Join(workDir, "conf")
	confPath := filepath.Join(confDir, "nginx.conf")
	secretPath := filepath.Join(confDir, "secret")
	writeFile(t, confPath, []byte(moduleNginxConf(reloadAccessKeyA)))
	writeFile(t, secretPath, []byte(reloadSecretKeyA+"\n"))

	originDir := filepath.Join(workDir, "origin")
	writeOriginFixtures(t, originDir)

	port := freePort(t)
	name := "sigv4-module-reload-" + uniqueID()
	runModuleContainer(t, ctx, image, name, port, confDir, originDir, false)

	client := &http.Client{Timeout: 10 * time.Second}
	waitForStatus(t, client, port, http.MethodGet, "/my-bucket/public/file.txt", openHost, "", http.StatusOK)

	presignerA := newPresignerCreds(t, publicHost, reloadAccessKeyA, reloadSecretKeyA)
	presignerB := newPresignerCreds(t, publicHost, reloadAccessKeyB, reloadSecretKeyB)

	// Expiry must stay under the credential's max_expires (10m); the reload
	// completes in seconds.
	uriA := presignerA.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil)
	if status, body := requestThroughNginx(t, client, port, http.MethodGet, uriA, publicHost, ""); status != http.StatusOK {
		t.Fatalf("credential A request before reload: status = %d, want 200, body=%q", status, body)
	}

	// Swap the credential in place (same inode, so the bind mount reflects it)
	// and reload.
	writeFile(t, secretPath, []byte(reloadSecretKeyB+"\n"))
	writeFile(t, confPath, []byte(moduleNginxConf(reloadAccessKeyB)))
	if out, err := dockerExec(ctx, name, "nginx", "-c", "/etc/sigv4/nginx.conf", "-s", "reload"); err != nil {
		t.Fatalf("nginx -s reload failed: %v\n%s", err, out)
	}

	// Wait for the new credential to be served, then confirm the old one is
	// rejected. Reload drains old workers, so poll both outcomes.
	uriB := presignerB.presign(t, http.MethodGet, "public/file.txt", 5*time.Minute, nil)
	waitForRequestStatus(t, client, port, http.MethodGet, uriB, publicHost, http.StatusOK)
	waitForRequestStatus(t, client, port, http.MethodGet, uriA, publicHost, http.StatusForbidden)

	// The worker must not have crashed during reload.
	running, err := dockerInspectRunning(ctx, name)
	if err != nil {
		t.Fatalf("inspect container running state: %v", err)
	}
	if !running {
		t.Fatalf("container %s is not running after reload", name)
	}
	logs, err := dockerLogs(ctx, name)
	if err != nil {
		t.Fatalf("read container logs: %v", err)
	}
	if strings.Contains(logs, "worker process exited on signal") {
		t.Fatalf("a worker crashed during reload; logs:\n%s", logs)
	}
}

// ---------------------------------------------------------------------------
// Module container + docker helpers
// ---------------------------------------------------------------------------

func buildModuleImage(t *testing.T, ctx context.Context, root, image string) {
	t.Helper()
	t.Logf("building module image %s (this downloads nginx source + Rust crates and compiles the module; expect several minutes)", image)
	out, err := dockerRunDir(ctx, root, "build",
		"-f", "build/nginx-module/Dockerfile",
		"-t", image, ".")
	if err != nil {
		t.Fatalf("docker build module image failed: %v\n%s", err, out)
	}
	if size, err := dockerImageSize(ctx, image); err == nil {
		t.Logf("module image %s built: %d bytes (%.1f MB)", image, size, float64(size)/(1024*1024))
	}
}

func runModuleContainer(t *testing.T, ctx context.Context, image, name string, port int, confDir, originDir string, readOnlyConf bool) {
	t.Helper()
	confMount := confDir + ":/etc/sigv4"
	if readOnlyConf {
		confMount += ":ro"
	}
	args := []string{"run", "-d",
		"--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", port),
		"-v", confMount,
		"-v", originDir + ":/usr/share/nginx/html:ro",
		image,
		"nginx", "-c", "/etc/sigv4/nginx.conf", "-g", "daemon off;",
	}
	run(t, ctx, "", "docker", args...)
	t.Cleanup(func() { cleanupDocker("rm", "-f", name) })
	dumpLogsOnFailure(t, name)
}

// waitForRequestStatus polls a single request URI until it returns want or the
// deadline passes.
func waitForRequestStatus(t *testing.T, client *http.Client, port int, method, requestURI, host string, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastStatus int
	for time.Now().Before(deadline) {
		lastStatus, _ = requestThroughNginx(t, client, port, method, requestURI, host, "")
		if lastStatus == want {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s %s (host %s) to return %d, last status=%d", method, requestURI, host, want, lastStatus)
}

// waitForAccessLogLine reads the module access log inside the container until a
// line matching pred appears.
func waitForAccessLogLine(t *testing.T, ctx context.Context, container string, pred func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastLog string
	for time.Now().Before(deadline) {
		out, err := dockerExec(ctx, container, "cat", "/var/log/nginx/sigv4_access.log")
		if err == nil {
			lastLog = out
			for _, line := range strings.Split(out, "\n") {
				if pred(line) {
					return line
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for matching access log line; log was:\n%s", lastLog)
	return ""
}

func dockerRun(ctx context.Context, args ...string) (string, error) {
	return dockerRunDir(ctx, "", append([]string{"run"}, args...)...)
}

func dockerExec(ctx context.Context, container string, args ...string) (string, error) {
	return dockerRunDir(ctx, "", append([]string{"exec", container}, args...)...)
}

func dockerLogs(ctx context.Context, container string) (string, error) {
	return dockerRunDir(ctx, "", "logs", container)
}

func dockerInspectRunning(ctx context.Context, container string) (bool, error) {
	out, err := dockerRunDir(ctx, "", "inspect", "-f", "{{.State.Running}}", container)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "true", nil
}

func dockerImageSize(ctx context.Context, image string) (int64, error) {
	out, err := dockerRunDir(ctx, "", "image", "inspect", "-f", "{{.Size}}", image)
	if err != nil {
		return 0, err
	}
	var size int64
	if _, err := fmt.Sscan(strings.TrimSpace(out), &size); err != nil {
		return 0, err
	}
	return size, nil
}

// dockerRunDir runs a docker subcommand from dir and returns combined output.
func dockerRunDir(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func newPresignerCreds(t *testing.T, endpoint, ak, sk string) presigner {
	t.Helper()
	client, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(ak, sk, ""),
		Secure:       false,
		Region:       region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("minio.New(%q): %v", endpoint, err)
	}
	return presigner{client: client}
}

// moduleNginxConf renders the module nginx.conf. accessKeyID selects the
// configured credential so the reload test can swap it.
func moduleNginxConf(accessKeyID string) string {
	return fmt.Sprintf(`load_module /etc/nginx/modules/ngx_http_sigv4_verify_module.so;

worker_processes 1;

events {
    worker_connections 1024;
}

http {
    error_log /dev/stderr notice;

    log_format sigv4 'result=$sigv4_verify_result reason=$sigv4_verify_reason '
                     'akh=$sigv4_verify_access_key_hash lat=$sigv4_verify_latency_us '
                     'method=$request_method host=$host uri=$request_uri status=$status';
    access_log /var/log/nginx/sigv4_access.log sigv4;

    sigv4_verify_clock_skew 5m;
    sigv4_verify_default_max_expires 15m;
    sigv4_verify_methods GET HEAD;
    sigv4_verify_log_denies on;

    sigv4_verify_credential %s
        secret_key_file=/etc/sigv4/secret
        enabled=on
        max_expires=10m
        allowed_host=%s
        allowed_method=GET
        allowed_method=HEAD
        allowed_prefix=/my-bucket/public/;

    server {
        listen 8080;
        server_name %s;
        root /usr/share/nginx/html;
        location / {
            sigv4_verify on;
            try_files $uri =404;
        }
    }

    server {
        listen 8080;
        server_name %s;
        root /usr/share/nginx/html;
        location / {
            sigv4_verify shadow;
            try_files $uri =404;
        }
    }

    server {
        listen 8080;
        server_name %s;
        root /usr/share/nginx/html;
        location / {
            sigv4_verify off;
            try_files $uri =404;
        }
    }
}
`, accessKeyID, publicHost, publicHost, shadowHost, openHost)
}
