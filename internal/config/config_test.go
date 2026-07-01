package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadYAMLConfig(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte("secret-value\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	data := []byte(`
server:
  network: "tcp"
  listen: "127.0.0.1:9090"
  socket_mode: "660"
  read_header_timeout: "750ms"
  read_timeout: "2s"
  write_timeout: "3s"
  idle_timeout: "45s"
  max_header_bytes: "16384"

verification:
  allowed_clock_skew: "2m"
  default_max_expires: "30m"
  supported_methods:
    - GET
    - HEAD
  supported_service: "s3"

logging:
  log_all_requests: true
  log_denies: false

credentials:
  - access_key: "asset-reader"
    secret_key_file: "` + secretPath + `"
    enabled: true
    max_expires: "10m"
    allowed_hosts:
      - "assets.example.com"
    allowed_methods:
      - GET
    allowed_prefixes:
      - "/bucket/public/"
`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9090" {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.Network != NetworkTCP {
		t.Fatalf("network = %q", cfg.Server.Network)
	}
	if cfg.Server.SocketMode != 0o660 {
		t.Fatalf("socket mode = %o", cfg.Server.SocketMode)
	}
	if cfg.Server.ReadHeaderTimeout != 750*time.Millisecond || cfg.Server.MaxHeaderBytes != 16384 {
		t.Fatalf("server settings not parsed: %+v", cfg.Server)
	}
	if cfg.Verification.AllowedClockSkew != 2*time.Minute || cfg.Verification.DefaultMaxExpires != 30*time.Minute {
		t.Fatalf("verification settings not parsed: %+v", cfg.Verification)
	}
	if !cfg.Logging.LogAllRequests || cfg.Logging.LogDenies {
		t.Fatalf("logging settings not parsed: %+v", cfg.Logging)
	}
	if len(cfg.Credentials) != 1 {
		t.Fatalf("credentials len = %d", len(cfg.Credentials))
	}
	cred := cfg.Credentials[0]
	if cred.AccessKey != "asset-reader" || cred.SecretKey != "secret-value" || !cred.Enabled {
		t.Fatalf("credential not parsed: %+v", cred)
	}
	if cred.MaxExpires != 10*time.Minute {
		t.Fatalf("max expires = %s", cred.MaxExpires)
	}
}

func TestLoadEnvConfig(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "sigv4-verify.sock")
	t.Setenv("NETWORK", "unix")
	t.Setenv("ADDR", socketPath)
	t.Setenv("SIGV4_SOCKET_MODE", "600")
	t.Setenv("SIGV4_ACCESS_KEY", "env-reader")
	t.Setenv("SIGV4_SECRET_KEY", "env-secret")
	t.Setenv("SIGV4_ALLOWED_HOSTS", "assets.example.com,cdn.example.com")
	t.Setenv("SIGV4_ALLOWED_PREFIXES", "/bucket/a/,/bucket/b/")
	t.Setenv("SIGV4_ALLOWED_METHODS", "GET,HEAD")
	t.Setenv("SIGV4_MAX_EXPIRES", "15m")
	t.Setenv("SIGV4_DEFAULT_MAX_EXPIRES", "30m")
	t.Setenv("SIGV4_CLOCK_SKEW", "1m")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.Network != NetworkUnix {
		t.Fatalf("network = %q", cfg.Server.Network)
	}
	if cfg.Server.Listen != socketPath {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.SocketMode != 0o600 {
		t.Fatalf("socket mode = %o", cfg.Server.SocketMode)
	}
	if cfg.Verification.AllowedClockSkew != time.Minute || cfg.Verification.DefaultMaxExpires != 30*time.Minute {
		t.Fatalf("verification settings not parsed: %+v", cfg.Verification)
	}
	if len(cfg.Credentials) != 1 {
		t.Fatalf("credentials len = %d", len(cfg.Credentials))
	}
	cred := cfg.Credentials[0]
	if cred.AccessKey != "env-reader" || cred.SecretKey != "env-secret" || !cred.Enabled {
		t.Fatalf("credential not parsed: %+v", cred)
	}
	if cred.MaxExpires != 15*time.Minute {
		t.Fatalf("max expires = %s", cred.MaxExpires)
	}
	if len(cred.AllowedHosts) != 2 || len(cred.AllowedPrefixes) != 2 || len(cred.AllowedMethods) != 2 {
		t.Fatalf("policy lists not parsed: %+v", cred)
	}
}

func TestLoadRejectsDuplicateAccessKeys(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	data := []byte(`
credentials:
  - access_key: "dup"
    secret_key: "a"
  - access_key: "dup"
    secret_key: "b"
`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(configPath); err == nil {
		t.Fatal("Load() error = nil, want duplicate access key error")
	}
}

func TestLoadRejectsInlineCredentialList(t *testing.T) {
	for _, field := range []string{"allowed_hosts", "allowed_methods", "allowed_prefixes"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.yaml")
			data := []byte(`
credentials:
  - access_key: "reader"
    secret_key: "secret"
    ` + field + `: ["assets.example.com"]
`)
			if err := os.WriteFile(configPath, data, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			// An inline flow-style list must be rejected rather than silently dropped,
			// which would leave the allow-list empty and fail open.
			if _, err := Load(configPath); err == nil {
				t.Fatal("Load() error = nil, want inline credential list error")
			}
		})
	}
}

func TestLoadRejectsUnixNetworkWithoutListen(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	data := []byte(`
server:
  network: "unix"

credentials:
  - access_key: "reader"
    secret_key: "secret"
`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(configPath); err == nil {
		t.Fatal("Load() error = nil, want unix listen error")
	}
}
