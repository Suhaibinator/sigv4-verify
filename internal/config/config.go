package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	NetworkTCP          = "tcp"
	NetworkUnix         = "unix"
	defaultNetwork      = NetworkTCP
	defaultListen       = "127.0.0.1:8080"
	defaultSocketMode   = 0o660
	defaultClockSkew    = 15 * time.Minute
	defaultMaxExpires   = 7 * 24 * time.Hour
	maxSigV4Expires     = 7 * 24 * time.Hour
	defaultReadHeaderTO = time.Second
	defaultReadTO       = 2 * time.Second
	defaultWriteTO      = 2 * time.Second
	defaultIdleTO       = 30 * time.Second
)

type Config struct {
	Server                Server
	Verification          Verification
	Logging               Logging
	Credentials           []Credential
	AllowEmptyCredentials bool
}

type Server struct {
	Network           string
	Listen            string
	SocketMode        os.FileMode
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

type Verification struct {
	AllowedClockSkew  time.Duration
	DefaultMaxExpires time.Duration
	SupportedMethods  []string
	SupportedService  string
}

type Logging struct {
	LogAllRequests bool
	LogDenies      bool
}

type Credential struct {
	AccessKey       string
	SecretKey       string
	Enabled         bool
	MaxExpires      time.Duration
	AllowedHosts    []string
	AllowedMethods  []string
	AllowedPrefixes []string
}

type rawConfig struct {
	Server                rawServer       `json:"server"`
	Verification          rawVerification `json:"verification"`
	Logging               rawLogging      `json:"logging"`
	Credentials           []rawCredential `json:"credentials"`
	AllowEmptyCredentials *bool           `json:"allow_empty_credentials"`
}

type rawServer struct {
	Network           string `json:"network"`
	Listen            string `json:"listen"`
	SocketMode        string `json:"socket_mode"`
	ReadHeaderTimeout string `json:"read_header_timeout"`
	ReadTimeout       string `json:"read_timeout"`
	WriteTimeout      string `json:"write_timeout"`
	IdleTimeout       string `json:"idle_timeout"`
	MaxHeaderBytes    string `json:"max_header_bytes"`
}

type rawVerification struct {
	AllowedClockSkew  string   `json:"allowed_clock_skew"`
	DefaultMaxExpires string   `json:"default_max_expires"`
	SupportedMethods  []string `json:"supported_methods"`
	SupportedService  string   `json:"supported_service"`
}

type rawLogging struct {
	LogAllRequests *bool `json:"log_all_requests"`
	LogDenies      *bool `json:"log_denies"`
}

type rawCredential struct {
	AccessKey         string   `json:"access_key"`
	SecretKey         string   `json:"secret_key"`
	SecretKeyEnv      string   `json:"secret_key_env"`
	SecretKeyFile     string   `json:"secret_key_file"`
	Enabled           *bool    `json:"enabled"`
	MaxExpires        string   `json:"max_expires"`
	MaxExpiresSeconds string   `json:"max_expires_seconds"`
	AllowedHosts      []string `json:"allowed_hosts"`
	AllowedMethods    []string `json:"allowed_methods"`
	AllowedPrefixes   []string `json:"allowed_prefixes"`
}

func Load(path string) (*Config, error) {
	var raw rawConfig
	if path == "" {
		raw = rawFromEnv()
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := parseConfigFile(path, data, &raw); err != nil {
			return nil, err
		}
	}

	if listen := strings.TrimSpace(os.Getenv("ADDR")); listen != "" {
		raw.Server.Listen = listen
	}
	if network := firstEnv("NETWORK", "SIGV4_NETWORK"); network != "" {
		raw.Server.Network = network
	}
	if socketMode := strings.TrimSpace(os.Getenv("SIGV4_SOCKET_MODE")); socketMode != "" {
		raw.Server.SocketMode = socketMode
	}
	return build(raw)
}

func rawFromEnv() rawConfig {
	enabled := true
	raw := rawConfig{
		Server: rawServer{
			Network:           firstEnv("NETWORK", "SIGV4_NETWORK"),
			Listen:            os.Getenv("ADDR"),
			SocketMode:        os.Getenv("SIGV4_SOCKET_MODE"),
			ReadHeaderTimeout: os.Getenv("SIGV4_READ_HEADER_TIMEOUT"),
			ReadTimeout:       os.Getenv("SIGV4_READ_TIMEOUT"),
			WriteTimeout:      os.Getenv("SIGV4_WRITE_TIMEOUT"),
			IdleTimeout:       os.Getenv("SIGV4_IDLE_TIMEOUT"),
			MaxHeaderBytes:    os.Getenv("SIGV4_MAX_HEADER_BYTES"),
		},
		Verification: rawVerification{
			AllowedClockSkew:  os.Getenv("SIGV4_CLOCK_SKEW"),
			DefaultMaxExpires: os.Getenv("SIGV4_DEFAULT_MAX_EXPIRES"),
			SupportedService:  "s3",
			SupportedMethods:  splitCSV(os.Getenv("SIGV4_SUPPORTED_METHODS")),
		},
		Logging: rawLogging{
			LogAllRequests: boolPtrFromEnv("SIGV4_LOG_ALL_REQUESTS"),
			LogDenies:      boolPtrFromEnv("SIGV4_LOG_DENIES"),
		},
		AllowEmptyCredentials: boolPtrFromEnv("SIGV4_ALLOW_EMPTY_CREDENTIALS"),
	}

	accessKey := strings.TrimSpace(os.Getenv("SIGV4_ACCESS_KEY"))
	if accessKey != "" {
		raw.Credentials = append(raw.Credentials, rawCredential{
			AccessKey:       accessKey,
			SecretKey:       os.Getenv("SIGV4_SECRET_KEY"),
			SecretKeyEnv:    os.Getenv("SIGV4_SECRET_KEY_ENV"),
			SecretKeyFile:   os.Getenv("SIGV4_SECRET_KEY_FILE"),
			Enabled:         &enabled,
			MaxExpires:      os.Getenv("SIGV4_MAX_EXPIRES"),
			AllowedHosts:    splitCSV(os.Getenv("SIGV4_ALLOWED_HOSTS")),
			AllowedMethods:  splitCSV(os.Getenv("SIGV4_ALLOWED_METHODS")),
			AllowedPrefixes: splitCSV(os.Getenv("SIGV4_ALLOWED_PREFIXES")),
		})
	}
	return raw
}

func parseConfigFile(path string, data []byte, raw *rawConfig) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(raw); err != nil {
			return fmt.Errorf("parse json config: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			if err == nil {
				return errors.New("parse json config: multiple JSON values")
			}
			return fmt.Errorf("parse json config: %w", err)
		}
		return nil
	default:
		if err := parseYAML(data, raw); err != nil {
			return fmt.Errorf("parse yaml config: %w", err)
		}
		return nil
	}
}

func build(raw rawConfig) (*Config, error) {
	cfg := Config{
		Server: Server{
			Network:           defaultNetwork,
			Listen:            defaultListen,
			SocketMode:        defaultSocketMode,
			ReadHeaderTimeout: defaultReadHeaderTO,
			ReadTimeout:       defaultReadTO,
			WriteTimeout:      defaultWriteTO,
			IdleTimeout:       defaultIdleTO,
			MaxHeaderBytes:    8 << 10,
		},
		Verification: Verification{
			AllowedClockSkew:  defaultClockSkew,
			DefaultMaxExpires: defaultMaxExpires,
			SupportedMethods:  []string{"GET", "HEAD"},
			SupportedService:  "s3",
		},
		Logging: Logging{
			LogDenies: true,
		},
	}

	if raw.AllowEmptyCredentials != nil {
		cfg.AllowEmptyCredentials = *raw.AllowEmptyCredentials
	}
	if raw.Server.Network != "" {
		cfg.Server.Network = strings.ToLower(strings.TrimSpace(raw.Server.Network))
	}
	switch cfg.Server.Network {
	case NetworkTCP, NetworkUnix:
	default:
		return nil, fmt.Errorf("server.network must be %q or %q", NetworkTCP, NetworkUnix)
	}
	if raw.Server.Listen != "" {
		cfg.Server.Listen = strings.TrimSpace(raw.Server.Listen)
	}
	if cfg.Server.Network == NetworkUnix && cfg.Server.Listen == defaultListen && raw.Server.Listen == "" {
		return nil, errors.New("server.listen is required when server.network is unix")
	}
	if raw.Server.SocketMode != "" {
		mode, err := parseFileMode(raw.Server.SocketMode)
		if err != nil {
			return nil, fmt.Errorf("server.socket_mode: %w", err)
		}
		cfg.Server.SocketMode = mode
	}
	if raw.Server.ReadHeaderTimeout != "" {
		d, err := parseDuration(raw.Server.ReadHeaderTimeout)
		if err != nil {
			return nil, fmt.Errorf("server.read_header_timeout: %w", err)
		}
		cfg.Server.ReadHeaderTimeout = d
	}
	if raw.Server.ReadTimeout != "" {
		d, err := parseDuration(raw.Server.ReadTimeout)
		if err != nil {
			return nil, fmt.Errorf("server.read_timeout: %w", err)
		}
		cfg.Server.ReadTimeout = d
	}
	if raw.Server.WriteTimeout != "" {
		d, err := parseDuration(raw.Server.WriteTimeout)
		if err != nil {
			return nil, fmt.Errorf("server.write_timeout: %w", err)
		}
		cfg.Server.WriteTimeout = d
	}
	if raw.Server.IdleTimeout != "" {
		d, err := parseDuration(raw.Server.IdleTimeout)
		if err != nil {
			return nil, fmt.Errorf("server.idle_timeout: %w", err)
		}
		cfg.Server.IdleTimeout = d
	}
	if raw.Server.MaxHeaderBytes != "" {
		n, err := strconv.Atoi(strings.TrimSpace(raw.Server.MaxHeaderBytes))
		if err != nil || n <= 0 {
			return nil, errors.New("server.max_header_bytes must be a positive integer")
		}
		cfg.Server.MaxHeaderBytes = n
	}

	if raw.Verification.AllowedClockSkew != "" {
		d, err := parseDuration(raw.Verification.AllowedClockSkew)
		if err != nil {
			return nil, fmt.Errorf("verification.allowed_clock_skew: %w", err)
		}
		if d < 0 {
			return nil, errors.New("verification.allowed_clock_skew must be non-negative")
		}
		cfg.Verification.AllowedClockSkew = d
	}
	if raw.Verification.DefaultMaxExpires != "" {
		d, err := parseDuration(raw.Verification.DefaultMaxExpires)
		if err != nil {
			return nil, fmt.Errorf("verification.default_max_expires: %w", err)
		}
		if d <= 0 || d > maxSigV4Expires {
			return nil, errors.New("verification.default_max_expires must be >0 and <=168h")
		}
		cfg.Verification.DefaultMaxExpires = d
	}
	if len(raw.Verification.SupportedMethods) > 0 {
		methods, err := normalizeMethods(raw.Verification.SupportedMethods)
		if err != nil {
			return nil, fmt.Errorf("verification.supported_methods: %w", err)
		}
		cfg.Verification.SupportedMethods = methods
	}
	if raw.Verification.SupportedService != "" {
		cfg.Verification.SupportedService = strings.TrimSpace(raw.Verification.SupportedService)
	}
	if cfg.Verification.SupportedService != "s3" {
		return nil, errors.New("verification.supported_service must be s3")
	}
	if raw.Logging.LogAllRequests != nil {
		cfg.Logging.LogAllRequests = *raw.Logging.LogAllRequests
	}
	if raw.Logging.LogDenies != nil {
		cfg.Logging.LogDenies = *raw.Logging.LogDenies
	}

	seen := make(map[string]struct{}, len(raw.Credentials))
	enabledCount := 0
	for i, rc := range raw.Credentials {
		cred, err := buildCredential(rc, cfg.Verification.DefaultMaxExpires)
		if err != nil {
			return nil, fmt.Errorf("credentials[%d]: %w", i, err)
		}
		if _, ok := seen[cred.AccessKey]; ok {
			return nil, fmt.Errorf("duplicate access key %q", cred.AccessKey)
		}
		seen[cred.AccessKey] = struct{}{}
		if cred.Enabled {
			enabledCount++
		}
		cfg.Credentials = append(cfg.Credentials, cred)
	}
	if enabledCount == 0 && !cfg.AllowEmptyCredentials {
		return nil, errors.New("no enabled credentials configured")
	}
	return &cfg, nil
}

func buildCredential(raw rawCredential, defaultMaxExpires time.Duration) (Credential, error) {
	accessKey := strings.TrimSpace(raw.AccessKey)
	if accessKey == "" {
		return Credential{}, errors.New("access_key is required")
	}
	enabled := true
	if raw.Enabled != nil {
		enabled = *raw.Enabled
	}
	secret, err := resolveSecret(raw)
	if err != nil {
		return Credential{}, err
	}
	maxExpires := defaultMaxExpires
	if raw.MaxExpiresSeconds != "" {
		secs, err := strconv.ParseInt(strings.TrimSpace(raw.MaxExpiresSeconds), 10, 64)
		if err != nil {
			return Credential{}, errors.New("max_expires_seconds must be an integer")
		}
		maxExpires = time.Duration(secs) * time.Second
	}
	if raw.MaxExpires != "" {
		maxExpires, err = parseDuration(raw.MaxExpires)
		if err != nil {
			return Credential{}, fmt.Errorf("max_expires: %w", err)
		}
	}
	if maxExpires <= 0 || maxExpires > maxSigV4Expires {
		return Credential{}, errors.New("max_expires must be >0 and <=168h")
	}

	methods, err := normalizeMethods(raw.AllowedMethods)
	if err != nil {
		return Credential{}, fmt.Errorf("allowed_methods: %w", err)
	}
	hosts := normalizeHosts(raw.AllowedHosts)
	prefixes, err := normalizePrefixes(raw.AllowedPrefixes)
	if err != nil {
		return Credential{}, fmt.Errorf("allowed_prefixes: %w", err)
	}
	return Credential{
		AccessKey:       accessKey,
		SecretKey:       secret,
		Enabled:         enabled,
		MaxExpires:      maxExpires,
		AllowedHosts:    hosts,
		AllowedMethods:  methods,
		AllowedPrefixes: prefixes,
	}, nil
}

func resolveSecret(raw rawCredential) (string, error) {
	sources := 0
	secret := raw.SecretKey
	if raw.SecretKey != "" {
		sources++
	}
	if raw.SecretKeyEnv != "" {
		sources++
		val := os.Getenv(strings.TrimSpace(raw.SecretKeyEnv))
		if val == "" {
			return "", fmt.Errorf("secret_key_env %q is empty or unset", raw.SecretKeyEnv)
		}
		secret = val
	}
	if raw.SecretKeyFile != "" {
		sources++
		data, err := os.ReadFile(strings.TrimSpace(raw.SecretKeyFile))
		if err != nil {
			return "", fmt.Errorf("read secret_key_file: %w", err)
		}
		secret = strings.TrimRight(string(data), "\r\n")
	}
	if sources == 0 {
		return "", errors.New("one of secret_key, secret_key_env, or secret_key_file is required")
	}
	if sources > 1 {
		return "", errors.New("only one secret source may be configured")
	}
	if secret == "" {
		return "", errors.New("secret key is empty")
	}
	return secret, nil
}

func parseDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("empty duration")
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}
	return time.ParseDuration(value)
}

func parseFileMode(value string) (os.FileMode, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("empty file mode")
	}
	value = strings.TrimPrefix(value, "0o")
	value = strings.TrimPrefix(value, "0O")
	value = strings.TrimPrefix(value, "0")
	if value == "" {
		return 0, errors.New("empty file mode")
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, errors.New("must be an octal permission like 660 or 0660")
	}
	if parsed > 0o777 {
		return 0, errors.New("must be between 0000 and 0777")
	}
	return os.FileMode(parsed), nil
}

func normalizeMethods(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		method := strings.ToUpper(strings.TrimSpace(value))
		if method == "" {
			continue
		}
		if method != "GET" && method != "HEAD" {
			return nil, fmt.Errorf("unsupported method %q", method)
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	return out, nil
}

func normalizeHosts(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		host := strings.ToLower(strings.TrimSpace(value))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func normalizePrefixes(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		prefix := strings.TrimSpace(value)
		if prefix == "" {
			continue
		}
		if !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("%q must start with /", prefix)
		}
		if strings.Contains(prefix, "//") || containsDotSegment(prefix) {
			return nil, fmt.Errorf("%q is ambiguous", prefix)
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
}

func containsDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func boolPtrFromEnv(name string) *bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil
	}
	return &parsed
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
