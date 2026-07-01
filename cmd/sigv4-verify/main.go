package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/suhaibinator/sigv4-verify/internal/config"
	"github.com/suhaibinator/sigv4-verify/internal/metrics"
	"github.com/suhaibinator/sigv4-verify/internal/server"
	"github.com/suhaibinator/sigv4-verify/internal/verifier"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	configPath := os.Getenv("CONFIG_PATH")
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	v, err := verifier.New(toVerifierSettings(cfg), toVerifierCredentials(cfg))
	if err != nil {
		logger.Error("initialize verifier", "error", err)
		os.Exit(1)
	}
	m := metrics.New()
	m.SetCredentialsLoaded(v.CredentialCount())
	app := server.New(v, m, logger, cfg.Logging.LogAllRequests, cfg.Logging.LogDenies)

	httpServer := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}
	listener, cleanup, err := listen(cfg.Server)
	if err != nil {
		logger.Error("listen failed", "network", cfg.Server.Network, "listen", cfg.Server.Listen, "error", err)
		os.Exit(1)
	}
	defer cleanup()

	go handleReloads(configPath, v, m, app, logger)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "network", cfg.Server.Network, "listen", cfg.Server.Listen, "credentials_loaded", v.CredentialCount())
		errCh <- httpServer.Serve(listener)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		logger.Info("shutdown requested", "signal", sig.String())
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

func listen(server config.Server) (net.Listener, func(), error) {
	switch server.Network {
	case config.NetworkTCP:
		l, err := net.Listen("tcp", server.Listen)
		if err != nil {
			return nil, func() {}, err
		}
		return l, func() {}, nil
	case config.NetworkUnix:
		l, err := listenUnix(server.Listen, server.SocketMode)
		if err != nil {
			return nil, func() {}, err
		}
		return l, func() {
			_ = os.Remove(server.Listen)
		}, nil
	default:
		return nil, func() {}, fmt.Errorf("unsupported network %q", server.Network)
	}
}

func listenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("unix socket path is required")
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create socket directory: %w", err)
		}
	}
	if err := removeStaleUnixSocket(path); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = l.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod unix socket: %w", err)
	}
	return l, nil
}

func removeStaleUnixSocket(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a unix socket", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("%s is already accepting unix socket connections", path)
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !os.IsNotExist(dialErr) {
			return fmt.Errorf("probe unix socket: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale unix socket: %w", err)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("stat unix socket: %w", err)
}

func handleReloads(configPath string, v *verifier.Verifier, m *metrics.Metrics, app *server.Server, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		cfg, err := config.Load(configPath)
		if err != nil {
			m.IncReload(false)
			logger.Error("reload config failed", "error", err)
			continue
		}
		if err := v.Reload(toVerifierSettings(cfg), toVerifierCredentials(cfg)); err != nil {
			m.IncReload(false)
			logger.Error("reload verifier failed", "error", err)
			continue
		}
		app.UpdateLogging(cfg.Logging.LogAllRequests, cfg.Logging.LogDenies)
		m.SetCredentialsLoaded(v.CredentialCount())
		m.IncReload(true)
		logger.Info("reload complete", "credentials_loaded", v.CredentialCount())
	}
}

func toVerifierSettings(cfg *config.Config) verifier.Settings {
	return verifier.Settings{
		AllowedClockSkew:  cfg.Verification.AllowedClockSkew,
		DefaultMaxExpires: cfg.Verification.DefaultMaxExpires,
		SupportedMethods:  append([]string(nil), cfg.Verification.SupportedMethods...),
		SupportedService:  cfg.Verification.SupportedService,
	}
}

func toVerifierCredentials(cfg *config.Config) []verifier.Credential {
	out := make([]verifier.Credential, 0, len(cfg.Credentials))
	for _, credential := range cfg.Credentials {
		out = append(out, verifier.Credential{
			AccessKey:       credential.AccessKey,
			SecretKey:       credential.SecretKey,
			Enabled:         credential.Enabled,
			MaxExpires:      credential.MaxExpires,
			AllowedHosts:    append([]string(nil), credential.AllowedHosts...),
			AllowedMethods:  append([]string(nil), credential.AllowedMethods...),
			AllowedPrefixes: append([]string(nil), credential.AllowedPrefixes...),
		})
	}
	return out
}
