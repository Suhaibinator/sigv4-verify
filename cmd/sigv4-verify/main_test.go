package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/suhaibinator/sigv4-verify/internal/config"
)

func TestListenUnixCreatesSocketWithMode(t *testing.T) {
	socketPath := shortTempSocketPath(t)
	listener, cleanup, err := listen(config.Server{
		Network:    config.NetworkUnix,
		Listen:     socketPath,
		SocketMode: 0o600,
	})
	if err != nil {
		t.Fatalf("listen() error = %v", err)
	}
	defer cleanup()
	defer listener.Close()

	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a unix socket: %s", socketPath, info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
}

func TestListenUnixRejectsActiveSocket(t *testing.T) {
	socketPath := shortTempSocketPath(t)
	active, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer active.Close()

	if _, _, err := listen(config.Server{
		Network:    config.NetworkUnix,
		Listen:     socketPath,
		SocketMode: 0o600,
	}); err == nil {
		t.Fatal("listen() error = nil, want active socket error")
	}
}

func TestListenUnixRemovesStaleSocket(t *testing.T) {
	socketPath := shortTempSocketPath(t)
	stale, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale listener: %v", err)
	}

	listener, cleanup, err := listen(config.Server{
		Network:    config.NetworkUnix,
		Listen:     socketPath,
		SocketMode: 0o600,
	})
	if err != nil {
		t.Fatalf("listen() error = %v", err)
	}
	defer cleanup()
	defer listener.Close()
}

func shortTempSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "sigv4-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.Join(dir, "s.sock")
}
