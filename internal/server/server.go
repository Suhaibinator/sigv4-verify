package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/suhaibinator/sigv4-verify/internal/metrics"
	"github.com/suhaibinator/sigv4-verify/internal/verifier"
)

type Server struct {
	verifier  *verifier.Verifier
	metrics   *metrics.Metrics
	logger    *slog.Logger
	logAll    atomic.Bool
	logDenies atomic.Bool
}

func New(v *verifier.Verifier, m *metrics.Metrics, logger *slog.Logger, logAll, logDenies bool) *Server {
	s := &Server{
		verifier: v,
		metrics:  m,
		logger:   logger,
	}
	s.UpdateLogging(logAll, logDenies)
	return s
}

func (s *Server) UpdateLogging(logAll, logDenies bool) {
	s.logAll.Store(logAll)
	s.logDenies.Store(logDenies)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/metrics", s.handleMetrics)
	return mux
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.metrics.Begin()
	defer func() {
		if rec := recover(); rec != nil {
			s.metrics.End("error", "error", time.Since(start))
			s.logger.Error("verify panic", "error", rec)
			http.Error(w, "internal error\n", http.StatusInternalServerError)
		}
	}()

	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if requestID != "" {
		w.Header().Set("X-Request-ID", requestID)
	}
	if r.Method != http.MethodGet {
		s.finishVerify(w, r, start, requestID, verifier.Result{Reason: verifier.ReasonUnsupportedMethod}, http.StatusForbidden)
		return
	}

	result := s.verifier.Verify(
		r.Header.Get("X-Original-Method"),
		r.Header.Get("X-Original-URI"),
		r.Header.Get("X-Original-Host"),
		r.Header.Get("X-Original-Scheme"),
		time.Now(),
	)
	if result.Allowed {
		s.finishVerify(w, r, start, requestID, result, http.StatusNoContent)
		return
	}
	s.finishVerify(w, r, start, requestID, result, http.StatusForbidden)
}

func (s *Server) finishVerify(w http.ResponseWriter, r *http.Request, start time.Time, requestID string, result verifier.Result, status int) {
	duration := time.Since(start)
	outcome := "deny"
	if status >= 500 {
		outcome = "error"
	} else if result.Allowed {
		outcome = "allow"
	}
	s.metrics.End(outcome, result.Reason, duration)
	s.metrics.IncReason(result.Reason)

	if s.shouldLog(result.Allowed) {
		s.logger.Info("verify",
			"request_id", requestID,
			"method", r.Header.Get("X-Original-Method"),
			"host", r.Header.Get("X-Original-Host"),
			"path", result.Path,
			"access_key_hash", result.AccessKeyHash,
			"result", outcome,
			"reason", result.Reason,
			"latency_us", duration.Microseconds(),
			"client_ip", clientIP(r),
		)
	}

	if status == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if result.Reason != "" {
		w.Header().Set("X-SigV4-Verify-Reason", result.Reason)
	}
	http.Error(w, "forbidden\n", status)
}

func (s *Server) shouldLog(allowed bool) bool {
	if s.logAll.Load() {
		return true
	}
	return !allowed && s.logDenies.Load()
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !s.verifier.Ready() {
		http.Error(w, "not ready\n", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.WritePrometheus(w)
}

func clientIP(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); value != "" {
		return value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); value != "" {
		if first, _, ok := strings.Cut(value, ","); ok {
			return strings.TrimSpace(first)
		}
		return value
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
