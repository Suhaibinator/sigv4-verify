package metrics

import (
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"time"
)

var reasons = []string{
	"ok",
	"missing_metadata",
	"invalid_uri",
	"unsupported_method",
	"missing_query_param",
	"unsupported_algorithm",
	"invalid_credential_scope",
	"unknown_access_key",
	"invalid_expiry",
	"expired",
	"future_dated",
	"unsupported_signed_header",
	"signature_mismatch",
	"unauthorized",
	"error",
	"other",
}

var results = []string{"allow", "deny", "error"}

var durationBuckets = []float64{
	0.00005,
	0.0001,
	0.00025,
	0.0005,
	0.001,
	0.002,
	0.005,
	0.01,
	0.025,
	0.05,
	0.1,
	1,
}

type Metrics struct {
	requests          [][]atomic.Uint64
	durationBuckets   []atomic.Uint64
	durationCount     atomic.Uint64
	durationSumMicros atomic.Uint64
	inflight          atomic.Int64
	credentialsLoaded atomic.Int64
	reloadSuccess     atomic.Uint64
	reloadFailure     atomic.Uint64
	unknownAccessKey  atomic.Uint64
	signatureMismatch atomic.Uint64
	expired           atomic.Uint64
}

func New() *Metrics {
	m := &Metrics{
		requests:        make([][]atomic.Uint64, len(results)),
		durationBuckets: make([]atomic.Uint64, len(durationBuckets)+1),
	}
	for i := range m.requests {
		m.requests[i] = make([]atomic.Uint64, len(reasons))
	}
	return m
}

func (m *Metrics) Begin() {
	m.inflight.Add(1)
}

func (m *Metrics) End(result, reason string, duration time.Duration) {
	m.inflight.Add(-1)
	ri := resultIndex(result)
	reasonIdx := reasonIndex(reason)
	m.requests[ri][reasonIdx].Add(1)
	m.durationCount.Add(1)
	m.durationSumMicros.Add(uint64(duration.Microseconds()))
	seconds := duration.Seconds()
	for i, bucket := range durationBuckets {
		if seconds <= bucket {
			m.durationBuckets[i].Add(1)
			return
		}
	}
	m.durationBuckets[len(m.durationBuckets)-1].Add(1)
}

func (m *Metrics) IncReason(reason string) {
	switch reason {
	case "unknown_access_key":
		m.unknownAccessKey.Add(1)
	case "signature_mismatch":
		m.signatureMismatch.Add(1)
	case "expired":
		m.expired.Add(1)
	}
}

func (m *Metrics) SetCredentialsLoaded(n int) {
	m.credentialsLoaded.Store(int64(n))
}

func (m *Metrics) IncReload(success bool) {
	if success {
		m.reloadSuccess.Add(1)
		return
	}
	m.reloadFailure.Add(1)
}

func (m *Metrics) WritePrometheus(w io.Writer) {
	fmt.Fprintln(w, "# HELP sigv4_verify_requests_total Total verification requests.")
	fmt.Fprintln(w, "# TYPE sigv4_verify_requests_total counter")
	for resultIdx, result := range results {
		for reasonIdx, reason := range reasons {
			value := m.requests[resultIdx][reasonIdx].Load()
			if value == 0 {
				continue
			}
			fmt.Fprintf(w, "sigv4_verify_requests_total{result=%q,reason=%q} %d\n", result, reason, value)
		}
	}

	fmt.Fprintln(w, "# HELP sigv4_verify_duration_seconds Verification latency histogram.")
	fmt.Fprintln(w, "# TYPE sigv4_verify_duration_seconds histogram")
	var cumulative uint64
	for i, bucket := range durationBuckets {
		cumulative += m.durationBuckets[i].Load()
		fmt.Fprintf(w, "sigv4_verify_duration_seconds_bucket{le=%q} %d\n", strconv.FormatFloat(bucket, 'f', -1, 64), cumulative)
	}
	cumulative += m.durationBuckets[len(m.durationBuckets)-1].Load()
	fmt.Fprintf(w, "sigv4_verify_duration_seconds_bucket{le=%q} %d\n", "+Inf", cumulative)
	fmt.Fprintf(w, "sigv4_verify_duration_seconds_sum %.6f\n", float64(m.durationSumMicros.Load())/1_000_000)
	fmt.Fprintf(w, "sigv4_verify_duration_seconds_count %d\n", m.durationCount.Load())

	fmt.Fprintln(w, "# HELP sigv4_credentials_loaded Number of credentials currently loaded.")
	fmt.Fprintln(w, "# TYPE sigv4_credentials_loaded gauge")
	fmt.Fprintf(w, "sigv4_credentials_loaded %d\n", m.credentialsLoaded.Load())

	fmt.Fprintln(w, "# HELP sigv4_config_reload_total Config reload attempts.")
	fmt.Fprintln(w, "# TYPE sigv4_config_reload_total counter")
	fmt.Fprintf(w, "sigv4_config_reload_total{result=%q} %d\n", "success", m.reloadSuccess.Load())
	fmt.Fprintf(w, "sigv4_config_reload_total{result=%q} %d\n", "failure", m.reloadFailure.Load())

	fmt.Fprintln(w, "# HELP sigv4_inflight_requests In-flight verification requests.")
	fmt.Fprintln(w, "# TYPE sigv4_inflight_requests gauge")
	fmt.Fprintf(w, "sigv4_inflight_requests %d\n", m.inflight.Load())

	fmt.Fprintln(w, "# HELP sigv4_unknown_access_key_total Requests denied for unknown access keys.")
	fmt.Fprintln(w, "# TYPE sigv4_unknown_access_key_total counter")
	fmt.Fprintf(w, "sigv4_unknown_access_key_total %d\n", m.unknownAccessKey.Load())

	fmt.Fprintln(w, "# HELP sigv4_signature_mismatch_total Requests denied for signature mismatch.")
	fmt.Fprintln(w, "# TYPE sigv4_signature_mismatch_total counter")
	fmt.Fprintf(w, "sigv4_signature_mismatch_total %d\n", m.signatureMismatch.Load())

	fmt.Fprintln(w, "# HELP sigv4_expired_total Requests denied because the presigned URL expired.")
	fmt.Fprintln(w, "# TYPE sigv4_expired_total counter")
	fmt.Fprintf(w, "sigv4_expired_total %d\n", m.expired.Load())
}

func resultIndex(result string) int {
	for i, value := range results {
		if value == result {
			return i
		}
	}
	return len(results) - 1
}

func reasonIndex(reason string) int {
	for i, value := range reasons {
		if value == reason {
			return i
		}
	}
	return len(reasons) - 1
}
