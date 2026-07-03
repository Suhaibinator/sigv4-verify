// Command loadgen is the HTTP load generator for the NGINX e2e benchmark in
// docs/benchmarks.md. It replays a file of "METHOD /request-uri" lines
// round-robin across N keep-alive connections for a fixed duration and reports
// RPS, latency percentiles (p50/p90/p99/p99.9), and the status-code
// distribution. It is meant to run in-network (a scratch container on the bench
// docker network). This is benchmark tooling, not part of the shipped product.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

func main() {
	var (
		corpus = flag.String("corpus", "", "file of 'METHOD /uri' lines (required)")
		base   = flag.String("base", "", "base URL, e.g. http://host:8080 (required)")
		host   = flag.String("host", "", "Host header to send")
		conns  = flag.Int("c", 64, "concurrent connections")
		dur    = flag.Duration("d", 60*time.Second, "measurement duration")
		warmup = flag.Duration("warmup", 5*time.Second, "warmup duration (not recorded)")
	)
	flag.Parse()
	if *corpus == "" || *base == "" {
		fmt.Fprintln(os.Stderr, "-corpus and -base are required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*corpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read corpus:", err)
		os.Exit(1)
	}
	type req struct{ method, uri string }
	var reqs []req
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m, u, ok := strings.Cut(line, " ")
		if !ok {
			m, u = "GET", line
		}
		reqs = append(reqs, req{m, u})
	}
	if len(reqs) == 0 {
		fmt.Fprintln(os.Stderr, "empty corpus")
		os.Exit(1)
	}

	transport := &http.Transport{
		MaxIdleConns:        *conns * 2,
		MaxIdleConnsPerHost: *conns,
		MaxConnsPerHost:     *conns,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	do := func(r req) (int, error) {
		hr, err := http.NewRequest(r.method, *base+r.uri, nil)
		if err != nil {
			return 0, err
		}
		if *host != "" {
			hr.Host = *host
		}
		resp, err := client.Do(hr)
		if err != nil {
			return 0, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}

	// phase runs c workers until the deadline. Each worker walks the corpus
	// round-robin from its own offset (no shared counter). Latencies and codes
	// are recorded only when record is true.
	phase := func(record bool, d time.Duration) ([]time.Duration, map[int]int, int) {
		deadline := time.Now().Add(d)
		var (
			mu     sync.Mutex
			allLat []time.Duration
			codes  = map[int]int{}
			errs   int
			wg     sync.WaitGroup
		)
		for w := range *conns {
			wg.Add(1)
			go func(offset int) {
				defer wg.Done()
				var (
					lat   []time.Duration
					lcode = map[int]int{}
					lerr  int
					i     = offset
				)
				for time.Now().Before(deadline) {
					r := reqs[i%len(reqs)]
					i += *conns
					t := time.Now()
					code, err := do(r)
					el := time.Since(t)
					if !record {
						continue
					}
					if err != nil {
						lerr++
						continue
					}
					lat = append(lat, el)
					lcode[code]++
				}
				if record {
					mu.Lock()
					allLat = append(allLat, lat...)
					for c, n := range lcode {
						codes[c] += n
					}
					errs += lerr
					mu.Unlock()
				}
			}(w)
		}
		wg.Wait()
		return allLat, codes, errs
	}

	// Prime a connection, warm up, then measure.
	_, _ = do(reqs[0])
	if *warmup > 0 {
		phase(false, *warmup)
	}
	start := time.Now()
	lat, codes, errs := phase(true, *dur)
	elapsed := time.Since(start)

	slices.Sort(lat)
	pctMs := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		idx := int(p / 100 * float64(len(lat)))
		if idx >= len(lat) {
			idx = len(lat) - 1
		}
		return float64(lat[idx].Microseconds()) / 1000.0
	}
	total := len(lat)
	rps := float64(total) / elapsed.Seconds()
	non2xx := 0
	for c, n := range codes {
		if c < 200 || c >= 300 {
			non2xx += n
		}
	}
	fmt.Printf("requests=%d duration=%.2f rps=%.0f p50=%.3f p90=%.3f p99=%.3f p99.9=%.3f errors=%d\n",
		total, elapsed.Seconds(), rps, pctMs(50), pctMs(90), pctMs(99), pctMs(99.9), errs)
	keys := make([]int, 0, len(codes))
	for c := range codes {
		keys = append(keys, c)
	}
	slices.Sort(keys)
	var sb strings.Builder
	for _, c := range keys {
		fmt.Fprintf(&sb, "%d=%d ", c, codes[c])
	}
	pctNon := 0.0
	if total > 0 {
		pctNon = 100 * float64(non2xx) / float64(total)
	}
	fmt.Printf("status: %snon2xx=%d (%.1f%%)\n", sb.String(), non2xx, pctNon)
}
