// Command gen-barrage generates the mixed adversarial benchmark corpus used by
// the NGINX e2e "barrage" in docs/benchmarks.md. It presigns URLs with the
// MinIO SDK (path-style, us-east-1) against the fixed e2e credential and emits a
// deterministically shuffled file of "METHOD /request-uri" lines with a
// documented traffic mix (55% valid, 10% high-cardinality valid, 5% long path,
// 10% tampered, 5% expired, 5% unknown key, 5% prefix deny, 3% missing param,
// 2% POST). This is benchmark tooling, not part of the shipped product.
//
//	go run ./cmd/gen-barrage -n 500 -o /path/to/corpus.txt
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	host    = "assets.example.test"
	region  = "us-east-1"
	bucket  = "my-bucket"
	realKey = "e2e-access-key"
	realSec = "e2e-secret-key"
)

func newClient(access, secret string) *minio.Client {
	c, err := minio.New(host, &minio.Options{
		Creds:        credentials.NewStaticV4(access, secret, ""),
		Secure:       false,
		Region:       region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "minio.New:", err)
		os.Exit(1)
	}
	return c
}

func presign(c *minio.Client, method, object string, expiry time.Duration, params url.Values) string {
	var (
		u   *url.URL
		err error
	)
	switch method {
	case "GET":
		u, err = c.PresignedGetObject(context.Background(), bucket, object, expiry, params)
	case "HEAD":
		u, err = c.PresignedHeadObject(context.Background(), bucket, object, expiry, params)
	default:
		fmt.Fprintln(os.Stderr, "unsupported presign method", method)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "presign %s %s: %v\n", method, object, err)
		os.Exit(1)
	}
	return u.RequestURI()
}

// tamper flips the last hex digit of the X-Amz-Signature value.
func tamper(uri string) string {
	const key = "X-Amz-Signature="
	i := strings.Index(uri, key)
	if i < 0 {
		return uri
	}
	start := i + len(key)
	end := start
	for end < len(uri) && uri[end] != '&' {
		end++
	}
	if end == start {
		return uri
	}
	repl := byte('0')
	if uri[end-1] == '0' {
		repl = '1'
	}
	return uri[:end-1] + string(repl) + uri[end:]
}

// removeParam drops a single query parameter by name.
func removeParam(uri, name string) string {
	path, query, ok := strings.Cut(uri, "?")
	if !ok {
		return uri
	}
	parts := strings.Split(query, "&")
	kept := parts[:0]
	for _, p := range parts {
		k, _, _ := strings.Cut(p, "=")
		if k == name {
			continue
		}
		kept = append(kept, p)
	}
	return path + "?" + strings.Join(kept, "&")
}

func main() {
	var (
		n   = flag.Int("n", 500, "total number of request lines")
		out = flag.String("o", "", "output file (required)")
	)
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-o is required")
		os.Exit(2)
	}

	real := newClient(realKey, realSec)
	ghost := newClient("AKIAUNKNOWNKEY000000", "unknown-secret-000")

	// Mix as fractions of n (see docs/benchmarks.md barrage).
	type cat struct {
		name string
		frac float64
	}
	cats := []cat{
		{"valid", 0.55},        // valid GET, unique response-content-disposition, warm cache
		{"highcard", 0.10},     // valid GET, multiple unique response-content-* params
		{"longpath", 0.05},     // valid GET, ~1KB key, origin 404 (non-2xx but not a verify reject)
		{"tampered", 0.10},     // flipped signature -> 403
		{"expired", 0.05},      // expiry=1s, stale by run time -> 403
		{"unknownkey", 0.05},   // signed by a key absent from config -> 403
		{"prefixdeny", 0.05},   // valid signature, object outside allowed prefix -> 403
		{"missingparam", 0.03}, // X-Amz-Signature removed -> 403
		{"post", 0.02},         // valid GET signature, sent as POST -> 403
	}

	type line struct{ method, uri string }
	var lines []line
	longKey := "public/" + strings.Repeat("a", 1000) + ".bin"
	counts := map[string]int{}
	idx := 0
	for _, ct := range cats {
		want := int(ct.frac*float64(*n) + 0.5)
		for range want {
			idx++
			counts[ct.name]++
			disp := url.Values{"response-content-disposition": {fmt.Sprintf(`attachment; filename="f-%d.txt"`, idx)}}
			switch ct.name {
			case "valid":
				lines = append(lines, line{"GET", presign(real, "GET", "public/file.txt", 9*time.Minute, disp)})
			case "highcard":
				p := url.Values{
					"response-content-disposition": {fmt.Sprintf(`attachment; filename="hc-%d.txt"`, idx)},
					"response-content-type":        {fmt.Sprintf("application/x-bench-%d", idx)},
					"response-content-language":    {fmt.Sprintf("en-%d", idx)},
					"response-cache-control":       {fmt.Sprintf("max-age=%d", idx)},
				}
				lines = append(lines, line{"GET", presign(real, "GET", "public/file.txt", 9*time.Minute, p)})
			case "longpath":
				lines = append(lines, line{"GET", presign(real, "GET", longKey, 9*time.Minute, nil)})
			case "tampered":
				lines = append(lines, line{"GET", tamper(presign(real, "GET", "public/file.txt", 9*time.Minute, disp))})
			case "expired":
				lines = append(lines, line{"GET", presign(real, "GET", "public/file.txt", 1*time.Second, disp)})
			case "unknownkey":
				lines = append(lines, line{"GET", presign(ghost, "GET", "public/file.txt", 9*time.Minute, disp)})
			case "prefixdeny":
				lines = append(lines, line{"GET", presign(real, "GET", "private/file.txt", 9*time.Minute, disp)})
			case "missingparam":
				lines = append(lines, line{"GET", removeParam(presign(real, "GET", "public/file.txt", 9*time.Minute, disp), "X-Amz-Signature")})
			case "post":
				lines = append(lines, line{"POST", presign(real, "GET", "public/file.txt", 9*time.Minute, disp)})
			}
		}
	}

	// Deterministic shuffle so the mix is interleaved for round-robin replay.
	r := rand.New(rand.NewSource(42))
	r.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })

	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.method)
		b.WriteByte(' ')
		b.WriteString(l.uri)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}

	reject := counts["tampered"] + counts["expired"] + counts["unknownkey"] + counts["prefixdeny"] + counts["missingparam"] + counts["post"]
	non2xx := reject + counts["longpath"]
	fmt.Fprintf(os.Stderr, "wrote %d lines to %s\n", len(lines), *out)
	for _, ct := range cats {
		fmt.Fprintf(os.Stderr, "  %-13s %d\n", ct.name, counts[ct.name])
	}
	fmt.Fprintf(os.Stderr, "verify rejects (403): %d (%.1f%%)\n", reject, 100*float64(reject)/float64(len(lines)))
	fmt.Fprintf(os.Stderr, "non-2xx incl long-path 404: %d (%.1f%%)\n", non2xx, 100*float64(non2xx)/float64(len(lines)))
}
