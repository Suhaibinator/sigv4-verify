// Command gen-corpus generates a differential-test corpus for the SigV4
// verifier. It presigns URLs with the MinIO SDK, applies a broad set of
// mutations, and records the Go verifier's decision (allowed + reason) for
// every case. The Rust verifier core replays the same corpus and must reach
// identical decisions (see rust/sigv4-verifier/tests/differential.rs).
//
// The Go verifier is the oracle: decisions are never hardcoded here, they are
// whatever internal/verifier returns. The verifier configuration below is
// fixed and mirrored byte-for-byte by the Rust test.
//
// Regenerate with:
//
//	go run ./cmd/gen-corpus
//
// or with an explicit output path:
//
//	go run ./cmd/gen-corpus path/to/corpus.jsonl
//
//go:generate go run . rust/sigv4-verifier/testdata/differential-corpus.jsonl
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/suhaibinator/sigv4-verify/internal/verifier"
)

const defaultOutput = "rust/sigv4-verifier/testdata/differential-corpus.jsonl"

// Hosts used across the corpus. Only assets/cdn appear in credential allow
// lists; evil is always outside them.
const (
	hostAssets = "assets.example.com"
	hostCDN    = "cdn.example.com"
	hostEvil   = "evil.example.com"
	region     = "us-east-1"
)

// Access keys and secrets for the fixed credential set. The Rust test hardcodes
// the same values.
const (
	keyUnrestricted = "AKIAUNRESTRICTED"
	keyDisabled     = "AKIADISABLED"
	keyHostOnly     = "AKIAHOSTONLY"
	keyGetOnly      = "AKIAGETONLY"
	keyPrefix       = "AKIAPREFIX"
	keyShortExp     = "AKIASHORTEXP"
	keyGhost        = "AKIAGHOST" // never configured; used for unknown-key cases

	secretUnrestricted = "unrestricted-secret-000"
	secretDisabled     = "disabled-secret-111"
	secretHostOnly     = "hostonly-secret-222"
	secretGetOnly      = "getonly-secret-333"
	secretPrefix       = "prefix-secret-444"
	secretShortExp     = "shortexp-secret-555"
	secretGhost        = "ghost-secret-666"
)

type corpusLine struct {
	Name    string `json:"name"`
	Method  string `json:"method"`
	URI     string `json:"uri"`
	Host    string `json:"host"`
	NowUnix int64  `json:"now_unix"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// generator holds the oracle verifier and accumulates corpus lines.
type generator struct {
	verifier *verifier.Verifier
	lines    []corpusLine
	seen     map[string]struct{}
}

func main() {
	output := defaultOutput
	if len(os.Args) > 1 {
		output = os.Args[1]
	}

	v, err := verifier.New(fixedSettings(), fixedCredentials())
	if err != nil {
		fmt.Fprintf(os.Stderr, "build verifier: %v\n", err)
		os.Exit(1)
	}
	g := &generator{verifier: v, seen: make(map[string]struct{})}

	if err := g.build(); err != nil {
		fmt.Fprintf(os.Stderr, "generate corpus: %v\n", err)
		os.Exit(1)
	}

	if err := g.write(output); err != nil {
		fmt.Fprintf(os.Stderr, "write corpus: %v\n", err)
		os.Exit(1)
	}

	g.printSummary(output)
}

// fixedSettings and fixedCredentials define the exact configuration the Rust
// test mirrors. Keep both sides in sync.
func fixedSettings() verifier.Settings {
	return verifier.Settings{
		AllowedClockSkew:  60 * time.Second,
		DefaultMaxExpires: time.Hour,
		SupportedMethods:  []string{"GET", "HEAD"},
		SupportedService:  "s3",
	}
}

func fixedCredentials() []verifier.Credential {
	return []verifier.Credential{
		{
			// Unrestricted-style: enabled with explicit (broad) allow lists.
			AccessKey:       keyUnrestricted,
			SecretKey:       secretUnrestricted,
			Enabled:         true,
			AllowedHosts:    []string{hostAssets, hostCDN},
			AllowedMethods:  []string{"GET", "HEAD"},
			AllowedPrefixes: []string{"/"},
		},
		{
			// Disabled: reached only through the enabled gate.
			AccessKey: keyDisabled,
			SecretKey: secretDisabled,
			Enabled:   false,
		},
		{
			// Host-restricted to assets only.
			AccessKey:    keyHostOnly,
			SecretKey:    secretHostOnly,
			Enabled:      true,
			AllowedHosts: []string{hostAssets},
		},
		{
			// Method-restricted to GET only.
			AccessKey:      keyGetOnly,
			SecretKey:      secretGetOnly,
			Enabled:        true,
			AllowedMethods: []string{"GET"},
		},
		{
			// Prefix-restricted to /public-bucket/.
			AccessKey:       keyPrefix,
			SecretKey:       secretPrefix,
			Enabled:         true,
			AllowedPrefixes: []string{"/public-bucket/"},
		},
		{
			// Short max expiry (60s).
			AccessKey:  keyShortExp,
			SecretKey:  secretShortExp,
			Enabled:    true,
			MaxExpires: 60 * time.Second,
		},
	}
}

func (g *generator) build() error {
	if err := g.validCases(); err != nil {
		return err
	}
	if err := g.credentialAndPolicyCases(); err != nil {
		return err
	}
	if err := g.mutationCases(); err != nil {
		return err
	}
	return nil
}

// validCases exercises the supported envelope across object keys, methods, and
// credentials that should ordinarily allow the request.
func (g *generator) validCases() error {
	objects := []struct {
		name string
		key  string
	}{
		{"plain", "file.jpg"},
		{"nested", "path/to/deep/report.pdf"},
		{"spaces", "a b.jpg"},
		{"plus", "a+b.jpg"},
		{"parens_space", "snapshot (1).png"},
		{"unicode", "café-münchen.jpg"},
		{"percent_literal", "a%2Fb"},
		{"tilde_dash", "a~b_c-d.jpg"},
	}

	for _, obj := range objects {
		for _, method := range []string{"GET", "HEAD"} {
			p, err := g.presign(presignSpec{
				accessKey: keyUnrestricted,
				secretKey: secretUnrestricted,
				host:      hostAssets,
				method:    method,
				bucket:    "assets",
				object:    obj.key,
				expiry:    5 * time.Minute,
			})
			if err != nil {
				return err
			}
			g.emit("valid_unrestricted_"+obj.name+"_"+strings.ToLower(method), method, p.uri, p.host, p.signTime.Unix())
		}
	}

	// Response query parameters baked into the signature.
	respParams := url.Values{}
	respParams.Set("response-content-disposition", `attachment; filename="a b.jpg"`)
	respParams.Set("response-content-type", "image/jpeg")
	p, err := g.presign(presignSpec{
		accessKey: keyUnrestricted,
		secretKey: secretUnrestricted,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
		params:    respParams,
	})
	if err != nil {
		return err
	}
	g.emit("valid_response_params", "GET", p.uri, p.host, p.signTime.Unix())

	// Repeated non-singleton parameter baked into the signature.
	repeated := url.Values{"partNumber": {"1", "2"}}
	p, err = g.presign(presignSpec{
		accessKey: keyUnrestricted,
		secretKey: secretUnrestricted,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
		params:    repeated,
	})
	if err != nil {
		return err
	}
	g.emit("valid_repeated_part_number", "GET", p.uri, p.host, p.signTime.Unix())

	// Second allowed host for the unrestricted credential.
	p, err = g.presign(presignSpec{
		accessKey: keyUnrestricted,
		secretKey: secretUnrestricted,
		host:      hostCDN,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("valid_unrestricted_cdn_host", "GET", p.uri, p.host, p.signTime.Unix())

	// Host-restricted credential on its allowed host.
	for _, method := range []string{"GET", "HEAD"} {
		p, err := g.presign(presignSpec{
			accessKey: keyHostOnly,
			secretKey: secretHostOnly,
			host:      hostAssets,
			method:    method,
			bucket:    "assets",
			object:    "file.jpg",
			expiry:    5 * time.Minute,
		})
		if err != nil {
			return err
		}
		g.emit("valid_host_restricted_"+strings.ToLower(method), method, p.uri, p.host, p.signTime.Unix())
	}

	// Method-restricted credential using GET.
	p, err = g.presign(presignSpec{
		accessKey: keyGetOnly,
		secretKey: secretGetOnly,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("valid_method_restricted_get", "GET", p.uri, p.host, p.signTime.Unix())

	// Prefix-restricted credential inside its allowed prefix.
	for _, method := range []string{"GET", "HEAD"} {
		p, err := g.presign(presignSpec{
			accessKey: keyPrefix,
			secretKey: secretPrefix,
			host:      hostAssets,
			method:    method,
			bucket:    "public-bucket",
			object:    "report.pdf",
			expiry:    5 * time.Minute,
		})
		if err != nil {
			return err
		}
		g.emit("valid_prefix_ok_"+strings.ToLower(method), method, p.uri, p.host, p.signTime.Unix())
	}

	// Short-expiry credential within its max.
	p, err = g.presign(presignSpec{
		accessKey: keyShortExp,
		secretKey: secretShortExp,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    30 * time.Second,
	})
	if err != nil {
		return err
	}
	g.emit("valid_short_expiry_ok", "GET", p.uri, p.host, p.signTime.Unix())

	return nil
}

// credentialAndPolicyCases cover per-credential policy and time semantics that
// require presigning with a specific key or host.
func (g *generator) credentialAndPolicyCases() error {
	// Unknown access key: signed by a key absent from the config.
	p, err := g.presign(presignSpec{
		accessKey: keyGhost,
		secretKey: secretGhost,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("unknown_access_key", "GET", p.uri, p.host, p.signTime.Unix())

	// Disabled credential: validly signed but disabled.
	p, err = g.presign(presignSpec{
		accessKey: keyDisabled,
		secretKey: secretDisabled,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("disabled_credential", "GET", p.uri, p.host, p.signTime.Unix())

	// Host policy denial: host-restricted credential signed+verified for cdn.
	p, err = g.presign(presignSpec{
		accessKey: keyHostOnly,
		secretKey: secretHostOnly,
		host:      hostCDN,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("host_policy_denied", "GET", p.uri, p.host, p.signTime.Unix())

	// Host binding: unrestricted signed for assets, verified as cdn (both
	// allowed by policy, so this must be a signature mismatch).
	p, err = g.presign(presignSpec{
		accessKey: keyUnrestricted,
		secretKey: secretUnrestricted,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("host_binding_mismatch", "GET", p.uri, hostCDN, p.signTime.Unix())

	// Method policy denial: GET-only credential signed+verified as HEAD.
	p, err = g.presign(presignSpec{
		accessKey: keyGetOnly,
		secretKey: secretGetOnly,
		host:      hostAssets,
		method:    "HEAD",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("method_policy_denied", "HEAD", p.uri, p.host, p.signTime.Unix())

	// Method binding: unrestricted signed for HEAD, verified as GET.
	p, err = g.presign(presignSpec{
		accessKey: keyUnrestricted,
		secretKey: secretUnrestricted,
		host:      hostAssets,
		method:    "HEAD",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("method_binding_mismatch", "GET", p.uri, p.host, p.signTime.Unix())

	// Prefix policy denial: prefix credential signed for a bucket outside its
	// allowed prefix.
	p, err = g.presign(presignSpec{
		accessKey: keyPrefix,
		secretKey: secretPrefix,
		host:      hostAssets,
		method:    "GET",
		bucket:    "private-bucket",
		object:    "report.pdf",
		expiry:    5 * time.Minute,
	})
	if err != nil {
		return err
	}
	g.emit("prefix_policy_denied", "GET", p.uri, p.host, p.signTime.Unix())

	// Expiry over the credential's max (short-exp credential, 120s > 60s).
	p, err = g.presign(presignSpec{
		accessKey: keyShortExp,
		secretKey: secretShortExp,
		host:      hostAssets,
		method:    "GET",
		bucket:    "assets",
		object:    "file.jpg",
		expiry:    120 * time.Second,
	})
	if err != nil {
		return err
	}
	g.emit("expiry_over_credential_max", "GET", p.uri, p.host, p.signTime.Unix())

	return nil
}

// mutationCases derive negative inputs by string-editing valid presigned URIs.
func (g *generator) mutationCases() error {
	bases := []struct {
		name   string
		method string
		object string
	}{
		{"get", "GET", "file.jpg"},
		{"head", "HEAD", "file.jpg"},
		{"unicode", "GET", "café-münchen.jpg"},
	}

	for _, base := range bases {
		p, err := g.presign(presignSpec{
			accessKey: keyUnrestricted,
			secretKey: secretUnrestricted,
			host:      hostAssets,
			method:    base.method,
			bucket:    "assets",
			object:    base.object,
			expiry:    5 * time.Minute,
		})
		if err != nil {
			return err
		}
		g.mutate(base.name, base.method, p)
	}
	return nil
}

// mutate emits the full mutation suite for one valid presigned URL.
func (g *generator) mutate(prefix, method string, p presigned) {
	now := p.signTime.Unix()
	name := func(s string) string { return "mutate_" + prefix + "_" + s }

	required := []string{
		"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date",
		"X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature",
	}
	dupValues := map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    "extra",
		"X-Amz-Date":          p.amzDate,
		"X-Amz-Expires":       "60",
		"X-Amz-SignedHeaders": "host",
		"X-Amz-Signature":     p.sigHex,
	}
	for _, key := range required {
		short := strings.ToLower(strings.TrimPrefix(key, "X-Amz-"))
		g.emit(name("remove_"+short), method, removeQueryParam(p.uri, key), p.host, now)
		g.emit(name("duplicate_"+short), method, p.uri+"&"+key+"="+dupValues[key], p.host, now)
	}

	// Signature tampering.
	g.emit(name("sig_tampered"), method, replaceQueryParam(p.uri, "X-Amz-Signature", flipFirstHex(p.sigHex)), p.host, now)
	g.emit(name("sig_truncated"), method, replaceQueryParam(p.uri, "X-Amz-Signature", p.sigHex[:32]), p.host, now)
	g.emit(name("sig_non_hex"), method, replaceQueryParam(p.uri, "X-Amz-Signature", strings.Repeat("z", 64)), p.host, now)

	// Algorithm.
	g.emit(name("wrong_algorithm"), method, replaceQueryParam(p.uri, "X-Amz-Algorithm", "AWS4-HMAC-SHA1"), p.host, now)

	// Credential scope malformations (values are percent-encoded like MinIO's).
	scopes := []struct {
		name  string
		value string
	}{
		{"scope_too_few", keyUnrestricted + "/" + p.date + "/" + region + "/s3"},
		{"scope_too_many", keyUnrestricted + "/" + p.date + "/" + region + "/s3/aws4_request/extra"},
		{"scope_bad_date", keyUnrestricted + "/2026010X/" + region + "/s3/aws4_request"},
		{"scope_wrong_service", keyUnrestricted + "/" + p.date + "/" + region + "/ec2/aws4_request"},
		{"scope_wrong_terminal", keyUnrestricted + "/" + p.date + "/" + region + "/s3/aws4_request_v2"},
		{"scope_empty_region", keyUnrestricted + "/" + p.date + "//s3/aws4_request"},
	}
	for _, s := range scopes {
		g.emit(name(s.name), method, replaceQueryParam(p.uri, "X-Amz-Credential", encodeQueryComponent(s.value)), p.host, now)
	}

	// X-Amz-Date day not matching the credential scope date.
	dateMismatch := p.signTime.Add(24 * time.Hour).UTC().Format("20060102T150405Z")
	g.emit(name("date_scope_mismatch"), method, replaceQueryParam(p.uri, "X-Amz-Date", dateMismatch), p.host, now)

	// Time window (edit now_unix, not the URI).
	g.emit(name("expired"), method, p.uri, p.host, p.signTime.Unix()+p.expires+1)
	g.emit(name("future_dated"), method, p.uri, p.host, p.signTime.Unix()-61)

	// Expiry over the seven-day SigV4 maximum.
	g.emit(name("expiry_over_7d"), method, replaceQueryParam(p.uri, "X-Amz-Expires", "700000"), p.host, now)
	g.emit(name("expiry_zero"), method, replaceQueryParam(p.uri, "X-Amz-Expires", "0"), p.host, now)
	g.emit(name("expiry_empty"), method, replaceQueryParam(p.uri, "X-Amz-Expires", ""), p.host, now)
	g.emit(name("expiry_non_numeric"), method, replaceQueryParam(p.uri, "X-Amz-Expires", "abc"), p.host, now)

	// Unsupported signed headers.
	g.emit(name("signed_headers_extra"), method, replaceQueryParam(p.uri, "X-Amz-SignedHeaders", encodeQueryComponent("host;x-amz-content-sha256")), p.host, now)

	// Path traversal and ambiguity.
	traversals := []struct {
		name string
		path string
	}{
		{"dotdot", "/assets/../secret"},
		{"encoded_dotdot", "/assets/%2e%2e/secret"},
		{"double_slash", "/assets/a//b"},
		{"encoded_slash", "/assets/%2Fsecret"},
		{"encoded_backslash", "/assets/%5Csecret"},
		{"bad_percent", "/assets/%zz"},
		{"raw_space", "/assets/file name"},
	}
	for _, t := range traversals {
		g.emit(name("path_"+t.name), method, replaceURIPath(p.uri, t.path), p.host, now)
	}

	// Query additions that invalidate the signature.
	g.emit(name("unknown_param"), method, p.uri+"&foo=bar", p.host, now)
	g.emit(name("empty_added_value"), method, p.uri+"&extra=", p.host, now)
	g.emit(name("added_no_equals"), method, p.uri+"&extra", p.host, now)
	g.emit(name("added_repeated"), method, p.uri+"&partNumber=1&partNumber=2", p.host, now)

	// Unsupported client method on an otherwise valid URL.
	unsupported := "PUT"
	g.emit(name("unsupported_method"), unsupported, p.uri, p.host, now)
}

// presignSpec describes one presign request.
type presignSpec struct {
	accessKey string
	secretKey string
	host      string
	method    string
	bucket    string
	object    string
	expiry    time.Duration
	params    url.Values
}

// presigned is the result of a presign, decomposed for mutation.
type presigned struct {
	uri      string
	host     string
	signTime time.Time
	amzDate  string
	date     string
	expires  int64
	sigHex   string
}

func (g *generator) presign(spec presignSpec) (presigned, error) {
	client, err := minio.New(spec.host, &minio.Options{
		Creds:        credentials.NewStaticV4(spec.accessKey, spec.secretKey, ""),
		Secure:       true,
		Region:       region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return presigned{}, fmt.Errorf("new client: %w", err)
	}

	var u *url.URL
	switch spec.method {
	case "GET":
		u, err = client.PresignedGetObject(context.Background(), spec.bucket, spec.object, spec.expiry, spec.params)
	case "HEAD":
		u, err = client.PresignedHeadObject(context.Background(), spec.bucket, spec.object, spec.expiry, spec.params)
	default:
		return presigned{}, fmt.Errorf("unsupported presign method %q", spec.method)
	}
	if err != nil {
		return presigned{}, fmt.Errorf("presign %s %s/%s: %w", spec.method, spec.bucket, spec.object, err)
	}

	uri := strings.TrimPrefix(u.String(), "https://"+spec.host)
	q := u.Query()
	amzDate := q.Get("X-Amz-Date")
	signTime, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return presigned{}, fmt.Errorf("parse X-Amz-Date %q: %w", amzDate, err)
	}
	expires, err := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
	if err != nil {
		return presigned{}, fmt.Errorf("parse X-Amz-Expires: %w", err)
	}

	return presigned{
		uri:      uri,
		host:     spec.host,
		signTime: signTime.UTC(),
		amzDate:  amzDate,
		date:     amzDate[:8],
		expires:  expires,
		sigHex:   q.Get("X-Amz-Signature"),
	}, nil
}

// emit runs the oracle verifier and records one corpus line.
func (g *generator) emit(name, method, uri, host string, nowUnix int64) {
	if _, ok := g.seen[name]; ok {
		panic("duplicate corpus case name: " + name)
	}
	g.seen[name] = struct{}{}

	result := g.verifier.Verify(method, uri, host, "", time.Unix(nowUnix, 0).UTC())
	g.lines = append(g.lines, corpusLine{
		Name:    name,
		Method:  method,
		URI:     uri,
		Host:    host,
		NowUnix: nowUnix,
		Allowed: result.Allowed,
		Reason:  result.Reason,
	})
}

func (g *generator) write(output string) error {
	if dir := filepath.Dir(output); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, line := range g.lines {
		if err := enc.Encode(line); err != nil {
			return err
		}
	}
	return os.WriteFile(output, []byte(buf.String()), 0o644)
}

func (g *generator) printSummary(output string) {
	counts := make(map[string]int)
	allowed := 0
	for _, line := range g.lines {
		counts[line.Reason]++
		if line.Allowed {
			allowed++
		}
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)

	fmt.Fprintf(os.Stderr, "wrote %d corpus lines to %s\n", len(g.lines), output)
	fmt.Fprintf(os.Stderr, "allowed: %d, denied: %d\n", allowed, len(g.lines)-allowed)
	fmt.Fprintln(os.Stderr, "reason distribution:")
	for _, reason := range reasons {
		fmt.Fprintf(os.Stderr, "  %-26s %d\n", reason, counts[reason])
	}
}

// --- URI string editing helpers (operate on "path?query") ---

func splitURI(uri string) (path, query string, ok bool) {
	return strings.Cut(uri, "?")
}

func removeQueryParam(uri, key string) string {
	path, query, ok := splitURI(uri)
	if !ok {
		return uri
	}
	parts := strings.Split(query, "&")
	kept := parts[:0]
	for _, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		if name == key {
			continue
		}
		kept = append(kept, part)
	}
	return path + "?" + strings.Join(kept, "&")
}

func replaceQueryParam(uri, key, rawValue string) string {
	path, query, ok := splitURI(uri)
	if !ok {
		return uri
	}
	parts := strings.Split(query, "&")
	for i, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		if name == key {
			parts[i] = key + "=" + rawValue
		}
	}
	return path + "?" + strings.Join(parts, "&")
}

func replaceURIPath(uri, newPath string) string {
	_, query, ok := splitURI(uri)
	if !ok {
		return newPath
	}
	return newPath + "?" + query
}

func flipFirstHex(sig string) string {
	if sig == "" {
		return sig
	}
	first := byte('0')
	if sig[0] == '0' {
		first = '1'
	}
	return string(first) + sig[1:]
}

const hexUpper = "0123456789ABCDEF"

// encodeQueryComponent percent-encodes like AWS/MinIO: unreserved characters
// pass through, everything else becomes %XX with uppercase hex.
func encodeQueryComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&0x0f])
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	default:
		return false
	}
}
