package verifier

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	testAccessKey = "AKIATEST"
	testSecretKey = "test-secret"
	testRegion    = "us-east-1"
	testService   = "s3"
	testHost      = "minio.example.com"
)

var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestVerifierAllowsValidPresignedGetAndHead(t *testing.T) {
	v := newTestVerifier(t)

	for _, method := range []string{"GET", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			rawURI := presignedURI(t, presignInput{
				Method: method,
				Path:   "/bucket/file.jpg",
				Host:   testHost,
			})

			result := v.Verify(method, rawURI, testHost, "https", testNow)
			requireAllowed(t, result, "/bucket/file.jpg")
		})
	}
}

func TestVerifierAllowsMinIOV7PresignedURLs(t *testing.T) {
	v := newTestVerifier(t)
	client, err := minio.New(testHost, &minio.Options{
		Creds:        credentials.NewStaticV4(testAccessKey, testSecretKey, ""),
		Secure:       true,
		Region:       testRegion,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("minio.New() error = %v", err)
	}

	tests := []struct {
		name    string
		method  string
		object  string
		params  url.Values
		presign func(context.Context, string, string, time.Duration, url.Values) (*url.URL, error)
	}{
		{
			name:    "get",
			method:  "GET",
			object:  "file.jpg",
			presign: client.PresignedGetObject,
		},
		{
			name:    "head",
			method:  "HEAD",
			object:  "path/to/file.jpg",
			presign: client.PresignedHeadObject,
		},
		{
			name:   "get with response params",
			method: "GET",
			object: "a b+sdk.jpg",
			params: url.Values{
				"response-content-disposition": {`attachment; filename="a b+sdk.jpg"`},
			},
			presign: client.PresignedGetObject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := tt.presign(context.Background(), "bucket", tt.object, 5*time.Minute, tt.params)
			if err != nil {
				t.Fatalf("MinIO %s presign error = %v", tt.method, err)
			}

			result := v.Verify(tt.method, u.RequestURI(), u.Host, u.Scheme, signedAtFromURL(t, u))
			requireAllowed(t, result, u.EscapedPath())
		})
	}
}

func TestVerifierRejectsMissingQueryParams(t *testing.T) {
	v := newTestVerifier(t)
	rawURI := presignedURI(t, presignInput{
		Method: "GET",
		Path:   "/bucket/file.jpg",
		Host:   testHost,
	})

	for _, key := range []string{
		"X-Amz-Algorithm",
		"X-Amz-Credential",
		"X-Amz-Date",
		"X-Amz-Expires",
		"X-Amz-SignedHeaders",
		"X-Amz-Signature",
	} {
		t.Run(key, func(t *testing.T) {
			result := v.Verify("GET", removeQueryParam(rawURI, key), testHost, "https", testNow)
			requireDenied(t, result, ReasonMissingQueryParam)
		})
	}
}

func TestVerifierRejectsUnsupportedMethodAlgorithmAndSignedHeaders(t *testing.T) {
	v := newTestVerifier(t)
	rawURI := presignedURI(t, presignInput{
		Method: "GET",
		Path:   "/bucket/file.jpg",
		Host:   testHost,
	})

	t.Run("unsupported method", func(t *testing.T) {
		result := v.Verify("POST", rawURI, testHost, "https", testNow)
		requireDenied(t, result, ReasonUnsupportedMethod)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		result := v.Verify("GET", replaceQueryParam(rawURI, "X-Amz-Algorithm", "AWS4-HMAC-SHA1"), testHost, "https", testNow)
		requireDenied(t, result, ReasonUnsupportedAlgorithm)
	})

	t.Run("unsupported signed headers", func(t *testing.T) {
		signedHeaders := testURIEncodeString("host;x-amz-content-sha256")
		result := v.Verify("GET", replaceQueryParam(rawURI, "X-Amz-SignedHeaders", signedHeaders), testHost, "https", testNow)
		requireDenied(t, result, ReasonUnsupportedSignedHeader)
	})
}

func TestVerifierRejectsCredentialAndPolicyDenials(t *testing.T) {
	t.Run("unknown access key", func(t *testing.T) {
		v := newTestVerifier(t)
		rawURI := presignedURI(t, presignInput{
			Method:    "GET",
			Path:      "/bucket/file.jpg",
			Host:      testHost,
			AccessKey: "UNKNOWN",
			SecretKey: "unknown-secret",
		})

		result := v.Verify("GET", rawURI, testHost, "https", testNow)
		requireDenied(t, result, ReasonUnknownAccessKey)
	})

	t.Run("disabled credential", func(t *testing.T) {
		v := newTestVerifier(t, Credential{
			AccessKey:       testAccessKey,
			SecretKey:       testSecretKey,
			Enabled:         false,
			MaxExpires:      time.Hour,
			AllowedHosts:    []string{testHost},
			AllowedMethods:  []string{"GET", "HEAD"},
			AllowedPrefixes: []string{"/bucket/"},
		})
		rawURI := presignedURI(t, presignInput{
			Method: "GET",
			Path:   "/bucket/file.jpg",
			Host:   testHost,
		})

		result := v.Verify("GET", rawURI, testHost, "https", testNow)
		requireDenied(t, result, ReasonUnauthorized)
	})

	t.Run("host policy denial", func(t *testing.T) {
		blockedHost := "blocked.example.com"
		v := newTestVerifier(t, Credential{
			AccessKey:       testAccessKey,
			SecretKey:       testSecretKey,
			Enabled:         true,
			MaxExpires:      time.Hour,
			AllowedHosts:    []string{testHost},
			AllowedMethods:  []string{"GET", "HEAD"},
			AllowedPrefixes: []string{"/bucket/"},
		})
		rawURI := presignedURI(t, presignInput{
			Method: "GET",
			Path:   "/bucket/file.jpg",
			Host:   blockedHost,
		})

		result := v.Verify("GET", rawURI, blockedHost, "https", testNow)
		requireDenied(t, result, ReasonUnauthorized)
	})

	t.Run("prefix policy denial", func(t *testing.T) {
		v := newTestVerifier(t, Credential{
			AccessKey:       testAccessKey,
			SecretKey:       testSecretKey,
			Enabled:         true,
			MaxExpires:      time.Hour,
			AllowedHosts:    []string{testHost},
			AllowedMethods:  []string{"GET", "HEAD"},
			AllowedPrefixes: []string{"/allowed/"},
		})
		rawURI := presignedURI(t, presignInput{
			Method: "GET",
			Path:   "/bucket/file.jpg",
			Host:   testHost,
		})

		result := v.Verify("GET", rawURI, testHost, "https", testNow)
		requireDenied(t, result, ReasonUnauthorized)
	})

	t.Run("method policy denial", func(t *testing.T) {
		v := newTestVerifier(t, Credential{
			AccessKey:       testAccessKey,
			SecretKey:       testSecretKey,
			Enabled:         true,
			MaxExpires:      time.Hour,
			AllowedHosts:    []string{testHost},
			AllowedMethods:  []string{"GET"},
			AllowedPrefixes: []string{"/bucket/"},
		})
		rawURI := presignedURI(t, presignInput{
			Method: "HEAD",
			Path:   "/bucket/file.jpg",
			Host:   testHost,
		})

		result := v.Verify("HEAD", rawURI, testHost, "https", testNow)
		requireDenied(t, result, ReasonUnauthorized)
	})
}

func TestVerifierEnforcesPathPrefixBoundary(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		path    string
		allowed bool
	}{
		{name: "exact path", prefix: "/bucket/public", path: "/bucket/public", allowed: true},
		{name: "slash-delimited descendant", prefix: "/bucket/public", path: "/bucket/public/file.jpg", allowed: true},
		{name: "trailing-slash prefix", prefix: "/bucket/public/", path: "/bucket/public/file.jpg", allowed: true},
		{name: "root prefix", prefix: "/", path: "/bucket/public/file.jpg", allowed: true},
		{name: "adjacent name", prefix: "/bucket/public", path: "/bucket/publicity/secret.jpg", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestVerifier(t, Credential{
				AccessKey:       testAccessKey,
				SecretKey:       testSecretKey,
				Enabled:         true,
				MaxExpires:      time.Hour,
				AllowedHosts:    []string{testHost},
				AllowedMethods:  []string{"GET", "HEAD"},
				AllowedPrefixes: []string{tt.prefix},
			})
			rawURI := presignedURI(t, presignInput{
				Method: "GET",
				Path:   tt.path,
				Host:   testHost,
			})

			result := v.Verify("GET", rawURI, testHost, "https", testNow)
			if tt.allowed {
				requireAllowed(t, result, tt.path)
			} else {
				requireDenied(t, result, ReasonUnauthorized)
			}
		})
	}
}

func TestVerifierRejectsExpiredFutureDatedAndOverMaxExpires(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		v := newTestVerifier(t)
		rawURI := presignedURI(t, presignInput{
			Method:  "GET",
			Path:    "/bucket/file.jpg",
			Host:    testHost,
			Expires: time.Minute,
		})

		result := v.Verify("GET", rawURI, testHost, "https", testNow.Add(time.Minute+time.Second))
		requireDenied(t, result, ReasonExpired)
	})

	t.Run("future dated", func(t *testing.T) {
		v := newTestVerifier(t)
		rawURI := presignedURI(t, presignInput{
			Method:   "GET",
			Path:     "/bucket/file.jpg",
			Host:     testHost,
			SignTime: testNow.Add(2 * time.Minute),
		})

		result := v.Verify("GET", rawURI, testHost, "https", testNow)
		requireDenied(t, result, ReasonFutureDated)
	})

	t.Run("credential max expires", func(t *testing.T) {
		v := newTestVerifier(t, Credential{
			AccessKey:       testAccessKey,
			SecretKey:       testSecretKey,
			Enabled:         true,
			MaxExpires:      time.Minute,
			AllowedHosts:    []string{testHost},
			AllowedMethods:  []string{"GET", "HEAD"},
			AllowedPrefixes: []string{"/bucket/"},
		})
		rawURI := presignedURI(t, presignInput{
			Method:  "GET",
			Path:    "/bucket/file.jpg",
			Host:    testHost,
			Expires: 2 * time.Minute,
		})

		result := v.Verify("GET", rawURI, testHost, "https", testNow)
		requireDenied(t, result, ReasonInvalidExpiry)
	})
}

func TestVerifierRejectsSignatureMismatchAndMalformedSignature(t *testing.T) {
	v := newTestVerifier(t)
	rawURI := presignedURI(t, presignInput{
		Method: "GET",
		Path:   "/bucket/file.jpg",
		Host:   testHost,
	})

	t.Run("signature mismatch", func(t *testing.T) {
		result := v.Verify("GET", replaceQueryParam(rawURI, "X-Amz-Signature", tamperedSignatureValue(rawURI)), testHost, "https", testNow)
		requireDenied(t, result, ReasonSignatureMismatch)
	})

	t.Run("malformed signature", func(t *testing.T) {
		result := v.Verify("GET", replaceQueryParam(rawURI, "X-Amz-Signature", strings.Repeat("z", sha256.Size*2)), testHost, "https", testNow)
		requireDenied(t, result, ReasonSignatureMismatch)
	})
}

func TestVerifierAllowsCanonicalPathCases(t *testing.T) {
	v := newTestVerifier(t)

	for _, path := range []string{
		"/bucket/file.jpg",
		"/bucket/path/to/file.jpg",
		"/bucket/a%20b.jpg",
		"/bucket/a+b.jpg",
		"/bucket/a%2Bb.jpg",
		"/bucket/%E2%9C%93.jpg",
		"/bucket/a%252Fb.jpg",
	} {
		t.Run(path, func(t *testing.T) {
			rawURI := presignedURI(t, presignInput{
				Method: "GET",
				Path:   path,
				Host:   testHost,
			})

			result := v.Verify("GET", rawURI, testHost, "https", testNow)
			requireAllowed(t, result, path)
		})
	}
}

func TestVerifierAllowsCanonicalQueryCases(t *testing.T) {
	v := newTestVerifier(t)

	tests := []struct {
		name  string
		extra []rawQueryParam
	}{
		{
			name: "repeated params",
			extra: []rawQueryParam{
				{Name: "partNumber", Value: "2"},
				{Name: "partNumber", Value: "1"},
			},
		},
		{
			name: "empty value",
			extra: []rawQueryParam{
				{Name: "empty", Value: ""},
			},
		},
		{
			name: "space as percent 20",
			extra: []rawQueryParam{
				{Name: "note", Value: "a%20b"},
			},
		},
		{
			name: "plus as percent 2B",
			extra: []rawQueryParam{
				{Name: "note", Value: "a%2Bb"},
			},
		},
		{
			name: "response content disposition",
			extra: []rawQueryParam{
				{Name: "response-content-disposition", Value: testURIEncodeString(`attachment; filename="a b.jpg"`)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawURI := presignedURI(t, presignInput{
				Method: "GET",
				Path:   "/bucket/file.jpg",
				Host:   testHost,
				Extra:  tt.extra,
			})

			result := v.Verify("GET", rawURI, testHost, "https", testNow)
			requireAllowed(t, result, "/bucket/file.jpg")
		})
	}
}

func TestVerifierAllowsHighCardinalityCanonicalQuery(t *testing.T) {
	v := newTestVerifier(t)
	extra := make([]rawQueryParam, 0, 512)
	for i := 511; i >= 0; i-- {
		extra = append(extra, rawQueryParam{
			Name:  fmt.Sprintf("param-%04d", i),
			Value: fmt.Sprintf("value-%04d", i),
		})
	}

	rawURI := presignedURI(t, presignInput{
		Method: "GET",
		Path:   "/bucket/file.jpg",
		Host:   testHost,
		Extra:  extra,
	})

	result := v.Verify("GET", rawURI, testHost, "https", testNow)
	requireAllowed(t, result, "/bucket/file.jpg")
}

func TestVerifierRejectsTraversalAndAmbiguousPaths(t *testing.T) {
	v := newTestVerifier(t)
	rawURI := presignedURI(t, presignInput{
		Method: "GET",
		Path:   "/bucket/file.jpg",
		Host:   testHost,
	})

	for _, path := range []string{
		"/bucket/../secret",
		"/bucket/%2e%2e/secret",
		"/bucket/a//b",
	} {
		t.Run(path, func(t *testing.T) {
			result := v.Verify("GET", replaceURIPath(rawURI, path), testHost, "https", testNow)
			requireDenied(t, result, ReasonInvalidURI)
		})
	}
}

func BenchmarkVerifierVerifyValid(b *testing.B) {
	v := newTestVerifier(b)
	rawURI := presignedURI(b, presignInput{
		Method: "GET",
		Path:   "/bucket/path/to/file.jpg",
		Host:   testHost,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := v.Verify("GET", rawURI, testHost, "https", testNow)
		if !result.Allowed {
			b.Fatalf("Verify() denied valid request: reason=%s", result.Reason)
		}
	}
}

func BenchmarkVerifierVerifyMissingParamsHighCardinality(b *testing.B) {
	v := newTestVerifier(b)
	for _, count := range []int{12, 100, 400, 500} {
		for _, descending := range []bool{false, true} {
			order := "ascending"
			if descending {
				order = "descending"
			}
			b.Run(fmt.Sprintf("%s/%d", order, count), func(b *testing.B) {
				params := make([]rawQueryParam, 0, count)
				for i := 0; i < count; i++ {
					value := i
					if descending {
						value = count - i - 1
					}
					params = append(params, rawQueryParam{
						Name:  fmt.Sprintf("param-%04d", value),
						Value: "value",
					})
				}
				rawURI := "/bucket/file.jpg?" + joinRawQuery(params)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					result := v.Verify("GET", rawURI, testHost, "https", testNow)
					if result.Reason != ReasonMissingQueryParam {
						b.Fatalf("Verify() reason = %q, want %q", result.Reason, ReasonMissingQueryParam)
					}
				}
				b.ReportMetric(float64(len(rawURI)), "uri_B")
			})
		}
	}
}

type rawQueryParam struct {
	Name  string
	Value string
}

type presignInput struct {
	Method    string
	Path      string
	Host      string
	AccessKey string
	SecretKey string
	Region    string
	SignTime  time.Time
	Expires   time.Duration
	Extra     []rawQueryParam
}

func newTestVerifier(tb testing.TB, credentials ...Credential) *Verifier {
	tb.Helper()
	if len(credentials) == 0 {
		credentials = []Credential{{
			AccessKey:       testAccessKey,
			SecretKey:       testSecretKey,
			Enabled:         true,
			MaxExpires:      time.Hour,
			AllowedHosts:    []string{testHost},
			AllowedMethods:  []string{"GET", "HEAD"},
			AllowedPrefixes: []string{"/bucket/"},
		}}
	}
	v, err := New(Settings{
		AllowedClockSkew:  time.Minute,
		DefaultMaxExpires: time.Hour,
		SupportedMethods:  []string{"GET", "HEAD"},
		SupportedService:  testService,
	}, credentials)
	if err != nil {
		tb.Fatalf("New() error = %v", err)
	}
	return v
}

func presignedURI(tb testing.TB, in presignInput) string {
	tb.Helper()
	if in.Method == "" {
		in.Method = "GET"
	}
	if in.Path == "" {
		in.Path = "/bucket/file.jpg"
	}
	if in.Host == "" {
		in.Host = testHost
	}
	if in.AccessKey == "" {
		in.AccessKey = testAccessKey
	}
	if in.SecretKey == "" {
		in.SecretKey = testSecretKey
	}
	if in.Region == "" {
		in.Region = testRegion
	}
	if in.SignTime.IsZero() {
		in.SignTime = testNow
	}
	if in.Expires == 0 {
		in.Expires = 5 * time.Minute
	}

	amzDate := in.SignTime.UTC().Format("20060102T150405Z")
	date := in.SignTime.UTC().Format("20060102")
	credentialScope := date + "/" + in.Region + "/" + testService + "/aws4_request"
	params := []rawQueryParam{
		{Name: "X-Amz-Algorithm", Value: "AWS4-HMAC-SHA256"},
		{Name: "X-Amz-Credential", Value: testURIEncodeString(in.AccessKey + "/" + credentialScope)},
		{Name: "X-Amz-Date", Value: amzDate},
		{Name: "X-Amz-Expires", Value: secondsString(in.Expires)},
		{Name: "X-Amz-SignedHeaders", Value: "host"},
	}
	params = append(params, in.Extra...)

	rawQuery := joinRawQuery(params)
	canonicalPath := testCanonicalPath(tb, in.Path)
	canonicalQuery := testCanonicalQuery(tb, rawQuery)
	canonicalRequest := in.Method + "\n" +
		canonicalPath + "\n" +
		canonicalQuery + "\n" +
		"host:" + strings.ToLower(strings.TrimSpace(in.Host)) + "\n" +
		"\n" +
		"host\n" +
		"UNSIGNED-PAYLOAD"
	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256" + "\n" +
		amzDate + "\n" +
		credentialScope + "\n" +
		hex.EncodeToString(canonicalHash[:])
	signature := testSignature(in.SecretKey, date, in.Region, testService, stringToSign)

	return in.Path + "?" + rawQuery + "&X-Amz-Signature=" + hex.EncodeToString(signature)
}

func requireAllowed(tb testing.TB, result Result, path string) {
	tb.Helper()
	if !result.Allowed {
		tb.Fatalf("Verify() denied valid request: reason=%s path=%s", result.Reason, result.Path)
	}
	if result.Reason != ReasonOK {
		tb.Fatalf("Verify() reason = %q, want %q", result.Reason, ReasonOK)
	}
	if result.Path != path {
		tb.Fatalf("Verify() path = %q, want %q", result.Path, path)
	}
	if result.AccessKey != testAccessKey {
		tb.Fatalf("Verify() access key = %q, want %q", result.AccessKey, testAccessKey)
	}
	if result.AccessKeyHash != HashAccessKey(testAccessKey) {
		tb.Fatalf("Verify() access key hash = %q, want %q", result.AccessKeyHash, HashAccessKey(testAccessKey))
	}
}

func requireDenied(tb testing.TB, result Result, reason string) {
	tb.Helper()
	if result.Allowed {
		tb.Fatalf("Verify() allowed request, want deny reason %q", reason)
	}
	if result.Reason != reason {
		tb.Fatalf("Verify() reason = %q, want %q", result.Reason, reason)
	}
}

func signedAtFromURL(tb testing.TB, u *url.URL) time.Time {
	tb.Helper()
	raw := u.Query().Get("X-Amz-Date")
	if raw == "" {
		tb.Fatalf("MinIO presigned URL missing X-Amz-Date: %s", u.String())
	}
	signedAt, err := time.Parse("20060102T150405Z", raw)
	if err != nil {
		tb.Fatalf("parse X-Amz-Date %q: %v", raw, err)
	}
	return signedAt
}

func secondsString(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10)
}

func joinRawQuery(params []rawQueryParam) string {
	parts := make([]string, 0, len(params))
	for _, p := range params {
		parts = append(parts, p.Name+"="+p.Value)
	}
	return strings.Join(parts, "&")
}

func removeQueryParam(rawURI, key string) string {
	path, query, ok := strings.Cut(rawURI, "?")
	if !ok {
		return rawURI
	}
	parts := strings.Split(query, "&")
	out := parts[:0]
	for _, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		if name == key {
			continue
		}
		out = append(out, part)
	}
	return path + "?" + strings.Join(out, "&")
}

func replaceQueryParam(rawURI, key, rawValue string) string {
	path, query, ok := strings.Cut(rawURI, "?")
	if !ok {
		return rawURI
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

func replaceURIPath(rawURI, path string) string {
	_, query, ok := strings.Cut(rawURI, "?")
	if !ok {
		return path
	}
	return path + "?" + query
}

func tamperedSignatureValue(rawURI string) string {
	_, query, ok := strings.Cut(rawURI, "?")
	if !ok {
		return strings.Repeat("0", sha256.Size*2)
	}
	for _, part := range strings.Split(query, "&") {
		name, value, _ := strings.Cut(part, "=")
		if name != "X-Amz-Signature" || value == "" {
			continue
		}
		replacement := "0"
		if value[0] == '0' {
			replacement = "1"
		}
		return replacement + value[1:]
	}
	return strings.Repeat("0", sha256.Size*2)
}

type encodedQueryParam struct {
	name  string
	value string
}

func testCanonicalQuery(tb testing.TB, rawQuery string) string {
	tb.Helper()
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	params := make([]encodedQueryParam, 0, len(parts))
	for _, part := range parts {
		nameRaw, valueRaw, _ := strings.Cut(part, "=")
		nameBytes := testPercentDecode(tb, nameRaw)
		valueBytes := testPercentDecode(tb, valueRaw)
		if string(nameBytes) == "X-Amz-Signature" {
			continue
		}
		params = append(params, encodedQueryParam{
			name:  testURIEncode(nameBytes),
			value: testURIEncode(valueBytes),
		})
	}
	sort.Slice(params, func(i, j int) bool {
		if params[i].name == params[j].name {
			return params[i].value < params[j].value
		}
		return params[i].name < params[j].name
	})
	out := make([]string, 0, len(params))
	for _, p := range params {
		out = append(out, p.name+"="+p.value)
	}
	return strings.Join(out, "&")
}

func testCanonicalPath(tb testing.TB, rawPath string) string {
	tb.Helper()
	var b strings.Builder
	b.Grow(len(rawPath))
	for i := 0; i < len(rawPath); i++ {
		c := rawPath[i]
		switch {
		case c == '/':
			b.WriteByte('/')
		case c == '%' && i+2 < len(rawPath) && testIsHex(rawPath[i+1]) && testIsHex(rawPath[i+2]):
			b.WriteByte('%')
			b.WriteByte(testUpperHex(rawPath[i+1]))
			b.WriteByte(testUpperHex(rawPath[i+2]))
			i += 2
		case testIsUnreserved(c):
			b.WriteByte(c)
		default:
			testWriteEscapedByte(&b, c)
		}
	}
	return b.String()
}

func testURIEncodeString(value string) string {
	return testURIEncode([]byte(value))
}

func testURIEncode(value []byte) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, c := range value {
		if testIsUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		testWriteEscapedByte(&b, c)
	}
	return b.String()
}

func testPercentDecode(tb testing.TB, value string) []byte {
	tb.Helper()
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(value) || !testIsHex(value[i+1]) || !testIsHex(value[i+2]) {
			tb.Fatalf("invalid percent encoding %q", value)
		}
		out = append(out, testFromHex(value[i+1])<<4|testFromHex(value[i+2]))
		i += 2
	}
	return out
}

func testSignature(secretKey, date, region, service, stringToSign string) []byte {
	kDate := testHMACSHA256([]byte("AWS4"+secretKey), date)
	kRegion := testHMACSHA256(kDate, region)
	kService := testHMACSHA256(kRegion, service)
	kSigning := testHMACSHA256(kService, "aws4_request")
	return testHMACSHA256(kSigning, stringToSign)
}

func testHMACSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func testWriteEscapedByte(b *strings.Builder, c byte) {
	const hexdigits = "0123456789ABCDEF"
	b.WriteByte('%')
	b.WriteByte(hexdigits[c>>4])
	b.WriteByte(hexdigits[c&0x0f])
}

func testIsUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func testIsHex(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

func testFromHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func testUpperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}
