package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	ReasonOK                      = "ok"
	ReasonMissingMetadata         = "missing_metadata"
	ReasonInvalidURI              = "invalid_uri"
	ReasonUnsupportedMethod       = "unsupported_method"
	ReasonMissingQueryParam       = "missing_query_param"
	ReasonUnsupportedAlgorithm    = "unsupported_algorithm"
	ReasonInvalidCredentialScope  = "invalid_credential_scope"
	ReasonUnknownAccessKey        = "unknown_access_key"
	ReasonInvalidExpiry           = "invalid_expiry"
	ReasonExpired                 = "expired"
	ReasonFutureDated             = "future_dated"
	ReasonUnsupportedSignedHeader = "unsupported_signed_header"
	ReasonSignatureMismatch       = "signature_mismatch"
	ReasonUnauthorized            = "unauthorized"
)

const (
	algorithm       = "AWS4-HMAC-SHA256"
	terminal        = "aws4_request"
	payloadHash     = "UNSIGNED-PAYLOAD"
	maxSigV4Expires = 7 * 24 * time.Hour
)

type Settings struct {
	AllowedClockSkew  time.Duration
	DefaultMaxExpires time.Duration
	SupportedMethods  []string
	SupportedService  string
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

type Result struct {
	Allowed       bool
	Reason        string
	Path          string
	AccessKey     string
	AccessKeyHash string
}

type Verifier struct {
	state atomic.Value
}

type state struct {
	settings         Settings
	credentials      map[string]*compiledCredential
	supportedMethods map[string]struct{}
}

type compiledCredential struct {
	accessKey       string
	accessKeyHash   string
	secretSeed      []byte
	enabled         bool
	maxExpires      time.Duration
	allowedHosts    map[string]struct{}
	allowedMethods  map[string]struct{}
	allowedPrefixes []string
	signingMu       sync.Mutex
	signingCache    atomic.Pointer[signingKeyCache]
}

type signingKeyCache struct {
	date    string
	region  string
	service string
	key     [sha256.Size]byte
}

type credentialScope struct {
	accessKey string
	date      string
	region    string
	service   string
	terminal  string
	scope     string
}

func New(settings Settings, credentials []Credential) (*Verifier, error) {
	v := &Verifier{}
	if err := v.Reload(settings, credentials); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verifier) Reload(settings Settings, credentials []Credential) error {
	next, err := compileState(settings, credentials)
	if err != nil {
		return err
	}
	v.state.Store(next)
	return nil
}

func (v *Verifier) Ready() bool {
	s, ok := v.current()
	return ok && len(s.credentials) > 0
}

func (v *Verifier) CredentialCount() int {
	s, ok := v.current()
	if !ok {
		return 0
	}
	return len(s.credentials)
}

func (v *Verifier) Verify(method, rawURI, host, _ string, now time.Time) Result {
	s, ok := v.current()
	if !ok {
		return deny(ReasonMissingMetadata, "", "")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	host = strings.ToLower(strings.TrimSpace(host))
	if method == "" || rawURI == "" || host == "" {
		return deny(ReasonMissingMetadata, "", "")
	}
	if _, ok := s.supportedMethods[method]; !ok {
		path, _, _ := splitOriginalURI(rawURI)
		return deny(ReasonUnsupportedMethod, path, "")
	}

	rawPath, rawQuery, err := splitOriginalURI(rawURI)
	if err != nil {
		return deny(ReasonInvalidURI, "", "")
	}
	canonicalQueryString, query, err := canonicalQuery(rawQuery)
	if err != nil {
		return deny(ReasonInvalidURI, rawPath, "")
	}

	alg, ok := singleKnownQueryValue(query.algorithm, query.algorithmCount)
	if !ok {
		return deny(ReasonMissingQueryParam, rawPath, "")
	}
	if alg != algorithm {
		return deny(ReasonUnsupportedAlgorithm, rawPath, "")
	}
	credentialValue, ok := singleKnownQueryValue(query.credential, query.credentialCount)
	if !ok {
		return deny(ReasonMissingQueryParam, rawPath, "")
	}
	scope, err := parseCredentialScope(credentialValue)
	if err != nil {
		return deny(ReasonInvalidCredentialScope, rawPath, "")
	}
	if scope.service != s.settings.SupportedService || scope.terminal != terminal {
		return deny(ReasonInvalidCredentialScope, rawPath, HashAccessKey(scope.accessKey))
	}
	signedHeaders, ok := singleKnownQueryValue(query.signedHeaders, query.signedHeadersCount)
	if !ok {
		return deny(ReasonMissingQueryParam, rawPath, HashAccessKey(scope.accessKey))
	}
	if signedHeaders != "host" {
		return deny(ReasonUnsupportedSignedHeader, rawPath, HashAccessKey(scope.accessKey))
	}
	amzDate, ok := singleKnownQueryValue(query.date, query.dateCount)
	if !ok {
		return deny(ReasonMissingQueryParam, rawPath, HashAccessKey(scope.accessKey))
	}
	signTime, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil || amzDate[:8] != scope.date {
		return deny(ReasonInvalidCredentialScope, rawPath, HashAccessKey(scope.accessKey))
	}
	expiresValue, ok := singleKnownQueryValue(query.expires, query.expiresCount)
	if !ok {
		return deny(ReasonMissingQueryParam, rawPath, HashAccessKey(scope.accessKey))
	}
	expiresSeconds, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil || expiresSeconds <= 0 || expiresSeconds > int64(maxSigV4Expires/time.Second) {
		return deny(ReasonInvalidExpiry, rawPath, HashAccessKey(scope.accessKey))
	}
	if _, ok := singleKnownQueryValue(query.signature, query.signatureCount); !ok {
		return deny(ReasonMissingQueryParam, rawPath, HashAccessKey(scope.accessKey))
	}

	cred := s.credentials[scope.accessKey]
	if cred == nil {
		return deny(ReasonUnknownAccessKey, rawPath, HashAccessKey(scope.accessKey))
	}
	accessKeyHash := cred.accessKeyHash
	if !cred.enabled {
		return deny(ReasonUnauthorized, rawPath, accessKeyHash)
	}
	if !cred.methodAllowed(method) || !cred.hostAllowed(host) || !cred.pathAllowed(rawPath) {
		return deny(ReasonUnauthorized, rawPath, accessKeyHash)
	}
	if time.Duration(expiresSeconds)*time.Second > cred.maxExpires {
		return deny(ReasonInvalidExpiry, rawPath, accessKeyHash)
	}

	now = now.UTC()
	if signTime.After(now.Add(s.settings.AllowedClockSkew)) {
		return deny(ReasonFutureDated, rawPath, accessKeyHash)
	}
	if now.After(signTime.Add(time.Duration(expiresSeconds) * time.Second)) {
		return deny(ReasonExpired, rawPath, accessKeyHash)
	}

	canonicalPath := canonicalURIFromValidPath(rawPath)
	canonicalHost := strings.ToLower(strings.TrimSpace(host))
	canonicalHash := hashCanonicalRequest(method, canonicalPath, canonicalQueryString, canonicalHost)
	expected := sign(cred, scope.date, scope.region, scope.service, amzDate, scope.scope, canonicalHash)

	signatureHex, _ := singleKnownQueryValue(query.signature, query.signatureCount)
	signature, err := decodeSignature(signatureHex)
	if err != nil || !hmac.Equal(signature[:], expected[:]) {
		return deny(ReasonSignatureMismatch, rawPath, accessKeyHash)
	}
	return Result{
		Allowed:       true,
		Reason:        ReasonOK,
		Path:          rawPath,
		AccessKey:     scope.accessKey,
		AccessKeyHash: accessKeyHash,
	}
}

func (v *Verifier) current() (*state, bool) {
	loaded := v.state.Load()
	if loaded == nil {
		return nil, false
	}
	s, ok := loaded.(*state)
	return s, ok
}

func compileState(settings Settings, credentials []Credential) (*state, error) {
	if settings.AllowedClockSkew < 0 {
		return nil, errors.New("allowed clock skew must be non-negative")
	}
	if settings.DefaultMaxExpires <= 0 || settings.DefaultMaxExpires > maxSigV4Expires {
		settings.DefaultMaxExpires = maxSigV4Expires
	}
	if settings.SupportedService == "" {
		settings.SupportedService = "s3"
	}
	if settings.SupportedService != "s3" {
		return nil, fmt.Errorf("unsupported service %q", settings.SupportedService)
	}
	if len(settings.SupportedMethods) == 0 {
		settings.SupportedMethods = []string{"GET", "HEAD"}
	}
	s := &state{
		settings:         settings,
		credentials:      make(map[string]*compiledCredential, len(credentials)),
		supportedMethods: make(map[string]struct{}, len(settings.SupportedMethods)),
	}
	for _, method := range settings.SupportedMethods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "GET" && method != "HEAD" {
			return nil, fmt.Errorf("unsupported method %q", method)
		}
		s.supportedMethods[method] = struct{}{}
	}
	for _, credential := range credentials {
		compiled, err := compileCredential(credential, settings.DefaultMaxExpires)
		if err != nil {
			return nil, err
		}
		if _, exists := s.credentials[compiled.accessKey]; exists {
			return nil, fmt.Errorf("duplicate access key %q", compiled.accessKey)
		}
		s.credentials[compiled.accessKey] = compiled
	}
	return s, nil
}

func compileCredential(credential Credential, defaultMaxExpires time.Duration) (*compiledCredential, error) {
	accessKey := strings.TrimSpace(credential.AccessKey)
	if accessKey == "" {
		return nil, errors.New("access key is required")
	}
	if credential.SecretKey == "" {
		return nil, fmt.Errorf("secret key for %q is required", accessKey)
	}
	maxExpires := credential.MaxExpires
	if maxExpires == 0 {
		maxExpires = defaultMaxExpires
	}
	if maxExpires <= 0 || maxExpires > maxSigV4Expires {
		return nil, fmt.Errorf("invalid max expires for %q", accessKey)
	}
	compiled := &compiledCredential{
		accessKey:       accessKey,
		accessKeyHash:   HashAccessKey(accessKey),
		secretSeed:      []byte("AWS4" + credential.SecretKey),
		enabled:         credential.Enabled,
		maxExpires:      maxExpires,
		allowedHosts:    make(map[string]struct{}, len(credential.AllowedHosts)),
		allowedMethods:  make(map[string]struct{}, len(credential.AllowedMethods)),
		allowedPrefixes: append([]string(nil), credential.AllowedPrefixes...),
	}
	for _, host := range credential.AllowedHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			compiled.allowedHosts[host] = struct{}{}
		}
	}
	for _, method := range credential.AllowedMethods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			compiled.allowedMethods[method] = struct{}{}
		}
	}
	return compiled, nil
}

func parseCredentialScope(value string) (credentialScope, error) {
	first := strings.IndexByte(value, '/')
	if first <= 0 {
		return credentialScope{}, errors.New("invalid credential scope")
	}
	secondRel := strings.IndexByte(value[first+1:], '/')
	if secondRel <= 0 {
		return credentialScope{}, errors.New("invalid credential scope")
	}
	second := first + 1 + secondRel
	thirdRel := strings.IndexByte(value[second+1:], '/')
	if thirdRel <= 0 {
		return credentialScope{}, errors.New("invalid credential scope")
	}
	third := second + 1 + thirdRel
	fourthRel := strings.IndexByte(value[third+1:], '/')
	if fourthRel <= 0 {
		return credentialScope{}, errors.New("invalid credential scope")
	}
	fourth := third + 1 + fourthRel
	if strings.Contains(value[fourth+1:], "/") {
		return credentialScope{}, errors.New("invalid credential scope")
	}
	scope := credentialScope{
		accessKey: value[:first],
		date:      value[first+1 : second],
		region:    value[second+1 : third],
		service:   value[third+1 : fourth],
		terminal:  value[fourth+1:],
		scope:     value[first+1:],
	}
	if scope.accessKey == "" || scope.region == "" || scope.service == "" || scope.terminal == "" {
		return credentialScope{}, errors.New("empty credential scope part")
	}
	if len(scope.date) != 8 {
		return credentialScope{}, errors.New("invalid credential scope date")
	}
	for i := 0; i < len(scope.date); i++ {
		if scope.date[i] < '0' || scope.date[i] > '9' {
			return credentialScope{}, errors.New("invalid credential scope date")
		}
	}
	return scope, nil
}

func hashCanonicalRequest(method, canonicalPath, canonicalQueryString, canonicalHost string) [sha256.Size]byte {
	h := sha256.New()
	writeString(h, method)
	writeString(h, "\n")
	writeString(h, canonicalPath)
	writeString(h, "\n")
	writeString(h, canonicalQueryString)
	writeString(h, "\n")
	writeString(h, "host:")
	writeString(h, canonicalHost)
	writeString(h, "\n\nhost\n")
	writeString(h, payloadHash)
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}

func sign(cred *compiledCredential, date, region, service, amzDate, credentialScope string, canonicalHash [sha256.Size]byte) [sha256.Size]byte {
	kSigning := cred.signingKey(date, region, service)
	mac := hmac.New(sha256.New, kSigning[:])
	writeString(mac, algorithm)
	writeString(mac, "\n")
	writeString(mac, amzDate)
	writeString(mac, "\n")
	writeString(mac, credentialScope)
	writeString(mac, "\n")
	var canonicalHashHex [sha256.Size * 2]byte
	hex.Encode(canonicalHashHex[:], canonicalHash[:])
	mac.Write(canonicalHashHex[:])
	var out [sha256.Size]byte
	mac.Sum(out[:0])
	return out
}

func (c *compiledCredential) signingKey(date, region, service string) *[sha256.Size]byte {
	if cached := c.signingCache.Load(); cached != nil && cached.date == date && cached.region == region && cached.service == service {
		return &cached.key
	}
	c.signingMu.Lock()
	defer c.signingMu.Unlock()
	if cached := c.signingCache.Load(); cached != nil && cached.date == date && cached.region == region && cached.service == service {
		return &cached.key
	}
	kDate := hmacSHA256(c.secretSeed, date)
	kRegion := hmacSHA256(kDate[:], region)
	kService := hmacSHA256(kRegion[:], service)
	kSigning := hmacSHA256(kService[:], terminal)
	cached := &signingKeyCache{
		date:    date,
		region:  region,
		service: service,
		key:     kSigning,
	}
	c.signingCache.Store(cached)
	return &cached.key
}

func hmacSHA256(key []byte, data string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key)
	writeString(mac, data)
	var out [sha256.Size]byte
	mac.Sum(out[:0])
	return out
}

func writeString(w interface{ Write([]byte) (int, error) }, s string) {
	if s == "" {
		return
	}
	// The hash implementations copy from the slice during Write and do not retain it.
	_, _ = w.Write(unsafe.Slice(unsafe.StringData(s), len(s)))
}

func decodeSignature(value string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	if len(value) != sha256.Size*2 {
		return out, errors.New("signature must be 64 hex characters")
	}
	for i := 0; i < sha256.Size; i++ {
		hi := value[i*2]
		lo := value[i*2+1]
		if !isHex(hi) || !isHex(lo) {
			return out, errors.New("signature must be hex")
		}
		out[i] = fromHex(hi)<<4 | fromHex(lo)
	}
	return out, nil
}

func (c *compiledCredential) methodAllowed(method string) bool {
	if len(c.allowedMethods) == 0 {
		return true
	}
	_, ok := c.allowedMethods[method]
	return ok
}

func (c *compiledCredential) hostAllowed(host string) bool {
	if len(c.allowedHosts) == 0 {
		return true
	}
	_, ok := c.allowedHosts[host]
	return ok
}

func (c *compiledCredential) pathAllowed(path string) bool {
	if len(c.allowedPrefixes) == 0 {
		return true
	}
	for _, prefix := range c.allowedPrefixes {
		if path == prefix {
			return true
		}
		if strings.HasPrefix(path, prefix) && (strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/') {
			return true
		}
	}
	return false
}

func deny(reason, path, accessKeyHash string) Result {
	return Result{
		Reason:        reason,
		Path:          path,
		AccessKeyHash: accessKeyHash,
	}
}

func HashAccessKey(accessKey string) string {
	if accessKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(accessKey))
	return "sha256:" + hex.EncodeToString(sum[:8])
}
