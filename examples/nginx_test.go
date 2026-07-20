package examples

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var proxyCacheKeyPattern = regexp.MustCompile(`(?m)^\s*proxy_cache_key\s+([^;]+);`)

func TestNginxCacheKeyIncludesSignedQuery(t *testing.T) {
	config, err := os.ReadFile("nginx.conf")
	if err != nil {
		t.Fatalf("read nginx.conf: %v", err)
	}

	cacheKeys := proxyCacheKeyPattern.FindAllStringSubmatch(string(config), -1)
	if len(cacheKeys) == 0 {
		t.Fatal("nginx.conf has no proxy_cache_key directive")
	}

	for _, match := range cacheKeys {
		cacheKey := strings.TrimSpace(match[1])
		if !strings.Contains(cacheKey, "$request_uri") {
			t.Errorf("proxy_cache_key %q omits $request_uri and can conflate differently signed queries", cacheKey)
		}
	}
}
