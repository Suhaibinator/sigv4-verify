package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func main() {
	var (
		endpoint                   = flag.String("endpoint", "", "public host used by clients, without scheme, for example assets.example.com")
		accessKey                  = flag.String("access-key", "", "access key; defaults to SIGV4_ACCESS_KEY, MINIO_ACCESS_KEY, or AWS_ACCESS_KEY_ID")
		secretKey                  = flag.String("secret-key", "", "secret key; defaults to SIGV4_SECRET_KEY, MINIO_SECRET_KEY, or AWS_SECRET_ACCESS_KEY")
		bucket                     = flag.String("bucket", "", "bucket name")
		object                     = flag.String("object", "", "object key inside the bucket")
		method                     = flag.String("method", http.MethodGet, "HTTP method to presign: GET or HEAD")
		region                     = flag.String("region", "us-east-1", "SigV4 region")
		expiry                     = flag.Duration("expiry", 5*time.Minute, "URL expiry duration")
		secure                     = flag.Bool("secure", true, "use https scheme in the generated URL")
		responseContentDisposition = flag.String("response-content-disposition", "", "optional response-content-disposition query value")
		responseContentType        = flag.String("response-content-type", "", "optional response-content-type query value")
	)
	flag.Parse()

	secureSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "secure" {
			secureSet = true
		}
	})

	normalizedEndpoint, schemeSecure, hasScheme := normalizeEndpoint(*endpoint)
	*endpoint = normalizedEndpoint
	if hasScheme && !secureSet {
		*secure = schemeSecure
	}
	*accessKey = firstNonEmpty(*accessKey, os.Getenv("SIGV4_ACCESS_KEY"), os.Getenv("MINIO_ACCESS_KEY"), os.Getenv("AWS_ACCESS_KEY_ID"))
	*secretKey = firstNonEmpty(*secretKey, os.Getenv("SIGV4_SECRET_KEY"), os.Getenv("MINIO_SECRET_KEY"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
	*method = strings.ToUpper(strings.TrimSpace(*method))

	if *endpoint == "" || *accessKey == "" || *secretKey == "" || *bucket == "" || *object == "" {
		fmt.Fprintln(os.Stderr, "endpoint, access key, secret key, bucket, and object are required")
		flag.Usage()
		os.Exit(2)
	}
	if *expiry <= 0 {
		fmt.Fprintln(os.Stderr, "expiry must be positive")
		os.Exit(2)
	}

	client, err := minio.New(*endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(*accessKey, *secretKey, ""),
		Secure:       *secure,
		Region:       *region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize presigner: %v\n", err)
		os.Exit(1)
	}

	params := url.Values{}
	if *responseContentDisposition != "" {
		params.Set("response-content-disposition", *responseContentDisposition)
	}
	if *responseContentType != "" {
		params.Set("response-content-type", *responseContentType)
	}

	u, err := presign(context.Background(), client, *method, *bucket, *object, *expiry, params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "presign URL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(u.String())
}

func presign(ctx context.Context, client *minio.Client, method, bucket, object string, expiry time.Duration, params url.Values) (*url.URL, error) {
	switch method {
	case http.MethodGet:
		return client.PresignedGetObject(ctx, bucket, object, expiry, params)
	case http.MethodHead:
		return client.PresignedHeadObject(ctx, bucket, object, expiry, params)
	default:
		return nil, fmt.Errorf("unsupported method %q", method)
	}
}

func normalizeEndpoint(endpoint string) (string, bool, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if strings.HasPrefix(endpoint, "https://") {
		return strings.TrimRight(strings.TrimPrefix(endpoint, "https://"), "/"), true, true
	}
	if strings.HasPrefix(endpoint, "http://") {
		return strings.TrimRight(strings.TrimPrefix(endpoint, "http://"), "/"), false, true
	}
	return strings.TrimRight(endpoint, "/"), true, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
