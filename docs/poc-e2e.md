# End-to-End POC: NGINX + Unix Socket Sidecar

This POC proves the complete request path:

1. Build the local `sigv4-verify` sidecar as a tiny Linux container image.
2. Start the sidecar with either `NETWORK=unix` or `NETWORK=tcp` through YAML
   config.
3. Start an ephemeral `nginx:1.27-alpine` container.
4. For Unix sockets, share a Docker volume between the two containers at
   `/sock`. For TCP, place both containers on an isolated Docker network.
5. Configure NGINX `auth_request` to call `http://sigv4_verify/verify` over
   `unix:/sock/sigv4-verify.sock` or `sigv4-sidecar:8080`.
6. Generate real MinIO-compatible presigned URLs in Go.
7. Send requests through NGINX and verify allow, deny, and fail-closed behavior.

Run it with:

```sh
go test -tags=e2e ./e2e -run 'TestNginx.*E2E' -count=1 -v
```

Prerequisites:

- Go 1.26.4.
- Docker with the daemon running.
- Access to `nginx:1.27-alpine`, either already pulled or pullable by Docker.

Useful overrides:

```sh
E2E_NGINX_IMAGE=nginx:alpine go test -tags=e2e ./e2e -run 'TestNginx.*E2E' -count=1 -v
E2E_GOARCH=amd64 go test -tags=e2e ./e2e -run 'TestNginx.*E2E' -count=1 -v
```

Use `-count=1` for this POC. The test depends on external Docker daemon state,
and normal Go test caching can otherwise replay an old skipped result.

The e2e harness runs the same case matrix for Unix socket and TCP transport:

- Valid presigned `GET` through NGINX returns `200`.
- Valid presigned `HEAD` through NGINX returns `200` with no body.
- Valid auth with a missing origin object returns origin `404`.
- Percent-encoded path and signed response query parameters survive NGINX.
- A URL signed for `HEAD` cannot be used with `GET`.
- Unsupported client methods fail with `403`.
- Missing SigV4 query parameters fail with `403`.
- Tampered signatures fail with `403`.
- Expired URLs fail with `403`.
- URLs signed for another host fail with `403`.
- Paths outside the allowed prefix fail with `403`.
- The internal auth location is not publicly reachable.
- Stopping the sidecar makes NGINX fail closed with `500`.

The POC uses static files in NGINX as the origin fixture. That keeps the test
small while still exercising the real NGINX `auth_request` subrequest, Unix
socket upstream, original request headers, sidecar verification, and protected
content serving path.

## Manual Presigning

The repository also includes a small presign helper:

```sh
go run ./cmd/presign-url \
  -endpoint assets.example.test \
  -secure=false \
  -access-key e2e-access-key \
  -secret-key e2e-secret-key \
  -bucket my-bucket \
  -object public/file.txt \
  -expiry 5m
```

The endpoint must match the public `Host` value NGINX passes to the sidecar.
For local tests against a loopback listener, request the loopback address while
sending the signed host header, for example:

```sh
curl -H 'Host: assets.example.test' 'http://127.0.0.1:8080/my-bucket/public/file.txt?...'
```
