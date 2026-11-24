package handlers

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRegistryBlobUsesMetadataFromRequestedMethod(t *testing.T) {
	const small, large = "abc", "abcdef"
	digest := func(data string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(data))) }
	records := map[string]string{
		"tiny": small, "chunked": small, "large": large, "largechunked": large, "exactlarge": large, "cdn": small,
	}
	var headCalls, getCalls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/repository-file" {
			_, _ = w.Write([]byte(small))
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 6 || parts[4] != "blobs" {
			http.NotFound(w, r)
			return
		}
		record := parts[3]
		if record == "private" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		data, ok := records[record]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodHead {
			headCalls.Add(1)
			// A stale HEAD describes the small body even for /large.
			if record == "exactlarge" {
				w.Header().Set("Content-Length", strconv.Itoa(len(large)))
			} else if record != "chunked" {
				w.Header().Set("Content-Length", strconv.Itoa(len(small)))
			}
			return
		}
		getCalls.Add(1)
		switch record {
		case "cdn":
			http.Redirect(w, r, "/repository-file", http.StatusTemporaryRedirect)
			return
		case "chunked", "largechunked":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write([]byte(data))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, `[server]
fileSize = 3
[downloadAuth]
username = "reader"
password = "test-password"
[registries."mirror.example.org"]
upstream = "mirror.example.org"
enabled = true`)
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	InitDockerProxy()
	router.Any("/v2/*path", ProxyDockerRegistryGin)

	for _, tc := range []struct {
		name, method, repository string
		login, mapped            bool
		status                   int
		want                     string
	}{
		{"anonymous at threshold", "GET", "tiny", false, false, 200, small},
		{"anonymous compact chunked", "GET", "chunked", false, true, 200, small},
		{"anonymous redirected", "GET", "cdn", false, false, 200, small},
		{"authenticated redirected length", "GET", "cdn", true, true, 200, small},
		{"anonymous over threshold", "GET", "large", false, false, 401, ""},
		{"anonymous chunked over threshold", "GET", "largechunked", false, true, 401, ""},
		{"authenticated known size", "GET", "large", true, true, 200, large},
		{"authenticated chunked", "GET", "largechunked", true, false, 200, large},
		{"HEAD stays metadata only", "HEAD", "large", false, false, 200, ""},
		{"anonymous large HEAD", "HEAD", "exactlarge", false, false, 401, ""},
		{"authenticated large HEAD", "HEAD", "exactlarge", true, true, 200, ""},
		{"missing HEAD", "HEAD", "missing", false, true, 404, ""},
		{"missing GET", "GET", "missing", false, false, 404, ""},
		{"upstream auth is not a proxy login", "GET", "private", true, true, 403, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "/v2/"
			if tc.mapped {
				prefix += "mirror.example.org/"
			}
			id := digest(records[tc.repository])
			req := httptest.NewRequest(tc.method, prefix+"library/"+tc.repository+"/blobs/"+id, nil)
			if tc.login {
				req.SetBasicAuth("reader", "test-password")
			}
			beforeHead, beforeGet := headCalls.Load(), getCalls.Load()
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.login && !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatal("authenticated blob response can be cached")
			}
			if tc.status == 200 {
				if got := w.Body.String(); got != tc.want {
					t.Fatalf("body=%q, want %q", got, tc.want)
				}
				if w.Header().Get("Docker-Content-Digest") != id {
					t.Fatalf("missing digest %s", id)
				}
				if tc.method == http.MethodGet && tc.repository != "largechunked" && w.Header().Get("Content-Length") != strconv.Itoa(len(tc.want)) {
					t.Fatalf("Content-Length=%q, want %d", w.Header().Get("Content-Length"), len(tc.want))
				}
			}
			if tc.status == 401 && w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing proxy login challenge")
			}
			if tc.method == http.MethodHead && getCalls.Load() != beforeGet {
				t.Fatal("HEAD fetched a blob body")
			}
			if tc.method == http.MethodGet && headCalls.Load() != beforeHead {
				t.Fatal("GET used a separate HEAD request")
			}
		})
	}
}

func TestRegistryBlobClientDetectsUpstreamFailure(t *testing.T) {
	const blockSize = 128 << 10
	expected := strings.Repeat("a", blockSize)
	corrupt := strings.Repeat("b", blockSize)
	id := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(expected)))
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch strings.Split(r.URL.Path, "/")[3] {
		case "empty":
			w.Header().Set("Content-Length", "0")
		case "known":
			w.Header().Set("Content-Length", strconv.Itoa(blockSize))
			_, _ = io.WriteString(w, corrupt)
		case "short":
			w.Header().Set("Content-Length", strconv.Itoa(blockSize))
			_, _ = io.WriteString(w, expected[:blockSize/2])
		case "unknown":
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, corrupt)
		}
	}))
	defer upstream.Close()
	router := newGitHubProxyTestRouter(t, `[downloadAuth]
username = "reader"
password = "test-password"`)
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	InitDockerProxy()
	router.Any("/v2/*path", ProxyDockerRegistryGin)
	proxy := httptest.NewServer(router)
	defer proxy.Close()
	h2 := httptest.NewUnstartedServer(router)
	h2.EnableHTTP2 = true
	h2.StartTLS()
	defer h2.Close()

	for _, tc := range []struct {
		repo   string
		server *httptest.Server
	}{
		{"empty", proxy}, {"known", proxy}, {"short", proxy}, {"unknown", proxy}, {"unknown", h2},
	} {
		protocol := "http1"
		if tc.server == h2 {
			protocol = "http2"
		}
		t.Run(protocol+"/"+tc.repo, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.server.URL+"/v2/library/"+tc.repo+"/blobs/"+id, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth("reader", "test-password")
			resp, err := tc.server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if tc.server == h2 && resp.ProtoMajor != 2 {
				t.Fatalf("protocol = %s, want HTTP/2", resp.Proto)
			}
			data, readErr := io.ReadAll(resp.Body)
			if tc.repo == "empty" {
				if readErr != nil || resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Docker-Content-Digest") != "" {
					t.Fatalf("first read failure: status=%d headers=%v err=%v", resp.StatusCode, resp.Header, readErr)
				}
				return
			}
			if resp.StatusCode != http.StatusOK || len(data) == 0 || readErr == nil {
				t.Fatalf("started blob: status=%d bytes=%d err=%v", resp.StatusCode, len(data), readErr)
			}
			if tc.repo == "known" && len(data) >= blockSize {
				t.Fatalf("delivered entire declared length before digest validation: %d", len(data))
			}
		})
	}
}
