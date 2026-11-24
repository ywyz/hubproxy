package handlers

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestPreparedArchiveReleasesQuotaAndTokenAfterIdleRegistryBody(t *testing.T) {
	layer := static.NewLayer([]byte("local test layer"), types.OCIUncompressedLayer)
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := img.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	configBlob, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := layer.Digest()
	if err != nil {
		t.Fatal(err)
	}
	usage := func() int64 {
		directLinkStagingQuota.mu.Lock()
		defer directLinkStagingQuota.mu.Unlock()
		return directLinkStagingQuota.used
	}
	canceled := make(chan struct{}, 1)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", string(types.DockerManifestSchema2))
			_, _ = w.Write(manifest)
		case strings.HasSuffix(r.URL.Path, hash.String()):
			if usage() == 0 {
				t.Error("expected staged archive bytes before the layer fetch")
			}
			_, _ = io.WriteString(w, "l")
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				select {
				case canceled <- struct{}{}:
				default:
				}
			case <-time.After(3 * time.Second):
				t.Error("registry body was not canceled")
			}
		case strings.Contains(r.URL.Path, "/blobs/"):
			_, _ = w.Write(configBlob)
		default:
			http.NotFound(w, r)
		}
	}))
	defer origin.Close()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize=65536")
	routeGlobalHTTPClientToTestUpstream(t, origin)
	idle := directLinkBodyIdleTimeout
	previousStreamer := globalImageStreamer
	directLinkBodyIdleTimeout = 75 * time.Millisecond
	t.Cleanup(func() {
		directLinkBodyIdleTimeout = idle
		globalImageStreamer = previousStreamer
	})
	InitImageStreamer()
	InitDebouncer()
	InitImageTarRoutes(router)
	get := func(url string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		return w
	}
	var prepare struct {
		URL string `json:"download_url"`
	}
	w := get("/api/image/download?mode=prepare&image=registry.example.org/library/demo:latest")
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &prepare) != nil || prepare.URL == "" {
		t.Fatalf("prepare failed: %d %s", w.Code, w.Body.String())
	}
	if w := get(prepare.URL); w.Code != http.StatusGatewayTimeout || w.Header().Get("Content-Disposition") != "" {
		t.Fatalf("idle archive returned %d %q", w.Code, w.Body.String())
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("registry did not observe cancellation")
	}
	downloadURL, err := url.Parse(prepare.URL)
	if err != nil {
		t.Fatal(err)
	}
	singleDownloadTokens.mu.RLock()
	_, retained := singleDownloadTokens.entries[downloadURL.Query().Get("token")]
	singleDownloadTokens.mu.RUnlock()
	if usage() != 0 || retained {
		t.Fatal("failed archive retained quota or an in-flight token")
	}
}

func TestPreparedArchiveRetry(t *testing.T) {
	manifest, err := empty.Image.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	configBlob, err := empty.Image.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	mediaType, err := empty.Image.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", string(mediaType))
			_, _ = w.Write(manifest)
		case strings.Contains(r.URL.Path, "/blobs/"):
			_, _ = w.Write(configBlob)
		default:
			http.NotFound(w, r)
		}
	}))
	defer origin.Close()
	const image = "registry.example.org/library/demo:latest"
	for _, batch := range []bool{false, true} {
		for _, busy := range []bool{false, true} {
			t.Run(fmt.Sprintf("batch=%t/busy=%t", batch, busy), func(t *testing.T) {
				limit := 1024
				if busy {
					limit = 64 * 1024
				}
				cfg := fmt.Sprintf("[server]\nfileSize=%d\n[downloadAuth]\nusername='reader'\npassword='test-password'\n", limit)
				router := newGitHubProxyTestRouter(t, cfg)
				routeGlobalHTTPClientToTestUpstream(t, origin)
				InitDebouncer()
				InitImageStreamer()
				InitImageTarRoutes(router)

				req := httptest.NewRequest("GET", "/api/image/download?mode=prepare&image="+image, nil)
				if batch {
					body := strings.NewReader(`{"images":["` + image + `"]}`)
					req = httptest.NewRequest("POST", "/api/image/batch?mode=prepare", body)
					req.Header.Set("Content-Type", "application/json")
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				var prepare struct {
					URL string `json:"download_url"`
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &prepare) != nil || prepare.URL == "" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("prepare: %d %s", w.Code, w.Body.String())
				}
				get := func(login bool) *httptest.ResponseRecorder {
					req := httptest.NewRequest("GET", prepare.URL, nil)
					if login {
						req.SetBasicAuth("reader", "test-password")
					}
					w := httptest.NewRecorder()
					router.ServeHTTP(w, req)
					return w
				}
				if busy {
					directLinkStagingQuota.reserve(int64(limit), int64(limit))
					w = get(false)
					directLinkStagingQuota.release(int64(limit))
					if w.Code != http.StatusServiceUnavailable {
						t.Fatalf("spool busy: %d %q", w.Code, w.Body.String())
					}
				} else {
					for range 2 {
						if w := get(false); w.Code != http.StatusUnauthorized || w.Header().Get("Content-Disposition") != "" {
							t.Fatalf("size challenge: %d %v", w.Code, w.Header())
						}
					}
				}
				w = get(!busy)
				if w.Code != 200 {
					t.Fatalf("retry: %d %s", w.Code, w.Body.String())
				}
				tr := tar.NewReader(w.Body)
				foundManifest := false
				for {
					h, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if h.Name == "manifest.json" {
						foundManifest = true
					}
				}
				if !foundManifest || get(true).Code != http.StatusBadRequest {
					t.Fatal("expected a complete single-use tar download")
				}
			})
		}
	}
}

func TestDownloadDebouncer(t *testing.T) {
	d := NewDownloadDebouncer(time.Minute)
	if !d.ShouldAllow("user", "content") {
		t.Fatal("first request denied")
	}
	if d.ShouldAllow("user", "content") {
		t.Fatal("duplicate request allowed")
	}
	if !d.ShouldAllow("other", "content") {
		t.Fatal("different user denied")
	}
}

func TestTokenStoreCreateConsume(t *testing.T) {
	store := newTokenStore[SingleDownloadRequest]()
	req := SingleDownloadRequest{Image: "nginx:latest", Platform: "linux/amd64", UseCompressedLayers: true}

	token, err := store.create(req, "127.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}

	got, finish, err := store.claim(token, "127.0.0.1", "ua", false)
	if err != nil {
		t.Fatal("token not consumed")
	}
	if got != req {
		t.Fatalf("request = %#v, want %#v", got, req)
	}
	finish(nil)
	if _, _, err := store.claim(token, "127.0.0.1", "ua", false); err == nil {
		t.Fatal("token consumed twice")
	}
}

func TestTokenStoreRejectsDifferentClient(t *testing.T) {
	store := newTokenStore[SingleDownloadRequest]()
	token, err := store.create(SingleDownloadRequest{Image: "nginx:latest"}, "127.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.claim(token, "127.0.0.2", "ua", false); err == nil {
		t.Fatal("token accepted for different IP")
	}
}

func TestGenerateContentFingerprintStable(t *testing.T) {
	a := generateContentFingerprint([]string{"b:1", "a:1"}, "linux/amd64")
	b := generateContentFingerprint([]string{"a:1", "b:1"}, "linux/amd64")
	c := generateContentFingerprint([]string{"a:1", "b:1"}, "linux/arm64")
	if a != b || a == c {
		t.Fatalf("unexpected fingerprints: %q %q %q", a, b, c)
	}
}

func TestResolveImageRef(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("query preserves underscores", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/api/image/download?image=user/my_app:v1", nil)
		if got := resolveImageRef(c); got != "user/my_app:v1" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("missing image is empty", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/api/image/download", nil)
		if got := resolveImageRef(c); got != "" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestWriteDownloadErrorSkipsJSONAfterBodyStarted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("before write returns json", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		writeDownloadError(c, errors.New("boom"), "镜像下载失败")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "镜像下载失败") || !strings.Contains(body, "boom") {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("after write skips json", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		if _, err := c.Writer.Write([]byte("tar-bytes")); err != nil {
			t.Fatal(err)
		}
		writeDownloadError(c, errors.New("boom"), "镜像下载失败")
		if got := w.Body.String(); got != "tar-bytes" {
			t.Fatalf("body corrupted: %q", got)
		}
	})
}
