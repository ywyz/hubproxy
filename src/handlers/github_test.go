package handlers

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"hubproxy/config"
	"hubproxy/utils"
)

func newGitHubProxyTestRouter(t *testing.T, configBody string) *gin.Engine {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", configPath)
	if err := config.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	utils.InitHTTPClients()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.NoRoute(GitHubProxyHandler)
	return router
}

func performGitHubProxyRequest(router http.Handler, method, target string, headers http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/"+target, nil)
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func configureDirectLinkTestUpstream(t *testing.T, upstream *httptest.Server, hostname string) string {
	t.Helper()

	previousLookup := lookupDirectLinkIPs
	lookupDirectLinkIPs = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if strings.EqualFold(host, hostname) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return previousLookup(context.Background(), "ip", host)
	}
	t.Cleanup(func() { lookupDirectLinkIPs = previousLookup })

	transport := upstream.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true // Test-only host mapping to httptest TLS.
	upstreamAddress := upstream.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstreamAddress)
	}
	utils.GetGlobalHTTPClient().Transport = transport

	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	return "https://" + net.JoinHostPort(hostname, parsed.Port())
}

func routeGlobalHTTPClientToTestUpstream(t *testing.T, upstream *httptest.Server) {
	t.Helper()

	transport := upstream.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true // Test-only host mapping to httptest TLS.
	upstreamAddress := upstream.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstreamAddress)
	}
	utils.GetGlobalHTTPClient().Transport = transport
}

func TestCheckGitHubURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		user string
		repo string
	}{
		{"release", "https://github.com/user/repo/releases/download/v1/file.tar.gz", "user", "repo"},
		{"raw", "https://raw.githubusercontent.com/user/repo/main/file.sh", "user", "repo"},
		{"api", "https://api.github.com/repos/user/repo/releases/latest", "user", "repo"},
		{"huggingface", "https://huggingface.co/user/model/resolve/main/file", "user", "model/resolve/main/file"},
		{"direct", "https://ollama.com/download/OllamaSetup.exe", "ollama.com", "download/OllamaSetup.exe"},
		{"direct with query", "https://downloads.example.com/files/app.zip?arch=amd64", "downloads.example.com", "files/app.zip?arch=amd64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckGitHubURL(tt.url)
			if len(got) < 2 || got[0] != tt.user || got[1] != tt.repo {
				t.Fatalf("CheckGitHubURL(%q) = %#v", tt.url, got)
			}
		})
	}
}

func TestCheckGitHubURLRejectsInvalidDirectLinks(t *testing.T) {
	tests := []string{
		"http://downloads.example.com/files/app.zip",
		"ftp://downloads.example.com/files/app.zip",
		"https://downloads.example.com",
		"not-a-url",
	}

	for _, rawURL := range tests {
		if got := CheckGitHubURL(rawURL); got != nil {
			t.Fatalf("CheckGitHubURL(%q) unexpectedly matched: %#v", rawURL, got)
		}
	}
}

func TestDirectLinkRejectsMethodsOtherThanGetAndHead(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
		recorder := performGitHubProxyRequest(router, method, upstreamURL+"/file.zip", nil)
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d, want 405; body=%s", method, recorder.Code, recorder.Body.String())
		}
		if allow := recorder.Header().Get("Allow"); allow != "GET, HEAD" {
			t.Fatalf("%s Allow = %q, want %q", method, allow, "GET, HEAD")
		}
	}

	head := performGitHubProxyRequest(router, http.MethodHead, upstreamURL+"/file.zip", nil)
	if head.Code != http.StatusNoContent {
		t.Fatalf("HEAD status = %d, want 204; body=%s", head.Code, head.Body.String())
	}
}

func TestDirectLinkForwardsOnlyAllowedRequestHeaders(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	headers := http.Header{
		"Authorization":       {"Bearer proxy-secret"},
		"Proxy-Authorization": {"Basic proxy-secret"},
		"Cookie":              {"session=proxy-secret"},
		"X-Api-Key":           {"proxy-secret"},
		"Range":               {"bytes=1-2"},
		"User-Agent":          {"hubproxy-test"},
	}

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/file.zip", headers)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	got := <-received
	if got.Get("Range") != "bytes=1-2" || got.Get("User-Agent") != "hubproxy-test" {
		t.Fatalf("allowed download headers were not preserved: %#v", got)
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key"} {
		if value := got.Get(name); value != "" {
			t.Fatalf("%s leaked to direct-link upstream: %q", name, value)
		}
	}
}

func TestDirectLinkRelativeRedirectIsRevalidatedAgainstAccessList(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/allowed/file.zip" {
			http.Redirect(w, r, "/private/file.zip", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("private"))
	}))
	defer upstream.Close()

	parsedUpstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	allowedResource := net.JoinHostPort("downloads.example.com", parsedUpstreamURL.Port()) + "/allowed/*"
	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList = [\""+allowedResource+"\"]\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/allowed/file.zip", nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "private") {
		t.Fatalf("disallowed redirect body was proxied: %q", recorder.Body.String())
	}
}

func TestDirectLinkRedirectRejectsHTTPAndPrivateTargets(t *testing.T) {
	for _, test := range []struct {
		name     string
		location func(port string) string
	}{
		{
			name: "HTTP downgrade",
			location: func(port string) string {
				return "http://downloads.example.com:" + port + "/redirected.zip"
			},
		},
		{
			name: "private address",
			location: func(port string) string {
				return "https://127.0.0.1:" + port + "/redirected.zip"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var redirectLocation string
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start.zip" {
					http.Redirect(w, r, redirectLocation, http.StatusFound)
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write([]byte("redirected"))
			}))
			defer upstream.Close()

			parsedUpstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			redirectLocation = test.location(parsedUpstreamURL.Port())
			whiteList := []string{
				net.JoinHostPort("downloads.example.com", parsedUpstreamURL.Port()) + "/*",
				net.JoinHostPort("127.0.0.1", parsedUpstreamURL.Port()) + "/*",
			}
			configBody := "[access]\nwhiteList = [\"" + strings.Join(whiteList, "\", \"") + "\"]\n"
			router := newGitHubProxyTestRouter(t, configBody)
			upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

			recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/start.zip", nil)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "redirected") {
				t.Fatalf("unsafe redirect body was proxied: %q", recorder.Body.String())
			}
		})
	}
}

func TestDirectLinkRejectsPrivateTargetAddresses(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("internal"))
	}))
	defer upstream.Close()

	allowedResource := strings.TrimPrefix(upstream.URL, "https://") + "/*"
	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList = [\""+allowedResource+"\"]\n")
	utils.GetGlobalHTTPClient().Transport = upstream.Client().Transport

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstream.URL+"/internal.zip", nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "internal") {
		t.Fatalf("private target body was proxied: %q", recorder.Body.String())
	}
}

func TestDirectLinkBodyLimitReturns413BeforeStreaming(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("12345"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 4\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/chunked.bin", nil)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "1234") {
		t.Fatalf("upstream prefix was streamed before the 413 response: %q", recorder.Body.String())
	}
}

func TestDirectLinkAccessIgnoresHostCaseButPreservesPathAndQueryCase(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	parsedUpstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	allowedResource := net.JoinHostPort("DOWNLOADS.EXAMPLE.COM", parsedUpstreamURL.Port()) + "/Files/App.zip?Token=ABC"
	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList = [\""+allowedResource+"\"]\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	allowed := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/Files/App.zip?Token=ABC", nil)
	if allowed.Code != http.StatusOK {
		t.Fatalf("same resource with different host case returned %d, want 200; body=%s", allowed.Code, allowed.Body.String())
	}

	pathCaseChanged := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/files/App.zip?Token=ABC", nil)
	if pathCaseChanged.Code != http.StatusForbidden {
		t.Fatalf("different path case returned %d, want 403; body=%s", pathCaseChanged.Code, pathCaseChanged.Body.String())
	}

	queryCaseChanged := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/Files/App.zip?token=ABC", nil)
	if queryCaseChanged.Code != http.StatusForbidden {
		t.Fatalf("different query case returned %d, want 403; body=%s", queryCaseChanged.Code, queryCaseChanged.Body.String())
	}
}

func TestGitSmartHTTPPreservesPostAndGitHubAuthorization(t *testing.T) {
	received := make(chan struct {
		method        string
		authorization string
	}, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct {
			method        string
			authorization string
		}{r.Method, r.Header.Get("Authorization")}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		_, _ = w.Write([]byte("git-result"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	headers := http.Header{"Authorization": {"Bearer github-token"}}

	recorder := performGitHubProxyRequest(router, http.MethodPost, "https://github.com/owner/repo/git-upload-pack", headers)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	got := <-received
	if got.method != http.MethodPost || got.authorization != "Bearer github-token" {
		t.Fatalf("upstream request = %#v, want POST with GitHub Authorization", got)
	}
}

func TestGitHubDownloadStillFollowsExternalAssetRedirectWithoutLeakingAuthorization(t *testing.T) {
	cdnAuthorization := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "github.com":
			http.Redirect(w, r, "https://cdn.example.com/asset.zip", http.StatusFound)
		case "cdn.example.com":
			cdnAuthorization <- r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("asset"))
		default:
			http.Error(w, "unexpected host", http.StatusBadRequest)
		}
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	headers := http.Header{"Authorization": {"Bearer github-token"}}

	recorder := performGitHubProxyRequest(router, http.MethodGet, "https://github.com/owner/repo/releases/download/v1/asset.zip", headers)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "asset" {
		t.Fatalf("response = %d %q, want 200 asset", recorder.Code, recorder.Body.String())
	}
	if got := <-cdnAuthorization; got != "" {
		t.Fatalf("GitHub Authorization leaked to external asset host: %q", got)
	}
}
