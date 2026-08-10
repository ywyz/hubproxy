package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func configureMultiAddressDirectLinkTestUpstream(t *testing.T, upstream *httptest.Server, hostname string) string {
	t.Helper()

	previousLookup := lookupDirectLinkIPs
	lookupDirectLinkIPs = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if strings.EqualFold(host, hostname) {
			return []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("1.0.0.1"),
			}, nil
		}
		return previousLookup(context.Background(), "ip", host)
	}
	t.Cleanup(func() { lookupDirectLinkIPs = previousLookup })

	transport := upstream.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true // Test-only host mapping to httptest TLS.
	upstreamAddress := upstream.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if host == "1.1.1.1" {
			return nil, errors.New("first validated address is unavailable")
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstreamAddress)
	}
	utils.GetGlobalHTTPClient().Transport = transport

	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	return "https://" + net.JoinHostPort(hostname, parsed.Port())
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

func TestDirectLinkStripsOriginAuthenticationResponseHeaders(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="file.zip"`)
		w.Header().Set("Set-Cookie", "session=attacker; Secure; HttpOnly")
		w.Header().Set("Www-Authenticate", `Basic realm="attacker"`)
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/file.zip", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Disposition"); got == "" {
		t.Fatal("download response header was removed")
	}
	for _, name := range []string{"Set-Cookie", "Set-Cookie2", "Www-Authenticate", "Proxy-Authenticate", "Authentication-Info"} {
		if value := recorder.Header().Get(name); value != "" {
			t.Fatalf("%s leaked from direct-link upstream: %q", name, value)
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

func TestDirectLinkBodyLimitUsesCompleteContentRangeSize(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=0-3" {
			t.Errorf("Range = %q, want bytes=0-3", r.Header.Get("Range"))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Range", "bytes 0-3/10")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("1234"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 4\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	headers := http.Header{"Range": {"bytes=0-3"}}

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/large.bin", headers)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "1234") {
		t.Fatalf("partial content was streamed before the 413 response: %q", recorder.Body.String())
	}
}

func TestDirectLinkRejectsInvalidPartialContentRange(t *testing.T) {
	for _, contentRange := range []string{"", "bytes 0-3/*", "bytes 4-3/10"} {
		t.Run(contentRange, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				if contentRange != "" {
					w.Header().Set("Content-Range", contentRange)
				}
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte("1234"))
			}))
			defer upstream.Close()

			router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 10\n")
			upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
			headers := http.Header{"Range": {"bytes=0-3"}}

			recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/file.bin", headers)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502; body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestDirectLinkBodyLimitDoesNotOverflowAtMaxInt64(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 9223372036854775807\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/file.bin", nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "file" {
		t.Fatalf("response = %d %q, want 200 file", recorder.Code, recorder.Body.String())
	}
}

func TestDirectLinkStagingStopsWhenClientDisconnects(t *testing.T) {
	started := make(chan struct{})
	upstreamCanceled := make(chan struct{})
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
			close(upstreamCanceled)
		case <-releaseUpstream:
		}
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 1048576\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/"+upstreamURL+"/slow.bin", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		router.ServeHTTP(recorder, req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(releaseUpstream)
		t.Fatal("upstream request did not start")
	}
	cancel()

	select {
	case <-upstreamCanceled:
	case <-time.After(500 * time.Millisecond):
		close(releaseUpstream)
		<-done
		t.Fatal("upstream request continued after the client disconnected")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy handler did not stop after client cancellation")
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

func TestDirectLinkAccessRejectsAmbiguousOrTraversingPaths(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("private"))
	}))
	defer upstream.Close()

	parsedUpstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	allowedResource := net.JoinHostPort("downloads.example.com", parsedUpstreamURL.Port()) + "/public/*"
	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList = [\""+allowedResource+"\"]\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	for _, requestPath := range []string{
		"/public/../private/file.zip",
		"/public/%2e%2e/private/file.zip",
		"/public%2F..%2Fprivate/file.zip",
		"/public\\..\\private\\file.zip",
		"/public/file%3Ftoken=secret.zip",
		"/public/file%23fragment.zip",
	} {
		recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+requestPath, nil)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%q status = %d, want 403; body=%q", requestPath, recorder.Code, recorder.Body.String())
		}
	}
}

func TestDirectLinkAccessNormalizesDefaultHTTPSPort(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList = [\"downloads.example.com:443/files/*\"]\n")
	_ = configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, "https://downloads.example.com/files/app.zip", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}

	blockedRouter := newGitHubProxyTestRouter(t, "[access]\nblackList = [\"downloads.example.com/files/*\"]\n")
	blocked := performGitHubProxyRequest(blockedRouter, http.MethodGet, "https://downloads.example.com:443/files/app.zip", nil)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("explicit :443 with portless blacklist returned %d, want 403; body=%s", blocked.Code, blocked.Body.String())
	}
}

func TestDirectLinkRetriesValidatedTargetAddresses(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	upstreamURL := configureMultiAddressDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/file.zip", nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "file" {
		t.Fatalf("response = %d %q, want 200 file", recorder.Code, recorder.Body.String())
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
