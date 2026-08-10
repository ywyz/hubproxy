package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	if !strings.Contains(configBody, "[access]") {
		configBody += "\n[access]\ndirectLinkWhiteList = [\"*/*\"]\n"
	}

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

func performGitHubProxyRequestWithBody(router http.Handler, method, target, body string, headers http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/"+target, strings.NewReader(body))
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

func TestDirectLinksRequireDedicatedWhitelist(t *testing.T) {
	for _, test := range []struct {
		name       string
		configBody string
	}{
		{name: "empty direct-link whitelist", configBody: "[access]\n"},
		{name: "legacy repository wildcard", configBody: "[access]\nwhiteList = [\"*/allowed-repo\"]\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := newGitHubProxyTestRouter(t, test.configBody)
			recorder := performGitHubProxyRequest(
				router,
				http.MethodGet,
				"https://attacker.example/allowed-repo/file.zip",
				nil,
			)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
			}
		})
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
	router := newGitHubProxyTestRouter(t, "[access]\ndirectLinkWhiteList = [\""+allowedResource+"\"]\n")
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
			directLinkWhiteList := []string{
				net.JoinHostPort("downloads.example.com", parsedUpstreamURL.Port()) + "/*",
				net.JoinHostPort("127.0.0.1", parsedUpstreamURL.Port()) + "/*",
			}
			configBody := "[access]\ndirectLinkWhiteList = [\"" + strings.Join(directLinkWhiteList, "\", \"") + "\"]\n"
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
	router := newGitHubProxyTestRouter(t, "[access]\ndirectLinkWhiteList = [\""+allowedResource+"\"]\n")
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
	router := newGitHubProxyTestRouter(t, "[access]\ndirectLinkWhiteList = [\""+allowedResource+"\"]\n")
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
	router := newGitHubProxyTestRouter(t, "[access]\ndirectLinkWhiteList = [\""+allowedResource+"\"]\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	for _, requestPath := range []string{
		"/public/../private/file.zip",
		"/public/%2e%2e/private/file.zip",
		"/public/%252e%252e/private/file.zip",
		"/public/%25252e%25252e/private/file.zip",
		"/public%2F..%2Fprivate/file.zip",
		"/public%252F..%252Fprivate/file.zip",
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

	router := newGitHubProxyTestRouter(t, "[access]\ndirectLinkWhiteList = [\"downloads.example.com:443/files/*\"]\n")
	_ = configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, "https://downloads.example.com/files/app.zip", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}

	blockedRouter := newGitHubProxyTestRouter(t, "[access]\ndirectLinkWhiteList = [\"*/*\"]\ndirectLinkBlackList = [\"downloads.example.com/files/*\"]\n")
	blocked := performGitHubProxyRequest(blockedRouter, http.MethodGet, "https://downloads.example.com:443/files/app.zip", nil)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("explicit :443 with portless blacklist returned %d, want 403; body=%s", blocked.Code, blocked.Body.String())
	}
	blockedEquivalentPort := performGitHubProxyRequest(blockedRouter, http.MethodGet, "https://downloads.example.com:0443/files/app.zip", nil)
	if blockedEquivalentPort.Code != http.StatusForbidden {
		t.Fatalf("numeric-equivalent :0443 with portless blacklist returned %d, want 403; body=%s", blockedEquivalentPort.Code, blockedEquivalentPort.Body.String())
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

func TestDirectLinkForcesNonExecutableAttachmentResponse(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Disposition", "inline")
		_, _ = w.Write([]byte("alert('from upstream')"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/payload.js", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", got)
	}
	if got := recorder.Header().Get("Content-Disposition"); got != "attachment" {
		t.Fatalf("Content-Disposition = %q, want attachment", got)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestRewrittenRedirectDropsHeadersForBodyThatIsNotForwarded(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://github.com/owner/repo/releases/download/v2/file.zip")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Range", "bytes 0-7/8")
		w.Header().Set("Content-Length", "8")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("redirect"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	routeGlobalHTTPClientToTestUpstream(t, upstream)

	recorder := performGitHubProxyRequest(router, http.MethodGet, "https://github.com/owner/repo/releases/download/v1/file.zip", nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/https://github.com/owner/repo/releases/download/v2/file.zip" {
		t.Fatalf("Location = %q, want rewritten GitHub URL", got)
	}
	for _, name := range []string{"Content-Length", "Content-Type", "Content-Encoding", "Content-Range", "Transfer-Encoding", "Trailer"} {
		if value := recorder.Header().Get(name); value != "" {
			t.Fatalf("%s = %q, want empty for bodyless redirect", name, value)
		}
	}
}

func TestDirectLinkRejectsMultipleByteRangesBeforeUpstreamRequest(t *testing.T) {
	upstreamCalled := make(chan struct{}, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled <- struct{}{}
		w.Header().Set("Content-Type", "multipart/byteranges; boundary=test")
		w.WriteHeader(http.StatusPartialContent)
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	headers := http.Header{"Range": {"bytes=0-1,4-5"}}

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/file.bin", headers)
	if recorder.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416; body=%q", recorder.Code, recorder.Body.String())
	}
	select {
	case <-upstreamCalled:
		t.Fatal("multi-range request reached the upstream")
	default:
	}
}

func TestDirectLinkDenialLogRedactsQuerySecrets(t *testing.T) {
	router := newGitHubProxyTestRouter(t, "[access]\ndirectLinkWhiteList = [\"downloads.example.com/public/*\"]\n")

	previousStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = previousStdout
		_ = reader.Close()
		_ = writer.Close()
	})

	recorder := performGitHubProxyRequest(
		router,
		http.MethodGet,
		"https://downloads.example.com/private/file.zip?X-Amz-Signature=secret-signature",
		nil,
	)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = previousStdout
	captured, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
	}
	logOutput := string(captured)
	if strings.Contains(logOutput, "X-Amz-Signature") || strings.Contains(logOutput, "secret-signature") || strings.Contains(logOutput, "?") {
		t.Fatalf("denial log leaked query data: %q", logOutput)
	}
	if !strings.Contains(logOutput, "downloads.example.com/private/file.zip") {
		t.Fatalf("denial log omitted safe target context: %q", logOutput)
	}
}

func TestExternalRedirectAppliesHTTPMethodAndBodySemantics(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			type receivedRequest struct {
				method string
				body   string
			}
			received := make(chan receivedRequest, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				if r.Host == "github.com" {
					if r.Method != http.MethodPost || string(body) != "payload" {
						t.Errorf("initial request = %s %q, want POST payload", r.Method, body)
					}
					w.Header().Set("Location", "https://cdn.example.com/asset.zip")
					w.WriteHeader(status)
					return
				}
				received <- receivedRequest{method: r.Method, body: string(body)}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write([]byte("asset"))
			}))
			defer upstream.Close()

			router := newGitHubProxyTestRouter(t, "")
			routeGlobalHTTPClientToTestUpstream(t, upstream)

			recorder := performGitHubProxyRequestWithBody(
				router,
				http.MethodPost,
				"https://github.com/owner/repo/git-upload-pack",
				"payload",
				nil,
			)
			if recorder.Code != http.StatusOK || recorder.Body.String() != "asset" {
				t.Fatalf("response = %d %q, want 200 asset", recorder.Code, recorder.Body.String())
			}
			got := <-received
			if got.method != http.MethodGet || got.body != "" {
				t.Fatalf("redirected request = %s %q, want GET with empty body", got.method, got.body)
			}
		})
	}

	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status)+" rejects consumed body", func(t *testing.T) {
			redirected := make(chan struct{}, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				if r.Host == "github.com" {
					w.Header().Set("Location", "https://cdn.example.com/asset.zip")
					w.WriteHeader(status)
					return
				}
				redirected <- struct{}{}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			router := newGitHubProxyTestRouter(t, "")
			routeGlobalHTTPClientToTestUpstream(t, upstream)

			recorder := performGitHubProxyRequestWithBody(
				router,
				http.MethodPost,
				"https://github.com/owner/repo/git-upload-pack",
				"payload",
				nil,
			)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502; body=%q", recorder.Code, recorder.Body.String())
			}
			select {
			case <-redirected:
				t.Fatal("307/308 request with a consumed body was replayed")
			default:
			}
		})
	}
}

func TestDirectLinkProxySelectionUsesOriginalHostBeforeIPPinning(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	transport := utils.GetGlobalHTTPClient().Transport.(*http.Transport)
	originalDial := transport.DialContext
	proxyHost := make(chan string, 1)
	dialTarget := make(chan string, 1)
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		proxyHost <- req.URL.Hostname()
		return nil, nil
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialTarget <- address
		return originalDial(ctx, network, address)
	}

	recorder := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/file.bin", nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "file" {
		t.Fatalf("response = %d %q, want 200 file", recorder.Code, recorder.Body.String())
	}
	select {
	case got := <-proxyHost:
		if got != "downloads.example.com" {
			t.Fatalf("proxy selector host = %q, want original hostname", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy selector was not called")
	}
	var pinnedTarget string
	select {
	case pinnedTarget = <-dialTarget:
	case <-time.After(2 * time.Second):
		t.Fatal("validated target was not dialed")
	}
	dialHost, _, err := net.SplitHostPort(pinnedTarget)
	if err != nil {
		t.Fatal(err)
	}
	if dialHost != "93.184.216.34" {
		t.Fatalf("dial host = %q, want validated pinned IP", dialHost)
	}
}

func TestDirectLinkIDNUsesASCIIForTLSVerification(t *testing.T) {
	serverName := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverName <- r.TLS.ServerName
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("file"))
	}))
	defer upstream.Close()

	previousLookup := lookupDirectLinkIPs
	lookupDirectLinkIPs = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "xn--bcher-kva.example.com" {
			t.Fatalf("lookup host = %q, want IDNA ASCII hostname", host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	t.Cleanup(func() { lookupDirectLinkIPs = previousLookup })

	_ = newGitHubProxyTestRouter(t, "")
	transport := upstream.Client().Transport.(*http.Transport).Clone()
	upstreamAddress := upstream.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstreamAddress)
	}
	utils.GetGlobalHTTPClient().Transport = transport

	parsedUpstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://" + net.JoinHostPort("bücher.example.com", parsedUpstreamURL.Port()) + "/files/app.zip"
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ProxyGitHubRequest(c, target)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "file" {
		t.Fatalf("response = %d %q, want 200 file", recorder.Code, recorder.Body.String())
	}
	select {
	case got := <-serverName:
		if got != "xn--bcher-kva.example.com" {
			t.Fatalf("TLS server name = %q, want xn--bcher-kva.example.com", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream TLS handshake was not observed")
	}
}

func TestDirectLinkStagingAllowsConcurrentSmallDownloads(t *testing.T) {
	quota := &directLinkSpoolQuota{}
	previousQuota := directLinkStagingQuota
	directLinkStagingQuota = quota
	t.Cleanup(func() { directLinkStagingQuota = previousQuota })

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{}, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Path == "/first.bin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("one"))
			w.(http.Flusher).Flush()
			close(firstStarted)
			<-releaseFirst
			_, _ = w.Write([]byte("first"))
			return
		}
		_, _ = w.Write([]byte("second"))
	}))
	defer upstream.Close()
	defer func() {
		select {
		case releaseFirst <- struct{}{}:
		default:
		}
	}()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 1024\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	secondResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResult <- performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/first.bin", nil)
	}()
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first direct-link request did not reach the upstream")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		quota.mu.Lock()
		used := quota.used
		quota.mu.Unlock()
		if used >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("first direct-link content was not staged; used=%d", used)
		}
		time.Sleep(5 * time.Millisecond)
	}

	go func() {
		secondResult <- performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/second.bin", nil)
	}()
	select {
	case recorder := <-secondResult:
		if recorder.Code != http.StatusOK || recorder.Body.String() != "second" {
			t.Fatalf("second response = %d %q, want 200 second", recorder.Code, recorder.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second direct-link request was blocked by the slow first upstream")
	}

	releaseFirst <- struct{}{}
	select {
	case recorder := <-firstResult:
		if recorder.Code != http.StatusOK || recorder.Body.String() != "onefirst" {
			t.Fatalf("first response = %d %q, want 200 onefirst", recorder.Code, recorder.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first direct-link request did not finish after release")
	}
}

func TestDirectLinkStagingFailsFastAtAggregateQuota(t *testing.T) {
	quota := &directLinkSpoolQuota{}
	previousQuota := directLinkStagingQuota
	directLinkStagingQuota = quota
	t.Cleanup(func() { directLinkStagingQuota = previousQuota })

	firstChunkSent := make(chan struct{})
	releaseFirst := make(chan struct{}, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Path == "/first.bin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("123456"))
			w.(http.Flusher).Flush()
			close(firstChunkSent)
			<-releaseFirst
			_, _ = w.Write([]byte("7"))
			return
		}
		_, _ = w.Write([]byte("7890"))
	}))
	defer upstream.Close()
	defer func() {
		select {
		case releaseFirst <- struct{}{}:
		default:
		}
	}()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 8\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResult <- performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/first.bin", nil)
	}()
	select {
	case <-firstChunkSent:
	case <-time.After(2 * time.Second):
		t.Fatal("first direct-link chunk was not sent")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		quota.mu.Lock()
		used := quota.used
		quota.mu.Unlock()
		if used >= 6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("first direct-link chunk was not reserved; used=%d", used)
		}
		time.Sleep(5 * time.Millisecond)
	}

	second := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/second.bin", nil)
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second response = %d %q, want 503 at aggregate quota", second.Code, second.Body.String())
	}
	releaseFirst <- struct{}{}
	select {
	case first := <-firstResult:
		if first.Code != http.StatusOK || first.Body.String() != "1234567" {
			t.Fatalf("first response = %d %q, want 200 1234567", first.Code, first.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first direct-link request did not finish after release")
	}
}

func TestDirectLinkStagingCancelsIdleUpstream(t *testing.T) {
	previousQuota := directLinkStagingQuota
	previousTimeout := directLinkBodyIdleTimeout
	directLinkStagingQuota = &directLinkSpoolQuota{}
	directLinkBodyIdleTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		directLinkStagingQuota = previousQuota
		directLinkBodyIdleTimeout = previousTimeout
	})

	upstreamCanceled := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Path == "/slow.bin" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(upstreamCanceled)
			return
		}
		_, _ = w.Write([]byte("fast"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 1024\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	slow := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/slow.bin", nil)
	if slow.Code != http.StatusGatewayTimeout {
		t.Fatalf("slow response = %d %q, want 504", slow.Code, slow.Body.String())
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("idle upstream request was not canceled")
	}

	fast := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/fast.bin", nil)
	if fast.Code != http.StatusOK || fast.Body.String() != "fast" {
		t.Fatalf("fast response after timeout = %d %q, want 200 fast", fast.Code, fast.Body.String())
	}
}

func TestDirectLinkRequestsHaveBoundedConcurrencyBeforeResponseHeaders(t *testing.T) {
	previousQuota := directLinkStagingQuota
	previousSlots := directLinkRequestSlots
	directLinkStagingQuota = &directLinkSpoolQuota{}
	directLinkRequestSlots = make(chan struct{}, 1)
	t.Cleanup(func() {
		directLinkStagingQuota = previousQuota
		directLinkRequestSlots = previousSlots
	})

	firstStarted := make(chan struct{})
	secondReachedUpstream := make(chan struct{}, 1)
	releaseFirst := make(chan struct{}, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Path == "/first.bin" {
			close(firstStarted)
			<-releaseFirst
			_, _ = w.Write([]byte("first"))
			return
		}
		secondReachedUpstream <- struct{}{}
		_, _ = w.Write([]byte("second"))
	}))
	defer upstream.Close()
	defer func() {
		select {
		case releaseFirst <- struct{}{}:
		default:
		}
	}()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 1024\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResult <- performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/first.bin", nil)
	}()
	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first direct-link request did not reach the upstream")
	}

	secondResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		secondResult <- performGitHubProxyRequest(router, http.MethodHead, upstreamURL+"/second.bin", nil)
	}()
	var second *httptest.ResponseRecorder
	secondDidNotFailFast := false
	select {
	case second = <-secondResult:
	case <-time.After(2 * time.Second):
		secondDidNotFailFast = true
		releaseFirst <- struct{}{}
		select {
		case second = <-secondResult:
		case <-time.After(2 * time.Second):
			t.Fatal("second direct-link request remained blocked after the first was released")
		}
	}
	secondReached := false
	select {
	case <-secondReachedUpstream:
		secondReached = true
	default:
	}
	if !secondDidNotFailFast {
		releaseFirst <- struct{}{}
	}
	var first *httptest.ResponseRecorder
	select {
	case first = <-firstResult:
	case <-time.After(2 * time.Second):
		t.Fatal("first direct-link request did not finish after release")
	}

	if secondDidNotFailFast {
		t.Fatal("second direct-link request did not fail fast while the request slot was full")
	}
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second HEAD response = %d %q, want 503 while first request awaits headers", second.Code, second.Body.String())
	}
	if secondReached {
		t.Fatal("second request reached the upstream while the direct-link request slot was full")
	}
	if first.Code != http.StatusOK || first.Body.String() != "first" {
		t.Fatalf("first response = %d %q, want 200 first", first.Code, first.Body.String())
	}
}

func TestDirectLinkRequestsHaveBoundedConcurrencyDuringStaging(t *testing.T) {
	previousQuota := directLinkStagingQuota
	previousSlots := directLinkRequestSlots
	directLinkStagingQuota = &directLinkSpoolQuota{}
	directLinkRequestSlots = make(chan struct{}, 2)
	t.Cleanup(func() {
		directLinkStagingQuota = previousQuota
		directLinkRequestSlots = previousSlots
	})

	started := make(chan struct{}, 2)
	releaseSlow := make(chan struct{}, 2)
	releaseAll := func() {
		for range 2 {
			select {
			case releaseSlow <- struct{}{}:
			default:
			}
		}
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if strings.HasPrefix(r.URL.Path, "/slow-") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			started <- struct{}{}
			<-releaseSlow
			_, _ = w.Write([]byte("done"))
			return
		}
		_, _ = w.Write([]byte("fast"))
	}))
	defer upstream.Close()
	defer releaseAll()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 1024\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	results := make(chan *httptest.ResponseRecorder, 2)
	for index := 1; index <= 2; index++ {
		path := fmt.Sprintf("/slow-%d.bin", index)
		go func() {
			results <- performGitHubProxyRequest(router, http.MethodGet, upstreamURL+path, nil)
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("slow direct-link request did not reach the upstream")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(directLinkRequestSlots) != cap(directLinkRequestSlots) {
		if time.Now().After(deadline) {
			t.Fatalf("request slots not filled: %d/%d", len(directLinkRequestSlots), cap(directLinkRequestSlots))
		}
		time.Sleep(5 * time.Millisecond)
	}

	full := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/fast-while-full.bin", nil)
	if full.Code != http.StatusServiceUnavailable {
		t.Fatalf("response at staging concurrency limit = %d %q, want 503", full.Code, full.Body.String())
	}
	releaseAll()
	for range 2 {
		select {
		case result := <-results:
			if result.Code != http.StatusOK || result.Body.String() != "xdone" {
				t.Fatalf("slow response = %d %q, want 200 xdone", result.Code, result.Body.String())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("slow direct-link request did not finish after release")
		}
	}

	fast := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/fast-after-release.bin", nil)
	if fast.Code != http.StatusOK || fast.Body.String() != "fast" {
		t.Fatalf("response after staging slots released = %d %q, want 200 fast", fast.Code, fast.Body.String())
	}
}

func TestDirectLinkRequestDeadlineStopsTrickleUpstream(t *testing.T) {
	previousQuota := directLinkStagingQuota
	previousSlots := directLinkRequestSlots
	previousIdleTimeout := directLinkBodyIdleTimeout
	previousRequestTimeout := directLinkRequestTimeout
	quota := &directLinkSpoolQuota{}
	slots := make(chan struct{}, 2)
	directLinkStagingQuota = quota
	directLinkRequestSlots = slots
	directLinkBodyIdleTimeout = time.Second
	directLinkRequestTimeout = 120 * time.Millisecond
	t.Cleanup(func() {
		directLinkStagingQuota = previousQuota
		directLinkRequestSlots = previousSlots
		directLinkBodyIdleTimeout = previousIdleTimeout
		directLinkRequestTimeout = previousRequestTimeout
	})

	upstreamCanceled := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.URL.Path != "/trickle.bin" {
			_, _ = w.Write([]byte("fast"))
			return
		}
		defer close(upstreamCanceled)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if _, err := w.Write([]byte("x")); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[server]\nfileSize = 1024\n")
	upstreamURL := configureDirectLinkTestUpstream(t, upstream, "downloads.example.com")
	trickle := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/trickle.bin", nil)
	if trickle.Code != http.StatusGatewayTimeout {
		t.Fatalf("trickle response = %d %q, want 504", trickle.Code, trickle.Body.String())
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("trickle upstream request was not canceled at the hard deadline")
	}
	if got := len(slots); got != 0 {
		t.Fatalf("staging slots still held after hard deadline: %d", got)
	}
	quota.mu.Lock()
	used := quota.used
	quota.mu.Unlock()
	if used != 0 {
		t.Fatalf("staging quota still reserved after hard deadline: %d", used)
	}

	fast := performGitHubProxyRequest(router, http.MethodGet, upstreamURL+"/fast.bin", nil)
	if fast.Code != http.StatusOK || fast.Body.String() != "fast" {
		t.Fatalf("response after trickle deadline = %d %q, want 200 fast", fast.Code, fast.Body.String())
	}
}
