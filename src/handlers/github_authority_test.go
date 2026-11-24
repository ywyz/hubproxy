package handlers

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hubproxy/utils"
)

func TestRepositoryAuthorityClassification(t *testing.T) {
	for _, tc := range []struct {
		url, owner, repo string
	}{
		{"https://GitHub.Com.:0443/Owner/Repo.git/info/refs", "Owner", "Repo.git"},
		{"github.com:443/Owner/Repo.git/info/refs", "Owner", "Repo.git"},
		{"https://HuggingFace.CO./Owner/Model/resolve/main/file.bin", "Owner", "Model/resolve/main/file.bin"},
	} {
		matches, direct := matchDownloadURL(tc.url, false)
		if direct || len(matches) < 2 || matches[0] != tc.owner || matches[1] != tc.repo {
			t.Errorf("matchDownloadURL(%q) = %q, direct=%t", tc.url, matches, direct)
		}
	}
	for _, u := range []string{
		"https://user@github.com/Owner/Repo.git/info/refs",
		"https://github.com../Owner/Repo.git/info/refs",
		"http://github.com:443/Owner/Repo.git/info/refs",
	} {
		if matches, direct := matchDownloadURL(u, false); matches != nil && !direct {
			t.Errorf("unexpected repository match for %q", u)
		}
	}
}

func TestNonDefaultGitHubPortRemainsGenericDirectLink(t *testing.T) {
	const rawURL = "https://GitHub.Com.:444/Owner/Repo.git/info/refs"
	matches, directLink := matchDownloadURL(rawURL, false)
	if !directLink {
		t.Fatalf("matchDownloadURL(%q) classified a non-default port as repository %#v", rawURL, matches)
	}
	if len(matches) < 2 || matches[0] != "github.com:444" {
		t.Fatalf("matchDownloadURL(%q) = %#v, want generic direct link for github.com:444", rawURL, matches)
	}

	router := newGitHubProxyTestRouter(t, "")
	recorder := performGitHubProxyRequestWithBody(
		router,
		http.MethodPost,
		"https://github.com:444/Owner/Repo.git/git-upload-pack",
		"payload",
		nil,
	)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("non-default port Git POST status = %d, want 405; body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestRepositoryCDNRedirectChainUsesPinnedAddressesWithoutSourceCredentials(t *testing.T) {
	const start = "https://github.com/owner/repo/releases/download/v1/artifact"
	const known = "https://github.com/owner/repo/releases/download/v1/raw"
	const cdn = "https://assets.example.org/storage%2Fkey?signature=fixture"
	const raw = "https://raw.githubusercontent.com/owner/repo/main/file"
	const back = "https://github.com/owner/repo/blob/main/file"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := "https://" + r.Host + r.URL.RequestURI()
		if url != start && url != known && (r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "") {
			t.Errorf("source credentials reached redirected path %s", r.URL.Path)
		}
		switch url {
		case start:
			if r.Header.Get("Authorization") == "" {
				t.Error("initial credentials missing")
			}
			http.Redirect(w, r, cdn, http.StatusFound)
		case cdn, known:
			http.Redirect(w, r, raw, http.StatusFound)
		case raw:
			http.Redirect(w, r, back, http.StatusFound)
		case "https://github.com/owner/repo/raw/main/file":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("artifact"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList=['owner/repo']\ndirectLinkWhiteList=[]")
	routeGlobalHTTPClientToTestUpstream(t, upstream, "assets.example.org", "raw.githubusercontent.com", "github.com")
	transport := utils.GetGlobalHTTPClient().Transport.(*http.Transport)
	dial := transport.DialContext
	dials := make(chan string, 10)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials <- address
		return dial(ctx, network, address)
	}
	headers := http.Header{"Authorization": {"Bearer fixture"}, "Cookie": {"upstream=fixture"}}
	r := performGitHubProxyRequest(router, http.MethodGet, start, headers)
	if r.Code != http.StatusOK || r.Body.String() != "artifact" {
		t.Fatalf("redirect chain returned %d %q", r.Code, r.Body.String())
	}
	for _, want := range []string{"github.com:443", "93.184.216.34:443", "93.184.216.34:443", "93.184.216.34:443"} {
		select {
		case got := <-dials:
			if got != want {
				t.Fatalf("dialed %q, want %q", got, want)
			}
		default:
			t.Fatalf("missing dial to %q", want)
		}
	}
	r = performGitHubProxyRequest(router, http.MethodGet, known, headers)
	if r.Code != http.StatusOK || r.Body.String() != "artifact" {
		t.Fatalf("cross-repository redirect returned %d %q", r.Code, r.Body.String())
	}
}

func TestCrossOriginRepositoryRedirectChecksTargetAccess(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "github.com" {
			t.Error("disallowed repository reached upstream")
		}
		http.Redirect(w, r, "https://raw.githubusercontent.com/other/private/main/file", http.StatusFound)
	}))
	defer upstream.Close()
	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList=['owner/repo']")
	routeGlobalHTTPClientToTestUpstream(t, upstream, "raw.githubusercontent.com")
	r := performGitHubProxyRequest(router, http.MethodGet, "https://github.com/owner/repo/releases/download/v1/file", nil)
	if r.Code != http.StatusForbidden {
		t.Fatalf("denied repository redirect returned %d", r.Code)
	}
}

func TestCDNRedirectRequiresResolvablePublicDestination(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "github.com" {
			t.Error("unresolved CDN destination reached the transport")
			return
		}
		http.Redirect(w, r, "https://unresolved.example.org/asset", http.StatusFound)
	}))
	defer upstream.Close()
	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList=['owner/repo']")
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	r := performGitHubProxyRequest(router, http.MethodGet, "https://github.com/owner/repo/releases/download/v1/file", nil)
	if r.Code != http.StatusForbidden {
		t.Fatalf("unresolved CDN redirect returned %d", r.Code)
	}
}

func TestEquivalentGitHubAuthorityRoutesGitAndBlobThroughCanonicalOrigin(t *testing.T) {
	type observedRequest struct {
		method        string
		host          string
		path          string
		authorization string
	}
	requests := make(chan observedRequest, 8)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- observedRequest{
			method:        r.Method,
			host:          r.Host,
			path:          r.URL.Path,
			authorization: r.Header.Get("Authorization"),
		}
		if r.URL.Path == "/owner/repo/releases/download/v1/start.bin" {
			w.Header().Set("Location", "https://GitHub.Com.:443/owner/repo/blob/main/data.bin")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/owner/repo/releases/download/v1/private.bin" {
			http.Redirect(w, r, "https://github.com.:443/storage/object", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("payload"))
	}))
	defer upstream.Close()

	router := newGitHubProxyTestRouter(t, "[access]\nwhiteList = [\"owner/repo\"]\ndirectLinkWhiteList = []\n")
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	headers := http.Header{
		"Authorization": {"Bearer dummy-download-token"},
		"Cookie":        {"session=dummy-download-session"},
	}

	assertUpstreamRequest := func(wantMethod, wantPath string) {
		t.Helper()
		got := <-requests
		if got.method != wantMethod || got.path != wantPath {
			t.Fatalf("upstream request = %s %s, want %s %s", got.method, got.path, wantMethod, wantPath)
		}
		if got.host != "github.com" {
			t.Fatalf("upstream Host = %q, want canonical github.com", got.host)
		}
		if got.authorization != "Bearer dummy-download-token" {
			t.Fatalf("upstream Authorization = %q, want dummy repository credentials", got.authorization)
		}
	}

	git := performGitHubProxyRequestWithBody(
		router,
		http.MethodPost,
		"https://GitHub.Com.:443/owner/repo.git/git-upload-pack",
		"payload",
		headers,
	)
	if git.Code != http.StatusOK || git.Body.String() != "payload" {
		t.Fatalf("Git POST response = %d %q, want 200 payload", git.Code, git.Body.String())
	}
	assertUpstreamRequest(http.MethodPost, "/owner/repo.git/git-upload-pack")

	blob := performGitHubProxyRequest(
		router,
		http.MethodGet,
		"https://GitHub.Com.:443/owner/repo/blob/main/data.bin",
		headers,
	)
	if blob.Code != http.StatusOK || blob.Body.String() != "payload" {
		t.Fatalf("blob response = %d %q, want 200 payload", blob.Code, blob.Body.String())
	}
	assertUpstreamRequest(http.MethodGet, "/owner/repo/raw/main/data.bin")

	// An object URL outside the repository patterns is followed internally.
	// Source credentials remain valid on the equivalent HTTPS authority.
	private := performGitHubProxyRequest(router, http.MethodGet,
		"https://github.com/owner/repo/releases/download/v1/private.bin", headers)
	if private.Code != http.StatusOK {
		t.Fatalf("private object response = %d %q", private.Code, private.Body.String())
	}
	assertUpstreamRequest(http.MethodGet, "/owner/repo/releases/download/v1/private.bin")
	if object := <-requests; object.path != "/storage/object" || object.authorization != headers.Get("Authorization") {
		t.Fatalf("private object upstream request = %+v", object)
	}

	redirect := performGitHubProxyRequest(
		router,
		http.MethodGet,
		"https://github.com/owner/repo/releases/download/v1/start.bin",
		headers,
	)
	if redirect.Code != http.StatusFound {
		t.Fatalf("redirect response = %d, want 302; body=%q", redirect.Code, redirect.Body.String())
	}
	location := redirect.Header().Get("Location")
	if location == "" {
		t.Fatal("rewritten redirect Location is empty")
	}
	assertUpstreamRequest(http.MethodGet, "/owner/repo/releases/download/v1/start.bin")

	followed := performGitHubProxyRequest(
		router,
		http.MethodGet,
		strings.TrimPrefix(location, "/"),
		headers,
	)
	if followed.Code != http.StatusOK || followed.Body.String() != "payload" {
		t.Fatalf("followed redirect response = %d %q, want 200 payload", followed.Code, followed.Body.String())
	}
	assertUpstreamRequest(http.MethodGet, "/owner/repo/raw/main/data.bin")
}
