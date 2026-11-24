package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"hubproxy/config"
	"hubproxy/utils"
)

const (
	downloadTestUser = "downloader"
	downloadTestPass = "secret-pass"
)

type downloadAuthTestRouter struct {
	router    *gin.Engine
	forwarded http.Header
}

func newDownloadAuthTestRouter(t *testing.T, username, password string) *downloadAuthTestRouter {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	utils.ConfigureTrustedProxies(router)
	RegisterDownloadAuth(router, config.DownloadAuthConfig{Username: username, Password: password})
	tr := &downloadAuthTestRouter{router: router}
	router.GET("/download", func(c *gin.Context) {
		tr.forwarded = c.Request.Header.Clone()
		c.String(http.StatusOK, "ok")
	})
	router.GET("/auth", func(c *gin.Context) {
		if DownloadAuthenticated(c) {
			c.String(http.StatusOK, "authenticated")
			return
		}
		c.String(http.StatusUnauthorized, "anonymous")
	})
	router.GET("/sized", func(c *gin.Context) {
		if !DownloadAuthenticated(c) && c.Request.ContentLength > anonymousDownloadLimit() {
			if handleDownloadStageError(c, errDownloadLoginRequired) {
				return
			}
		}
		c.String(http.StatusOK, "ok")
	})
	return tr
}

func (tr *downloadAuthTestRouter) serve(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	tr.router.ServeHTTP(w, req)
	return w
}

func expectDownloadStatus(t *testing.T, w *httptest.ResponseRecorder, want int) *httptest.ResponseRecorder {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d: %s", w.Code, want, w.Body.String())
	}
	return w
}

func newDownloadLoginRequest(username, password string) *http.Request {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "http://hub.local/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://hub.local")
	return req
}

func newDownloadLogoutRequest(session *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://hub.local/logout", nil)
	req.Header.Set("Origin", "http://hub.local")
	if session != nil {
		req.AddCookie(session)
	}
	return req
}

func basicAuthHeader(username, password string) string {
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(username, password)
	return req.Header.Get("Authorization")
}

func downloadSessionFromResponse(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == downloadSessionCookieName {
			return cookie
		}
	}
	t.Fatalf("session cookie missing: %v", w.Header().Values("Set-Cookie"))
	return nil
}

func loginDownloadTestUser(t *testing.T, tr *downloadAuthTestRouter) *http.Cookie {
	t.Helper()
	w := expectDownloadStatus(t, tr.serve(newDownloadLoginRequest(downloadTestUser, downloadTestPass)),
		http.StatusSeeOther)
	return downloadSessionFromResponse(t, w)
}

func overrideDownloadAuthClock(t *testing.T, start time.Time) *time.Time {
	t.Helper()
	previous := downloadAuthNow
	clock := &start
	downloadAuthNow = func() time.Time { return *clock }
	t.Cleanup(func() { downloadAuthNow = previous })
	return clock
}

func TestDownloadAuthPublicRoutesAndDisabledState(t *testing.T) {
	tr := newDownloadAuthTestRouter(t, downloadTestUser, downloadTestPass)
	w := expectDownloadStatus(t, tr.serve(httptest.NewRequest(http.MethodGet, "http://hub.local/download", nil)),
		http.StatusOK)
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("anonymous public route challenged: %q", w.Header().Get("WWW-Authenticate"))
	}
	expectDownloadStatus(t, tr.serve(httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)),
		http.StatusUnauthorized)
	page := expectDownloadStatus(t, tr.serve(httptest.NewRequest(http.MethodGet, "http://hub.local/login", nil)),
		http.StatusOK)
	if !strings.Contains(page.Body.String(), `type="password"`) {
		t.Fatal("login page has no password form")
	}

	lowercase := httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)
	lowercase.Header.Set("Authorization",
		"basic "+strings.TrimPrefix(basicAuthHeader(downloadTestUser, downloadTestPass), "Basic "))
	expectDownloadStatus(t, tr.serve(lowercase), http.StatusOK)

	disabled := newDownloadAuthTestRouter(t, "", "")
	upstream := basicAuthHeader("gh-user", "gh-token")
	req := httptest.NewRequest(http.MethodGet, "http://hub.local/download", nil)
	req.Header.Set("Authorization", upstream)
	req.Header["Cookie"] = []string{
		downloadSessionCookieName + " = stale; github_session=abc",
		"theme=dark",
	}
	expectDownloadStatus(t, disabled.serve(req), http.StatusOK)
	if got := disabled.forwarded.Values("Authorization"); len(got) != 1 || got[0] != upstream {
		t.Fatalf("upstream Authorization = %v", got)
	}
	cookies := disabled.forwarded.Values("Cookie")
	if len(cookies) != 2 || cookies[0] != "github_session=abc" || cookies[1] != "theme=dark" {
		t.Fatalf("forwarded cookies = %v", cookies)
	}
	expectDownloadStatus(t, disabled.serve(httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)),
		http.StatusUnauthorized)
	large := httptest.NewRequest(http.MethodGet, "http://hub.local/sized", nil)
	large.ContentLength = anonymousDownloadLimit() + 1
	w = expectDownloadStatus(t, disabled.serve(large), http.StatusUnauthorized)
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("disabled size gate did not challenge")
	}
	page = expectDownloadStatus(t, disabled.serve(httptest.NewRequest(http.MethodGet, "http://hub.local/login", nil)),
		http.StatusOK)
	if !strings.Contains(page.Body.String(), "未启用") || strings.Contains(page.Body.String(), `type="password"`) {
		t.Fatalf("disabled login page = %q", page.Body.String())
	}
}

func TestDownloadAuthDefaultsAndAttemptCapacity(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if DownloadAuthenticated(c) {
		t.Fatal("DownloadAuthenticated must default to false without middleware")
	}

	state := newDownloadAuthState(config.DownloadAuthConfig{
		Username: downloadTestUser,
		Password: downloadTestPass,
	})
	now := time.Now()
	for i := range maxTrackedLoginIPs {
		state.attempts[strconv.Itoa(i)] = &loginAttempt{started: now, failures: downloadLoginMaxFailures}
	}
	if valid, limited := state.checkCredentials("new-client", downloadTestUser, downloadTestPass); valid || !limited {
		t.Fatal("a full attempt table must refuse new logins")
	}
	state.attempts["0"].started = now.Add(-downloadLoginWindow)
	state.nextSweep = time.Time{}
	if valid, limited := state.checkCredentials("new-client", downloadTestUser, downloadTestPass); !valid || limited {
		t.Fatal("an expired lockout should free a slot for a new client")
	}
}

func TestDownloadAuthSizeGateContract(t *testing.T) {
	tr := newDownloadAuthTestRouter(t, downloadTestUser, downloadTestPass)

	small := httptest.NewRequest(http.MethodGet, "http://hub.local/sized", nil)
	small.ContentLength = anonymousDownloadLimit()
	expectDownloadStatus(t, tr.serve(small), http.StatusOK)

	large := httptest.NewRequest(http.MethodGet, "http://hub.local/sized", nil)
	large.ContentLength = anonymousDownloadLimit() + 1
	w := expectDownloadStatus(t, tr.serve(large), http.StatusUnauthorized)
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "Basic") ||
		!strings.Contains(w.Body.String(), "/login") {
		t.Fatal("large anonymous download did not receive a login challenge")
	}

	basic := httptest.NewRequest(http.MethodGet, "http://hub.local/sized", nil)
	basic.ContentLength = anonymousDownloadLimit() + 1
	basic.Header.Set("Authorization", basicAuthHeader(downloadTestUser, downloadTestPass))
	expectDownloadStatus(t, tr.serve(basic), http.StatusOK)

	session := loginDownloadTestUser(t, tr)
	sessionLarge := httptest.NewRequest(http.MethodGet, "http://hub.local/sized", nil)
	sessionLarge.ContentLength = anonymousDownloadLimit() + 1
	sessionLarge.AddCookie(session)
	expectDownloadStatus(t, tr.serve(sessionLarge), http.StatusOK)
}

func TestDownloadLoginLogoutAndExpiry(t *testing.T) {
	tr := newDownloadAuthTestRouter(t, downloadTestUser, downloadTestPass)
	clock := overrideDownloadAuthClock(t, time.Now())

	w := expectDownloadStatus(t, tr.serve(newDownloadLoginRequest(downloadTestUser, downloadTestPass)),
		http.StatusSeeOther)
	if w.Header().Get("Location") != "/login" {
		t.Fatalf("login redirect = %q", w.Header().Get("Location"))
	}
	session := downloadSessionFromResponse(t, w)
	if !strings.HasPrefix(session.Name, "__Host-") || len(session.Value) < 16 ||
		!session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" {
		t.Fatalf("session cookie flags = %+v", session)
	}

	loggedIn := httptest.NewRequest(http.MethodGet, "http://hub.local/login", nil)
	loggedIn.AddCookie(session)
	page := expectDownloadStatus(t, tr.serve(loggedIn), http.StatusOK)
	if !strings.Contains(page.Body.String(), "已登录") ||
		!strings.Contains(page.Body.String(), `action="/logout"`) ||
		page.Header().Get("Cache-Control") != "no-store" ||
		page.Header().Get("Referrer-Policy") != "no-referrer" ||
		page.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("logged-in page headers = %v", page.Header())
	}
	authed := httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)
	authed.AddCookie(session)
	expectDownloadStatus(t, tr.serve(authed), http.StatusOK)

	w = expectDownloadStatus(t, tr.serve(newDownloadLogoutRequest(session)), http.StatusSeeOther)
	cleared := false
	for _, line := range w.Header().Values("Set-Cookie") {
		if strings.Contains(line, downloadSessionCookieName+"=;") && strings.Contains(line, "Max-Age=0") {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("logout did not clear cookie: %v", w.Header().Values("Set-Cookie"))
	}
	replay := httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)
	replay.AddCookie(session)
	expectDownloadStatus(t, tr.serve(replay), http.StatusUnauthorized)

	expiring := loginDownloadTestUser(t, tr)
	*clock = clock.Add(downloadSessionTTL + time.Minute)
	expired := httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)
	expired.AddCookie(expiring)
	expectDownloadStatus(t, tr.serve(expired), http.StatusUnauthorized)
}

func TestDownloadLoginValidationAndCrossOriginProtection(t *testing.T) {
	tr := newDownloadAuthTestRouter(t, downloadTestUser, downloadTestPass)

	wrong := expectDownloadStatus(t, tr.serve(newDownloadLoginRequest(downloadTestUser, "wrong-pass")),
		http.StatusUnauthorized)
	if len(wrong.Result().Cookies()) != 0 || !strings.Contains(wrong.Body.String(), "错误") {
		t.Fatal("failed login returned a cookie or no error message")
	}
	cross := newDownloadLoginRequest(downloadTestUser, downloadTestPass)
	cross.Header.Set("Origin", "http://evil.example")
	expectDownloadStatus(t, tr.serve(cross), http.StatusForbidden)
	site := newDownloadLoginRequest(downloadTestUser, downloadTestPass)
	site.Header.Set("Sec-Fetch-Site", "cross-site")
	expectDownloadStatus(t, tr.serve(site), http.StatusForbidden)

	// TLS terminates at a reverse proxy: Origin scheme differs, but Host matches.
	tlsProxy := newDownloadLoginRequest(downloadTestUser, downloadTestPass)
	tlsProxy.Header.Set("Origin", "https://hub.local")
	expectDownloadStatus(t, tr.serve(tlsProxy), http.StatusSeeOther)
	noOrigin := newDownloadLoginRequest(downloadTestUser, downloadTestPass)
	noOrigin.Header.Del("Origin")
	expectDownloadStatus(t, tr.serve(noOrigin), http.StatusSeeOther)

	big := httptest.NewRequest(http.MethodPost, "http://hub.local/login",
		strings.NewReader("junk="+strings.Repeat("a", 8192)))
	big.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	big.Header.Set("Origin", "http://hub.local")
	expectDownloadStatus(t, tr.serve(big), http.StatusBadRequest)
}

func TestDownloadBasicRateLimitBlocksValidBasicAfterFailures(t *testing.T) {
	tr := newDownloadAuthTestRouter(t, downloadTestUser, downloadTestPass)
	clock := overrideDownloadAuthClock(t, time.Now())
	basicRequest := func(ip, password string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)
		req.RemoteAddr = ip + ":1000"
		req.Header.Set("Authorization", basicAuthHeader(downloadTestUser, password))
		return req
	}

	for i := 0; i < downloadLoginMaxFailures; i++ {
		expectDownloadStatus(t, tr.serve(basicRequest("192.0.2.12", "wrong-pass")), http.StatusUnauthorized)
	}
	blocked := expectDownloadStatus(t, tr.serve(basicRequest("192.0.2.12", downloadTestPass)),
		http.StatusTooManyRequests)
	if blocked.Header().Get("Retry-After") == "" {
		t.Fatal("blocked Basic response lacks Retry-After")
	}

	public := httptest.NewRequest(http.MethodGet, "http://hub.local/download", nil)
	public.RemoteAddr = "192.0.2.12:1000"
	expectDownloadStatus(t, tr.serve(public), http.StatusOK)

	sessionReq := newDownloadLoginRequest(downloadTestUser, downloadTestPass)
	sessionReq.RemoteAddr = "192.0.2.99:1000"
	session := downloadSessionFromResponse(t, tr.serve(sessionReq))
	existing := httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)
	existing.RemoteAddr = "192.0.2.12:1000"
	existing.AddCookie(session)
	expectDownloadStatus(t, tr.serve(existing), http.StatusOK)
	expectDownloadStatus(t, tr.serve(basicRequest("192.0.2.13", downloadTestPass)), http.StatusOK)

	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if w := tr.serve(basicRequest("192.0.2.20", downloadTestPass)); w.Code != http.StatusOK {
				t.Errorf("parallel Basic status = %d", w.Code)
			}
		}()
	}
	group.Wait()

	*clock = clock.Add(downloadLoginWindow + time.Minute)
	expectDownloadStatus(t, tr.serve(basicRequest("192.0.2.12", downloadTestPass)), http.StatusOK)
}

func TestDownloadCredentialScrubbing(t *testing.T) {
	tr := newDownloadAuthTestRouter(t, downloadTestUser, downloadTestPass)
	session := loginDownloadTestUser(t, tr)
	withSession := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://hub.local/download", nil)
		req.AddCookie(session)
		return req
	}

	req := withSession()
	req.Header.Set("Proxy-Authorization", basicAuthHeader(downloadTestUser, downloadTestPass))
	req.Header["Cookie"] = []string{
		downloadSessionCookieName + " = " + session.Value + "; upstream_sid=s1",
		"github_session=abc",
	}
	expectDownloadStatus(t, tr.serve(req), http.StatusOK)
	if tr.forwarded.Get("Proxy-Authorization") != "" {
		t.Fatal("proxy credentials were forwarded to the origin")
	}
	cookies := tr.forwarded.Values("Cookie")
	if len(cookies) != 2 || cookies[0] != "upstream_sid=s1" || cookies[1] != "github_session=abc" ||
		strings.Contains(strings.Join(cookies, ";"), session.Value) {
		t.Fatalf("forwarded cookies = %v", cookies)
	}

	for _, password := range []string{downloadTestPass, "wrong-pass"} {
		req = withSession()
		req.Header.Set("Authorization", basicAuthHeader(downloadTestUser, password))
		expectDownloadStatus(t, tr.serve(req), http.StatusOK)
		if got := tr.forwarded.Values("Authorization"); len(got) != 0 {
			t.Fatalf("local Basic forwarded upstream: %v", got)
		}
	}
	for _, credential := range []string{basicAuthHeader("gh-user", "gh-token"), "Bearer upstream-token"} {
		req = withSession()
		req.Header.Set("Authorization", credential)
		expectDownloadStatus(t, tr.serve(req), http.StatusOK)
		if got := tr.forwarded.Values("Authorization"); len(got) != 1 || got[0] != credential {
			t.Fatalf("upstream credential = %v", got)
		}
	}

	req = withSession()
	req.Header["Authorization"] = []string{
		basicAuthHeader(downloadTestUser, "wrong-pass"),
		"Bearer upstream-token",
	}
	expectDownloadStatus(t, tr.serve(req), http.StatusOK)
	if got := tr.forwarded.Values("Authorization"); len(got) != 0 {
		t.Fatalf("ambiguous Authorization forwarded: %v", got)
	}

	req = withSession()
	req.Header.Set("Authorization", basicAuthHeader(downloadTestUser, "wrong-pass")+", Bearer upstream-token")
	expectDownloadStatus(t, tr.serve(req), http.StatusOK)
	if got := tr.forwarded.Values("Authorization"); len(got) != 0 {
		t.Fatalf("combined Authorization forwarded: %v", got)
	}

	anonymous := httptest.NewRequest(http.MethodGet, "http://hub.local/auth", nil)
	anonymous.Header.Set("Authorization",
		basicAuthHeader(downloadTestUser, downloadTestPass)+", Bearer upstream-token")
	expectDownloadStatus(t, tr.serve(anonymous), http.StatusUnauthorized)
}
