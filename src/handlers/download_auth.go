package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"hubproxy/config"
)

const (
	// __Host- 前缀要求浏览器强制 Secure、Path=/ 且禁止 Domain 属性。
	downloadSessionCookieName = "__Host-hubproxy_download"
	downloadAuthContextKey    = "downloadAuthenticated"
	downloadTokenContextKey   = "downloadSessionToken"
	downloadSessionTTL        = 24 * time.Hour
	maxDownloadSessions       = 1024
	maxLoginFormBytes         = 4 << 10
	downloadLoginMaxFailures  = 5
	downloadLoginWindow       = 15 * time.Minute
	maxTrackedLoginIPs        = 4096
)

// downloadAuthNow 可在测试中替换的时钟。
var downloadAuthNow = time.Now

// downloadAuthState 保存会话和失败计数；两者均由单个互斥锁保护。
type downloadAuthState struct {
	username string
	password string

	mu        sync.Mutex
	sessions  map[string]time.Time
	attempts  map[string]*loginAttempt
	nextSweep time.Time
}

type loginAttempt struct {
	failures int
	started  time.Time
}

func newDownloadAuthState(authCfg config.DownloadAuthConfig) *downloadAuthState {
	return &downloadAuthState{
		username: authCfg.Username,
		password: authCfg.Password,
		sessions: make(map[string]time.Time),
		attempts: make(map[string]*loginAttempt),
	}
}

func (s *downloadAuthState) disabled() bool {
	return s.username == "" || s.password == ""
}

// RegisterDownloadAuth 安装下载登录中间件与登录/登出路由。
// 中间件只识别身份并清洗本地凭据，不质询请求；大文件由下载处理器调用
// RequireDownloadLogin 质询，小文件和标准路由保持匿名可用。
func RegisterDownloadAuth(router *gin.Engine, authCfg config.DownloadAuthConfig) {
	state := newDownloadAuthState(authCfg)
	crossOrigin := http.NewCrossOriginProtection()
	router.Use(state.middleware)
	router.GET("/login", state.loginPage)
	router.POST("/login", crossOriginOnly(crossOrigin), state.loginSubmit)
	router.POST("/logout", crossOriginOnly(crossOrigin), state.logout)
}

func crossOriginOnly(protection *http.CrossOriginProtection) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := protection.Check(c.Request); err != nil {
			c.Header("Cache-Control", "no-store")
			c.String(http.StatusForbidden, "跨站请求被拒绝")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *downloadAuthState) middleware(c *gin.Context) {
	authenticated := false
	blocked := false
	if !s.disabled() {
		if token, ok := downloadCookieValue(c.Request, downloadSessionCookieName); ok && s.validSession(token) {
			authenticated = true
		} else {
			authenticated, blocked = s.validBasicAuth(c)
		}
	}
	c.Set(downloadAuthContextKey, authenticated)
	if c.Request.URL.Path == "/logout" {
		if token, ok := downloadCookieValue(c.Request, downloadSessionCookieName); ok {
			c.Set(downloadTokenContextKey, token)
		}
	}
	s.scrubLocalCredentials(c)
	if blocked {
		s.writeLoginRateLimited(c)
		c.Abort()
		return
	}
	c.Next()
}

// validBasicAuth 先检查 IP 是否被限流，再校验本地保留用户名的密码。
// 其他用户名属于上游凭据，不参与本地登录也不计入失败次数。
func (s *downloadAuthState) validBasicAuth(c *gin.Context) (authenticated, blocked bool) {
	values := c.Request.Header.Values("Authorization")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return false, false
	}
	username, password, ok := basicAuthValue(values[0])
	if !ok || !digestEqual(username, s.username) {
		return false, false
	}
	return s.checkCredentials(c.ClientIP(), username, password)
}

func (s *downloadAuthState) scrubLocalCredentials(c *gin.Context) {
	// Proxy credentials belong to the current hop. The outbound transport
	// configures its own proxy authentication when required.
	c.Request.Header.Del("Proxy-Authorization")
	scrubCookieHeaders(c.Request.Header, downloadSessionCookieName)
	if s.username == "" {
		return
	}
	if s.hasLocalAuthorization(c.Request) {
		c.Request.Header.Del("Authorization")
	}
}

// scrubCookieHeaders 按名称移除本地 Cookie，同时保留每一行 Cookie 中的其他项。
func scrubCookieHeaders(header http.Header, name string) {
	lines := header.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if filtered := withoutCookie(line, name); filtered != "" {
			kept = append(kept, filtered)
		}
	}
	header.Del("Cookie")
	for _, line := range kept {
		header.Add("Cookie", line)
	}
}

// withoutCookie 容忍名称和值周围的空白，但只删除目标 Cookie。
func withoutCookie(line, drop string) string {
	parts := strings.Split(line, ";")
	kept := parts[:0]
	for _, part := range parts {
		pair := strings.TrimSpace(part)
		if pair == "" {
			continue
		}
		name, _, _ := strings.Cut(pair, "=")
		if strings.TrimSpace(name) == drop {
			continue
		}
		kept = append(kept, pair)
	}
	return strings.Join(kept, "; ")
}

// hasLocalAuthorization 检测单个头或多个合并值中是否包含本地 Basic 凭据。
// 一旦命中，整个 Authorization 头都不会转发上游。
func (s *downloadAuthState) hasLocalAuthorization(r *http.Request) bool {
	for _, header := range r.Header.Values("Authorization") {
		for _, value := range strings.Split(header, ",") {
			if username, _, ok := basicAuthValue(value); ok && digestEqual(username, s.username) {
				return true
			}
		}
	}
	return false
}

// Basic credentials use token68 following one or more spaces.
func basicAuthValue(value string) (username, password string, ok bool) {
	fields := strings.Fields(value)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(decoded), ":")
}

// downloadCookieValue 优先使用标准解析，并兼容名称/值周围的空白。
func downloadCookieValue(r *http.Request, name string) (string, bool) {
	if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
		return cookie.Value, true
	}
	for _, line := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			cookieName, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && strings.TrimSpace(cookieName) == name {
				if value = strings.TrimSpace(value); value != "" {
					return value, true
				}
			}
		}
	}
	return "", false
}

// digestEqual 基于摘要的常数时间比较，避免长度与内容泄漏。
func digestEqual(a, b string) bool {
	sumA := sha256.Sum256([]byte(a))
	sumB := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(sumA[:], sumB[:]) == 1
}

func (s *downloadAuthState) validSession(token string) bool {
	if token == "" {
		return false
	}
	now := downloadAuthNow()
	s.mu.Lock()
	defer s.mu.Unlock()
	expiresAt, ok := s.sessions[token]
	if !ok {
		return false
	}
	if !now.Before(expiresAt) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *downloadAuthState) createSession() string {
	token := rand.Text()
	now := downloadAuthNow()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expiresAt := range s.sessions {
		if !now.Before(expiresAt) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= maxDownloadSessions {
		var oldestKey string
		var oldest time.Time
		for key, expiresAt := range s.sessions {
			if oldestKey == "" || expiresAt.Before(oldest) {
				oldestKey, oldest = key, expiresAt
			}
		}
		delete(s.sessions, oldestKey)
	}
	s.sessions[token] = now.Add(downloadSessionTTL)
	return token
}

func (s *downloadAuthState) revokeSession(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// Verification and failure accounting share a lock so concurrent guesses from
// one IP cannot all enter between a separate limit check and counter update.
func (s *downloadAuthState) checkCredentials(ip, username, password string) (valid, limited bool) {
	now := downloadAuthNow()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !now.Before(s.nextSweep) {
		for key, entry := range s.attempts {
			if !now.Before(entry.started.Add(downloadLoginWindow)) {
				delete(s.attempts, key)
			}
		}
		s.nextSweep = now.Add(time.Minute)
	}
	entry := s.attempts[ip]
	if entry != nil && !now.Before(entry.started.Add(downloadLoginWindow)) {
		delete(s.attempts, ip)
		entry = nil
	}
	if (entry == nil && len(s.attempts) >= maxTrackedLoginIPs) ||
		(entry != nil && entry.failures >= downloadLoginMaxFailures) {
		return false, true
	}
	userOK := digestEqual(username, s.username)
	passwordOK := digestEqual(password, s.password)
	if userOK && passwordOK {
		delete(s.attempts, ip)
		return true, false
	}
	if entry == nil {
		entry = &loginAttempt{started: now}
		s.attempts[ip] = entry
	}
	entry.failures++
	return false, false
}

// DownloadAuthenticated 返回本次请求是否通过本地下载认证。
// 未运行认证中间件的请求一律视为未认证。
func DownloadAuthenticated(c *gin.Context) bool {
	return c.GetBool(downloadAuthContextKey)
}

// RequireDownloadLogin 返回 401 Basic 质询并提示 /login 入口。
func RequireDownloadLogin(c *gin.Context) {
	c.Header("WWW-Authenticate", `Basic realm="hubproxy-downloads", charset="UTF-8"`)
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.String(http.StatusUnauthorized,
		"需要下载登录认证：请在浏览器中打开 /login 完成登录，或在下载工具中使用下载账号的 HTTP Basic 认证。")
}

func newDownloadSessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     downloadSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (s *downloadAuthState) loginPage(c *gin.Context) {
	s.writeLoginPage(c, http.StatusOK, "")
}

func (s *downloadAuthState) loginSubmit(c *gin.Context) {
	if s.disabled() {
		s.writeLoginPage(c, http.StatusOK, "")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxLoginFormBytes)
	if err := c.Request.ParseForm(); err != nil {
		s.writeLoginPage(c, http.StatusBadRequest, "登录表单无效。")
		return
	}
	username := c.Request.PostForm.Get("username")
	password := c.Request.PostForm.Get("password")
	valid, limited := s.checkCredentials(c.ClientIP(), username, password)
	if limited {
		s.writeLoginRateLimited(c)
		return
	}
	if !valid {
		s.writeLoginPage(c, http.StatusUnauthorized, "用户名或密码错误。")
		return
	}
	token := s.createSession()
	c.Header("Cache-Control", "no-store")
	http.SetCookie(c.Writer, newDownloadSessionCookie(token, int(downloadSessionTTL/time.Second)))
	c.Redirect(http.StatusSeeOther, "/login")
}

func (s *downloadAuthState) logout(c *gin.Context) {
	// 中间件在清洗 Cookie 前把待撤销令牌放入上下文。
	s.revokeSession(c.GetString(downloadTokenContextKey))
	c.Header("Cache-Control", "no-store")
	http.SetCookie(c.Writer, newDownloadSessionCookie("", -1))
	c.Redirect(http.StatusSeeOther, "/login")
}

func (s *downloadAuthState) writeLoginRateLimited(c *gin.Context) {
	c.Header("Retry-After", strconv.Itoa(int(downloadLoginWindow/time.Second)))
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusTooManyRequests, "登录尝试过于频繁，请稍后再试。")
}

//go:embed download_login.html
var loginFiles embed.FS

var downloadLoginPage = template.Must(template.ParseFS(loginFiles, "download_login.html"))

func (s *downloadAuthState) writeLoginPage(c *gin.Context, status int, message string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	c.Status(status)
	_ = downloadLoginPage.Execute(c.Writer, struct {
		Disabled      bool
		Authenticated bool
		Message       string
	}{s.disabled(), DownloadAuthenticated(c), message})
}
