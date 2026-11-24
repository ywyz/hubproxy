package handlers

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/idna"
	"hubproxy/utils"
)

var (
	// GitHub URL匹配正则表达式
	githubExps = []*regexp.Regexp{
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:releases|archive)/.*`),
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:blob|raw)/.*`),
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:info|git-).*`),
		regexp.MustCompile(`^(?:https?://)?raw\.github(?:usercontent|)\.com/([^/]+)/([^/]+)/.+?/.+`),
		regexp.MustCompile(`^(?:https?://)?gist\.(?:githubusercontent|github)\.com/([^/]+)/([^/]+).*`),
		regexp.MustCompile(`^(?:https?://)?api\.github\.com/repos/([^/]+)/([^/]+)/.*`),
		regexp.MustCompile(`^(?:https?://)?huggingface\.co(?:/spaces)?/([^/]+)/(.+)`),
		regexp.MustCompile(`^(?:https?://)?cdn-lfs\.hf\.co(?:/spaces)?/([^/]+)/([^/]+)(?:/(.*))?`),
		regexp.MustCompile(`^(?:https?://)?(github|opengraph)\.githubassets\.com/([^/]+)/.+?`),
		// 通用 HTTPS 直链必须放在最后，避免覆盖上面的仓库级捕获规则。
		// 捕获域名和路径，交由独立的直链访问名单进行限制。
		regexp.MustCompile(`^https://([^/?#]+)/(.+)`),
	}
	githubBlobRoute = regexp.MustCompile(`^(https?://github\.com/[^/]+/[^/]+/)blob/`)
)

// 全局变量：被阻止的内容类型
var blockedContentTypes = map[string]bool{
	"text/html":             true,
	"application/xhtml+xml": true,
	"text/xml":              true,
	"application/xml":       true,
}

var directLinkRequestHeaders = map[string]struct{}{
	"Accept":              {},
	"Accept-Encoding":     {},
	"Accept-Language":     {},
	"Cache-Control":       {},
	"If-Match":            {},
	"If-Modified-Since":   {},
	"If-None-Match":       {},
	"If-Range":            {},
	"If-Unmodified-Since": {},
	"Range":               {},
	"User-Agent":          {},
}

var sourceCredentialHeaders = map[string]struct{}{
	"Authorization":       {},
	"Cookie":              {},
	"Cookie2":             {},
	"Proxy-Authorization": {},
	"Www-Authenticate":    {},
}

var directLinkResponseAuthenticationHeaders = []string{
	"Set-Cookie",
	"Set-Cookie2",
	"Clear-Site-Data",
	"Www-Authenticate",
	"Proxy-Authenticate",
	"Authentication-Info",
	"Proxy-Authentication-Info",
}

var blockedDirectLinkNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/32"),    // Teredo tunneling.
	netip.MustParsePrefix("2001:2::/48"),  // Benchmarking.
	netip.MustParsePrefix("2001:10::/28"), // Deprecated ORCHID identifiers.
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4 tunneling.
	netip.MustParsePrefix("3ffe::/16"), // Former 6bone space.
	netip.MustParsePrefix("3fff::/20"), // Documentation.
}

// IANA currently assigns IPv6 global-unicast networks from 2000::/3.
// This excludes reserved space, including the former site-local fec0::/10.
// https://www.iana.org/assignments/ipv6-address-space/
var globalIPv6Allocation = netip.MustParsePrefix("2000::/3")
var wellKnownNAT64 = netip.MustParsePrefix("64:ff9b::/96")

var lookupDirectLinkIPs = net.DefaultResolver.LookupNetIP

var (
	errDirectLinkSpoolCapacity = errors.New("direct-link spool capacity exhausted")
	directLinkStagingQuota     = &directLinkSpoolQuota{}
	directLinkRequestSlots     = make(chan struct{}, 16)
	directLinkBodyIdleTimeout  = 2 * time.Minute
	directLinkRequestTimeout   = 30 * time.Minute
)

type proxyRequestState struct {
	method  string
	body    io.Reader
	hasBody bool
}

// directLinkSpoolQuota bounds aggregate temporary-file content while still
// allowing multiple small direct-link downloads to stage concurrently.
type directLinkSpoolQuota struct {
	mu   sync.Mutex
	used int64
}

func (q *directLinkSpoolQuota) reserve(size, limit int64) bool {
	if size <= 0 {
		return true
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if limit <= 0 || q.used > limit || size > limit-q.used {
		return false
	}
	q.used += size
	return true
}

func (q *directLinkSpoolQuota) release(size int64) {
	if size <= 0 {
		return
	}
	q.mu.Lock()
	q.used -= size
	if q.used < 0 {
		q.used = 0
	}
	q.mu.Unlock()
}

type directLinkQuotaWriter struct {
	file     *os.File
	quota    *directLinkSpoolQuota
	limit    int64
	reserved int64
	err      error
}

func (w *directLinkQuotaWriter) Write(p []byte) (int, error) {
	size := int64(len(p))
	if w.err != nil {
		return 0, w.err
	}
	if size > w.limit-w.reserved {
		w.err = errDownloadLoginRequired
		return 0, w.err
	}
	if !w.quota.reserve(size, w.limit) {
		w.err = errDirectLinkSpoolCapacity
		return 0, w.err
	}
	written, err := w.file.Write(p)
	if unwritten := size - int64(written); unwritten > 0 {
		w.quota.release(unwritten)
	}
	w.reserved += int64(written)
	if err == nil && written != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return written, err
}

type directLinkIdleReadCloser struct {
	io.ReadCloser
	timeout  time.Duration
	timer    *time.Timer
	timedOut atomic.Bool
}

func newDirectLinkIdleReadCloser(body io.ReadCloser, timeout time.Duration, cancel context.CancelFunc) *directLinkIdleReadCloser {
	reader := &directLinkIdleReadCloser{ReadCloser: body, timeout: timeout}
	reader.timer = time.AfterFunc(timeout, func() {
		reader.timedOut.Store(true)
		cancel()
	})
	return reader
}

func (r *directLinkIdleReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 && !r.timedOut.Load() {
		r.timer.Reset(r.timeout)
	}
	if err != nil {
		r.timer.Stop()
	}
	return n, err
}

func (r *directLinkIdleReadCloser) Close() error {
	r.timer.Stop()
	return r.ReadCloser.Close()
}

// GitHubProxyHandler GitHub代理处理器
func GitHubProxyHandler(c *gin.Context) {
	rawPath := strings.TrimPrefix(c.Request.URL.RequestURI(), "/")

	for strings.HasPrefix(rawPath, "/") {
		rawPath = strings.TrimPrefix(rawPath, "/")
	}

	// 自动补全协议头
	mirror := isMirrorRequest(c)
	if mirror {
		rawPath = "https://" + strings.TrimPrefix(rawPath, "mirrors/")
	} else if !strings.HasPrefix(rawPath, "https://") {
		if strings.HasPrefix(rawPath, "http:/") || strings.HasPrefix(rawPath, "https:/") {
			rawPath = strings.Replace(rawPath, "http:/", "", 1)
			rawPath = strings.Replace(rawPath, "https:/", "", 1)
		} else if strings.HasPrefix(rawPath, "http://") {
			rawPath = strings.TrimPrefix(rawPath, "http://")
		}
		rawPath = "https://" + rawPath
	}

	matches, directLink := matchDownloadURL(rawPath, mirror)
	if matches != nil {
		if directLink && c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Header("Allow", "GET, HEAD")
			c.String(http.StatusMethodNotAllowed, "通用直链仅支持 GET 和 HEAD")
			return
		}
		if directLink && strings.Contains(c.GetHeader("Range"), ",") {
			c.String(http.StatusRequestedRangeNotSatisfiable, "通用直链仅支持单区间 Range 请求")
			return
		}
		allowed, reason := utils.GlobalAccessController.CheckGitHubAccess(matches)
		if directLink {
			allowed, reason = utils.GlobalAccessController.CheckDirectLinkAccess(matches)
		}
		if !allowed {
			if directLink {
				safePath, _, _ := strings.Cut(matches[1], "?")
				fmt.Printf("通用直链 %s/%s 访问被拒绝: %s\n", matches[0], safePath, reason)
			} else {
				var repoPath string
				username := matches[0]
				repoName := strings.TrimSuffix(matches[1], ".git")
				repoPath = username + "/" + repoName
				fmt.Printf("GitHub仓库 %s 访问被拒绝: %s\n", repoPath, reason)
			}
			c.String(http.StatusForbidden, reason)
			return
		}
	} else {
		c.String(http.StatusForbidden, "无效输入")
		return
	}

	// 将blob链接转换为raw链接
	if !mirror && !directLink {
		rawPath = repositoryDownloadURL(rawPath)
	}

	ProxyGitHubRequest(c, rawPath)
}

// CheckGitHubURL 检查URL是否匹配GitHub模式
func CheckGitHubURL(u string) []string {
	matches, _ := matchDownloadURL(u, false)
	return matches
}

func isMirrorRequest(c *gin.Context) bool {
	return strings.HasPrefix(c.Request.URL.EscapedPath(), "/mirrors/")
}

func repositoryDownloadURL(u string) string {
	canonical, ok := canonicalRepositoryURL(u)
	if !ok {
		return u
	}
	return githubBlobRoute.ReplaceAllString(canonical, "${1}raw/")
}

func matchDownloadURL(u string, mirror bool) ([]string, bool) {
	// Repository mirrors use the dedicated direct-link ACL on every hop, even
	// when a mirror's host or redirect also matches a GitHub repository route.
	if !mirror {
		if repositoryURL, ok := canonicalRepositoryURL(u); ok {
			for _, exp := range githubExps[:len(githubExps)-1] {
				if matches := exp.FindStringSubmatch(repositoryURL); matches != nil {
					return matches[1:], false
				}
			}
		}
	}
	targetURL, err := url.Parse(u)
	if err != nil {
		return nil, false
	}
	matches, err := directLinkAccessMatches(targetURL)
	if err == nil {
		return matches, true
	}
	return nil, false
}

// Normalize only the authority for repository routing. Keep escaped paths and
// signed queries intact and preserve support for scheme-less repository URLs.
func canonicalRepositoryURL(u string) (string, bool) {
	scheme, _, absolute := strings.Cut(u, "://")
	if !absolute || strings.ContainsAny(scheme, "/?#") {
		u = "https://" + u
	}
	targetURL, err := url.Parse(u)
	if err != nil || targetURL.User != nil || (targetURL.Scheme != "https" && targetURL.Scheme != "http") {
		return "", false
	}
	authority, err := canonicalDirectLinkAuthority(targetURL)
	if err != nil {
		return "", false
	}
	targetURL.Host = authority
	return targetURL.String(), true
}

func directLinkAccessMatches(targetURL *url.URL) ([]string, error) {
	if targetURL == nil || !strings.EqualFold(targetURL.Scheme, "https") || targetURL.Hostname() == "" || targetURL.User != nil {
		return nil, fmt.Errorf("通用直链目标必须是无来源凭据的 HTTPS 地址")
	}

	authority, err := canonicalDirectLinkAuthority(targetURL)
	if err != nil {
		return nil, err
	}
	escapedPath := targetURL.EscapedPath()
	lowerEscapedPath := strings.ToLower(escapedPath)
	for _, encodedDelimiter := range []string{"%25", "%2f", "%5c", "%3f", "%23"} {
		if strings.Contains(lowerEscapedPath, encodedDelimiter) {
			return nil, fmt.Errorf("通用直链路径包含编码分隔符或百分号")
		}
	}
	decodedPath := targetURL.Path
	if decodedPath == "" || decodedPath == "/" || strings.Contains(decodedPath, "\\") {
		return nil, fmt.Errorf("通用直链必须包含明确的文件路径")
	}
	for _, segment := range strings.Split(decodedPath, "/") {
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("通用直链路径包含目录遍历")
		}
	}
	cleanedPath := path.Clean(decodedPath)
	if cleanedPath != decodedPath || !strings.HasPrefix(cleanedPath, "/") {
		return nil, fmt.Errorf("通用直链路径不规范")
	}

	pathAndQuery := strings.TrimPrefix(cleanedPath, "/")
	if targetURL.RawQuery != "" {
		pathAndQuery += "?" + targetURL.RawQuery
	}
	return []string{authority, pathAndQuery}, nil
}

func canonicalDirectLinkAuthority(targetURL *url.URL) (string, error) {
	hostname := strings.TrimSuffix(targetURL.Hostname(), ".")
	if hostname == "" || strings.Contains(hostname, "%") {
		return "", fmt.Errorf("无效的通用直链主机名")
	}
	if address, err := netip.ParseAddr(hostname); err == nil {
		address = address.Unmap()
		hostname = address.String()
		if address.Is6() {
			hostname = "[" + hostname + "]"
		}
	} else {
		asciiHostname, err := idna.Lookup.ToASCII(hostname)
		if err != nil {
			return "", fmt.Errorf("无效的通用直链主机名")
		}
		hostname = strings.ToLower(asciiHostname)
	}

	port := targetURL.Port()
	if port == "" {
		return hostname, nil
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("无效的通用直链端口")
	}
	if (targetURL.Scheme == "http" && portNumber == 80) ||
		(strings.EqualFold(targetURL.Scheme, "https") && portNumber == 443) {
		return hostname, nil
	}
	return net.JoinHostPort(strings.Trim(hostname, "[]"), strconv.Itoa(portNumber)), nil
}

// ProxyGitHubRequest 代理GitHub请求
func ProxyGitHubRequest(c *gin.Context, u string) {
	_, directLink := matchDownloadURL(u, isMirrorRequest(c))
	if directLink {
		requestContext := c.Request.Context()
		if !DownloadAuthenticated(c) {
			var cancel context.CancelFunc
			requestContext, cancel = context.WithTimeout(requestContext, directLinkRequestTimeout)
			defer cancel()
			c.Request = c.Request.WithContext(requestContext)
		}

		requestSlots := directLinkRequestSlots
		select {
		case requestSlots <- struct{}{}:
			defer func() { <-requestSlots }()
		case <-requestContext.Done():
			finishDirectLinkContextError(c)
			return
		default:
			c.String(http.StatusServiceUnavailable, "直链请求并发已满，请稍后重试")
			return
		}
	}
	requestState := proxyRequestState{
		method: c.Request.Method,
		body:   c.Request.Body,
		hasBody: c.Request.Body != nil && c.Request.Body != http.NoBody &&
			(c.Request.ContentLength != 0 || len(c.Request.TransferEncoding) > 0),
	}
	proxyGitHubWithRedirect(c, u, 0, directLink, true, requestState)
}

// proxyGitHubWithRedirect 带重定向的GitHub代理请求
func proxyGitHubWithRedirect(
	c *gin.Context,
	u string,
	redirectCount int,
	directLink, forwardSourceCredentials bool,
	requestState proxyRequestState,
) {
	const maxRedirects = 20
	mirror := isMirrorRequest(c)
	if redirectCount > maxRedirects {
		c.String(http.StatusLoopDetected, "重定向次数过多，可能存在循环重定向")
		return
	}
	// Direct links and credential-stripped redirect hops dial a target chosen
	// by an upstream response. Pin DNS, IP, and TLS on every such hop instead
	// of trusting the shared outbound client pool.
	pinnedHop := directLink || !forwardSourceCredentials
	var directTargetAddresses []netip.Addr
	var directTargetServerName string
	if pinnedHop {
		targetURL, err := url.Parse(u)
		if err != nil {
			c.String(http.StatusForbidden, "无效的通用直链地址")
			return
		}
		directTargetAddresses, directTargetServerName, err = validateDirectLinkTarget(c.Request.Context(), targetURL)
		if err != nil {
			if finishDirectLinkContextError(c) {
				return
			}
			c.String(http.StatusForbidden, err.Error())
			return
		}
	}
	if directLink {
		matches, targetIsDirectLink := matchDownloadURL(u, mirror)
		if matches == nil {
			c.String(http.StatusForbidden, "无效的通用直链地址")
			return
		}
		allowed, reason := utils.GlobalAccessController.CheckGitHubAccess(matches)
		if targetIsDirectLink {
			allowed, reason = utils.GlobalAccessController.CheckDirectLinkAccess(matches)
		}
		if !allowed {
			c.String(http.StatusForbidden, reason)
			return
		}
	}

	baseHTTPClient := utils.GetGlobalHTTPClient()
	if baseHTTPClient == nil {
		c.String(http.StatusInternalServerError, "HTTP 客户端尚未初始化")
		return
	}
	var resp *http.Response
	var requestErr error
	var directTransport *http.Transport
	var directRequestCancel context.CancelFunc
	if pinnedHop {
		baseTransport, ok := baseHTTPClient.Transport.(*http.Transport)
		if !ok {
			c.String(http.StatusInternalServerError, "通用直链 HTTP 传输配置无效")
			return
		}
		for _, targetAddress := range directTargetAddresses {
			req, err := newProxyRequest(c, u, true, false, requestState)
			if err != nil {
				requestErr = err
				break
			}
			attemptContext, cancelAttempt := context.WithCancel(req.Context())
			req = req.WithContext(attemptContext)
			transport := baseTransport.Clone()
			if baseTransport.Proxy != nil {
				// Decide proxy/NO_PROXY routing from the original hostname before
				// pinning the validated public address used for the actual dial.
				proxyURL, proxyErr := baseTransport.Proxy(req)
				if proxyErr != nil {
					cancelAttempt()
					requestErr = proxyErr
					break
				}
				transport.Proxy = func(*http.Request) (*url.URL, error) {
					return proxyURL, nil
				}
			}
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			} else {
				transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			}
			transport.TLSClientConfig.ServerName = directTargetServerName
			originalHost := req.URL.Host
			port := req.URL.Port()
			if port == "" {
				port = "443"
			}
			req.Host = originalHost
			req.URL.Host = net.JoinHostPort(targetAddress.String(), port)

			httpClient := *baseHTTPClient
			httpClient.Transport = transport
			httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}
			resp, requestErr = httpClient.Do(req)
			if requestErr == nil {
				directTransport = transport
				directRequestCancel = cancelAttempt
				break
			}
			cancelAttempt()
			transport.CloseIdleConnections()
			if c.Request.Context().Err() != nil {
				break
			}
		}
	} else {
		req, err := newProxyRequest(c, u, false, forwardSourceCredentials, requestState)
		if err != nil {
			requestErr = err
		} else {
			httpClient := *baseHTTPClient
			httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}
			var ctx context.Context
			ctx, directRequestCancel = context.WithCancel(req.Context())
			resp, requestErr = httpClient.Do(req.WithContext(ctx))
		}
	}
	if directTransport != nil {
		defer directTransport.CloseIdleConnections()
	}
	if directRequestCancel != nil {
		defer directRequestCancel()
	}
	err := requestErr
	if err != nil {
		if directLink && finishDirectLinkContextError(c) {
			return
		}
		c.String(http.StatusInternalServerError, fmt.Sprintf("server error %v", err))
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("关闭响应体失败: %v\n", err)
		}
	}()

	sanitizeDownloadHeaders(resp.Header)
	if DownloadAuthenticated(c) {
		preventDownloadCaching(resp.Header)
	}

	if location := resp.Header.Get("Location"); location != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		currentURL, parseErr := url.Parse(u)
		if parseErr != nil {
			c.String(http.StatusBadGateway, "无效的重定向来源地址")
			return
		}
		locationURL, parseErr := url.Parse(location)
		if parseErr != nil {
			c.String(http.StatusBadGateway, "无效的重定向地址")
			return
		}
		nextURL := currentURL.ResolveReference(locationURL)
		matches, nextIsDirectLink := matchDownloadURL(nextURL.String(), mirror)
		if directLink {
			if !strings.EqualFold(nextURL.Scheme, "https") {
				c.String(http.StatusForbidden, "通用直链重定向仅允许 HTTPS")
				return
			}
			if matches == nil {
				c.String(http.StatusForbidden, "无效的重定向地址")
				return
			}
			allowed, reason := utils.GlobalAccessController.CheckGitHubAccess(matches)
			if nextIsDirectLink {
				allowed, reason = utils.GlobalAccessController.CheckDirectLinkAccess(matches)
			}
			if !allowed {
				c.String(http.StatusForbidden, reason)
				return
			}
			_ = resp.Body.Close()
			proxyGitHubWithRedirect(
				c,
				nextURL.String(),
				redirectCount+1,
				true,
				false,
				proxyRequestState{method: requestState.method},
			)
			return
		}

		keepCredentials := forwardSourceCredentials && sameOrigin(currentURL, nextURL)
		nextTarget := nextURL.String()
		if matches != nil && !nextIsDirectLink {
			if allowed, reason := utils.GlobalAccessController.CheckGitHubAccess(matches); !allowed {
				c.String(http.StatusForbidden, reason)
				return
			}
			if keepCredentials {
				copyResponseHeaders(c, resp.Header)
				removeResponseEntityHeaders(c.Writer.Header())
				c.Header("Location", "/"+nextURL.String())
				c.Status(resp.StatusCode)
				return
			}
			nextTarget = repositoryDownloadURL(nextTarget)
		}

		nextRequestState, redirectErr := redirectedProxyRequest(resp.StatusCode, requestState)
		if redirectErr != nil {
			c.String(http.StatusBadGateway, redirectErr.Error())
			return
		}
		_ = resp.Body.Close()
		proxyGitHubWithRedirect(c, nextTarget, redirectCount+1, false, keepCredentials, nextRequestState)
		return
	}

	// 检查并处理被阻止的内容类型
	if c.Request.Method == "GET" && !mirror {
		if contentType := resp.Header.Get("Content-Type"); blockedContentTypes[strings.ToLower(strings.Split(contentType, ";")[0])] {
			c.JSON(http.StatusForbidden, map[string]string{
				"error":   "Content type not allowed",
				"message": "检测到网页类型，本服务不支持加速网页，请检查您的链接是否正确。",
			})
			return
		}
	}

	authenticated := DownloadAuthenticated(c)
	rangeLength := int64(-1)
	if resp.StatusCode == http.StatusPartialContent {
		var allowed bool
		rangeLength, allowed = downloadRangeLength(c, resp, directLink, authenticated)
		if !allowed {
			return
		}
	}
	if !authenticated && resp.ContentLength > anonymousDownloadLimit() {
		RequireDownloadLogin(c)
		return
	}

	responseBody := io.Reader(resp.Body)
	hasBody := requestState.method != http.MethodHead && resp.StatusCode != http.StatusNotModified && resp.StatusCode != http.StatusNoContent
	if hasBody {
		reader := newDirectLinkIdleReadCloser(resp.Body, directLinkBodyIdleTimeout, directRequestCancel)
		resp.Body = reader
		responseBody = reader
		if !authenticated && resp.ContentLength < 0 {
			limit := anonymousDownloadLimit()
			if rangeLength >= 0 {
				limit = min(limit, rangeLength)
			}
			staged, err := stageAnonymousDownload(func(w *directLinkQuotaWriter) error {
				_, err := io.Copy(w, io.LimitReader(reader, limit+1))
				return err
			})
			if staged != nil {
				defer staged.cleanup()
			}
			switch {
			case reader.timedOut.Load():
				c.String(http.StatusGatewayTimeout, "读取下载响应超时")
				return
			case finishDirectLinkContextError(c):
				return
			case err != nil:
				if !handleDownloadStageError(c, err) {
					c.String(http.StatusBadGateway, "读取下载响应失败")
				}
				return
			}
			if rangeLength >= 0 && staged.size != rangeLength {
				c.String(http.StatusBadGateway, "上游分段长度与 Content-Range 不符")
				return
			}
			responseBody = staged
			resp.ContentLength = staged.size
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Set("Content-Length", strconv.FormatInt(staged.size, 10))
		}
	}
	if rangeLength >= 0 && resp.ContentLength < 0 {
		resp.Header.Set("Content-Length", strconv.FormatInt(rangeLength, 10))
		responseBody = io.LimitReader(responseBody, rangeLength)
	}

	if directLink {
		for _, header := range directLinkResponseAuthenticationHeaders {
			resp.Header.Del(header)
		}
	}

	// 清理安全相关的头
	resp.Header.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Del("Referrer-Policy")
	resp.Header.Del("Strict-Transport-Security")
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if directLink || mediaType == "" || strings.Contains(mediaType, "javascript") || strings.Contains(mediaType, "ecmascript") ||
		mediaType == "image/svg+xml" || mediaType == "text/css" || mediaType == "application/wasm" ||
		mediaType == "text/html" || mediaType == "application/xhtml+xml" || mediaType == "text/livescript" || mediaType == "text/jscript" {
		resp.Header.Set("Content-Type", "application/octet-stream")
		resp.Header.Set("Content-Disposition", downloadDisposition(resp.Header.Get("Content-Disposition")))
		resp.Header.Set("X-Content-Type-Options", "nosniff")
	}

	// Download managers and package mirrors need the original bytes. Only
	// transform small, ordinary anonymous script requests.
	script := strings.HasSuffix(strings.ToLower(u), ".sh") || strings.HasSuffix(strings.ToLower(u), ".ps1")
	if script && !mirror && !authenticated && requestState.method == http.MethodGet && resp.StatusCode == http.StatusOK &&
		c.GetHeader("Range") == "" && resp.ContentLength >= 0 && resp.ContentLength <= utils.MaxShellSize {
		proxyHost := "https://" + c.Request.Host
		encoding := resp.Header.Get("Content-Encoding")
		if encoding == "" || strings.EqualFold(encoding, "gzip") {
			// Keep the encoded source as a fallback when gzip expands beyond
			// the script rewriter's memory limit.
			source, err := io.ReadAll(io.LimitReader(responseBody, utils.MaxShellSize+1))
			if err != nil {
				c.String(http.StatusBadGateway, "读取脚本失败")
				return
			}
			responseBody = bytes.NewReader(source)
			processed, size, err := utils.ProcessSmart(bytes.NewReader(source), encoding != "", proxyHost)
			if err == nil && size <= anonymousDownloadLimit() {
				responseBody = processed
				preventDownloadCaching(resp.Header)
				resp.Header.Del("Content-Encoding")
				resp.Header.Del("ETag")
				resp.Header.Del("Digest")
				resp.Header.Set("Accept-Ranges", "none")
				resp.Header.Set("Content-Length", strconv.FormatInt(size, 10))
			}
		}
	}
	copyResponseHeaders(c, resp.Header)
	c.Status(resp.StatusCode)
	if hasBody {
		if n, err := copyDownloadResponse(c.Writer, responseBody); err != nil || (rangeLength >= 0 && n != rangeLength) {
			if !c.Writer.Written() {
				removeResponseEntityHeaders(c.Writer.Header())
				c.String(http.StatusBadGateway, "下载传输中断")
				return
			}
			// net/http terminates the stream without a final chunk. Clients
			// can then distinguish an incomplete unknown-length transfer.
			panic(http.ErrAbortHandler)
		}
	}
}

func finishDirectLinkContextError(c *gin.Context) bool {
	switch {
	case errors.Is(c.Request.Context().Err(), context.DeadlineExceeded):
		c.String(http.StatusGatewayTimeout, "通用直链请求超时")
		return true
	case errors.Is(c.Request.Context().Err(), context.Canceled):
		return true
	default:
		return false
	}
}

func preventDownloadCaching(header http.Header) {
	for _, key := range []string{"CDN-Cache-Control", "Surrogate-Control", "Cloudflare-CDN-Cache-Control", "Expires"} {
		header.Del(key)
	}
	header.Set("Cache-Control", "private, no-store")
}

// Remove connection-local, reverse-proxy, and browser-origin directives before
// applying HubProxy's own response headers, including on redirect responses.
func sanitizeDownloadHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, key := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(key))
		}
	}
	for key := range header {
		name := strings.ToLower(key)
		if strings.HasPrefix(name, "x-accel-") || strings.HasPrefix(name, "access-control-") {
			header.Del(key)
		}
	}
	for _, key := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
		"Set-Cookie", "Set-Cookie2", "Clear-Site-Data", "Refresh", "Service-Worker-Allowed", "Alt-Svc", "Link",
	} {
		header.Del(key)
	}
}

func copyResponseHeaders(c *gin.Context, headers http.Header) {
	for key, values := range headers {
		for _, value := range values {
			c.Writer.Header().Add(key, value)
		}
	}
	c.Writer.Header().Add("Vary", "Cookie, Authorization")
}

func removeResponseEntityHeaders(headers http.Header) {
	for _, name := range []string{
		"Content-Encoding",
		"Content-Length",
		"Content-Range",
		"Content-Type",
		"Trailer",
		"Transfer-Encoding",
	} {
		headers.Del(name)
	}
}

func newProxyRequest(
	c *gin.Context,
	target string,
	directLink, forwardSourceCredentials bool,
	requestState proxyRequestState,
) (*http.Request, error) {
	requestBody := requestState.body
	if directLink {
		requestBody = nil
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), requestState.method, target, requestBody)
	if err != nil {
		return nil, err
	}

	// 通用直链仅转发下载所需的允许列表头，避免泄露代理来源凭据。
	for key, values := range c.Request.Header {
		if directLink {
			if _, allowed := directLinkRequestHeaders[http.CanonicalHeaderKey(key)]; !allowed {
				continue
			}
		} else if !forwardSourceCredentials {
			if _, sensitive := sourceCredentialHeaders[http.CanonicalHeaderKey(key)]; sensitive {
				continue
			}
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Header.Del("Host")
	return req, nil
}

func redirectedProxyRequest(statusCode int, current proxyRequestState) (proxyRequestState, error) {
	next := proxyRequestState{method: current.method}
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound:
		if current.method != http.MethodGet && current.method != http.MethodHead {
			next.method = http.MethodGet
		}
	case http.StatusSeeOther:
		if current.method != http.MethodHead {
			next.method = http.MethodGet
		}
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		if current.hasBody {
			return proxyRequestState{}, fmt.Errorf("上游重定向需要重放已消耗的请求体")
		}
	default:
		return proxyRequestState{}, fmt.Errorf("不支持的上游重定向状态: %d", statusCode)
	}
	return next, nil
}

func sameOrigin(left, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) ||
		(left.Scheme != "http" && left.Scheme != "https") || left.User != nil || right.User != nil {
		return false
	}
	a, leftErr := canonicalDirectLinkAuthority(left)
	b, rightErr := canonicalDirectLinkAuthority(right)
	return leftErr == nil && rightErr == nil && a == b
}

// Only carry a portable filename across origins. mime.ParseMediaType resolves
// RFC 5987 filename* and FormatMediaType quotes or encodes it for the recipient.
func downloadDisposition(header string) string {
	_, params, err := mime.ParseMediaType(header)
	name := params["filename"]
	if err != nil || name == "" || name == "~" || name == "." || name == ".." || !utf8.ValidString(name) ||
		strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") || strings.ContainsAny(name, `/\<>:"|?*`) ||
		strings.ContainsFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return "attachment"
	}
	// Windows device names also keep their special meaning with an extension.
	base, _, _ := strings.Cut(strings.ToUpper(name), ".")
	base = strings.TrimRight(base, " ")
	switch base {
	case "CON", "NUL", "PRN", "AUX", "CONIN$", "CONOUT$":
		return "attachment"
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		suffix := base[3:]
		if utf8.RuneCountInString(suffix) == 1 && strings.Contains("123456789¹²³", suffix) {
			return "attachment"
		}
	}
	return mime.FormatMediaType("attachment", map[string]string{"filename": name})
}

// downloadRangeLength gates a partial response on the whole representation.
// A multipart response has no single complete length at the header level.
func downloadRangeLength(c *gin.Context, resp *http.Response, directLink, authenticated bool) (int64, bool) {
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if !directLink && mediaType == "multipart/byteranges" {
		if !authenticated {
			RequireDownloadLogin(c)
		}
		return -1, authenticated
	}

	start, end, total, valid := parseDownloadRange(resp.Header.Get("Content-Range"))
	if !valid || end-start == math.MaxInt64 || (resp.ContentLength >= 0 && resp.ContentLength-1 != end-start) {
		c.String(http.StatusBadGateway, "上游返回了无效的 Content-Range")
		return -1, false
	}
	if !authenticated && (total < 0 || total > anonymousDownloadLimit()) {
		RequireDownloadLogin(c)
		return -1, false
	}
	return end - start + 1, true
}

func parseDownloadRange(value string) (start, end, total int64, valid bool) {
	unit, spanAndTotal, ok := strings.Cut(strings.TrimSpace(value), " ")
	span, totalText, hasTotal := strings.Cut(spanAndTotal, "/")
	first, last, hasSpan := strings.Cut(span, "-")
	if !ok || !strings.EqualFold(unit, "bytes") || !hasTotal || !hasSpan {
		return
	}
	parse := func(text string) (int64, error) {
		// The HTTP range grammar only admits unsigned decimal digits.
		n, err := strconv.ParseUint(text, 10, 63)
		return int64(n), err
	}
	start, startErr := parse(first)
	end, endErr := parse(last)
	if startErr != nil || endErr != nil || end < start {
		return
	}
	if totalText == "*" {
		return start, end, -1, true
	}
	total, err := parse(totalText)
	return start, end, total, err == nil && end < total
}

func validateDirectLinkTarget(ctx context.Context, targetURL *url.URL) ([]netip.Addr, string, error) {
	if targetURL == nil || !strings.EqualFold(targetURL.Scheme, "https") || targetURL.Hostname() == "" || targetURL.User != nil {
		return nil, "", fmt.Errorf("通用直链目标必须是无来源凭据的 HTTPS 地址")
	}

	hostname := strings.TrimSuffix(targetURL.Hostname(), ".")
	addresses := make([]netip.Addr, 0, 1)
	if address, err := netip.ParseAddr(hostname); err == nil {
		address = address.Unmap()
		hostname = address.String()
		addresses = append(addresses, address)
	} else {
		asciiHostname, err := idna.Lookup.ToASCII(hostname)
		if err != nil {
			return nil, "", fmt.Errorf("无效的通用直链主机名")
		}
		hostname = strings.ToLower(asciiHostname)
		resolved, resolveErr := lookupDirectLinkIPs(ctx, "ip", hostname)
		if resolveErr != nil || len(resolved) == 0 {
			return nil, "", fmt.Errorf("无法解析通用直链目标地址")
		}
		addresses = append(addresses, resolved...)
	}

	validated := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		check := address
		if wellKnownNAT64.Contains(address) {
			// A DNS64 resolver on an IPv6-only host can synthesize either a
			// public or local IPv4 target. Validate the embedded destination.
			raw := address.As16()
			check = netip.AddrFrom4([4]byte(raw[12:]))
		}
		if !check.IsGlobalUnicast() || check.IsPrivate() || (check.Is6() && !globalIPv6Allocation.Contains(check)) {
			return nil, "", fmt.Errorf("通用直链目标地址不可访问")
		}
		for _, blocked := range blockedDirectLinkNetworks {
			if blocked.Contains(check) {
				return nil, "", fmt.Errorf("通用直链目标地址不可访问")
			}
		}
		validated = append(validated, address)
	}
	return validated, hostname, nil
}
