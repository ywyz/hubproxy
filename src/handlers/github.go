package handlers

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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

	"github.com/gin-gonic/gin"
	"golang.org/x/net/idna"
	"hubproxy/config"
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
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

var lookupDirectLinkIPs = net.DefaultResolver.LookupNetIP

var (
	errDirectLinkSpoolCapacity = errors.New("direct-link spool capacity exhausted")
	directLinkStagingQuota     = &directLinkSpoolQuota{}
	directLinkStagingSlots     = make(chan struct{}, 16)
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
}

func (w *directLinkQuotaWriter) Write(p []byte) (int, error) {
	size := int64(len(p))
	if !w.quota.reserve(size, w.limit) {
		return 0, errDirectLinkSpoolCapacity
	}
	written, err := w.file.Write(p)
	if unwritten := size - int64(written); unwritten > 0 {
		w.quota.release(unwritten)
	}
	w.reserved += int64(written)
	if err == nil && written != len(p) {
		err = io.ErrShortWrite
	}
	return written, err
}

func (w *directLinkQuotaWriter) release() {
	w.quota.release(w.reserved)
	w.reserved = 0
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
	if !strings.HasPrefix(rawPath, "https://") {
		if strings.HasPrefix(rawPath, "http:/") || strings.HasPrefix(rawPath, "https:/") {
			rawPath = strings.Replace(rawPath, "http:/", "", 1)
			rawPath = strings.Replace(rawPath, "https:/", "", 1)
		} else if strings.HasPrefix(rawPath, "http://") {
			rawPath = strings.TrimPrefix(rawPath, "http://")
		}
		rawPath = "https://" + rawPath
	}

	matches, directLink := matchGitHubURL(rawPath)
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
	if githubExps[1].MatchString(rawPath) {
		rawPath = strings.Replace(rawPath, "/blob/", "/raw/", 1)
	}

	ProxyGitHubRequest(c, rawPath)
}

// CheckGitHubURL 检查URL是否匹配GitHub模式
func CheckGitHubURL(u string) []string {
	matches, _ := matchGitHubURL(u)
	return matches
}

func matchGitHubURL(u string) ([]string, bool) {
	for _, exp := range githubExps[:len(githubExps)-1] {
		if matches := exp.FindStringSubmatch(u); matches != nil {
			return matches[1:], false
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
	if portNumber == 443 {
		return hostname, nil
	}
	return net.JoinHostPort(strings.Trim(hostname, "[]"), strconv.Itoa(portNumber)), nil
}

// ProxyGitHubRequest 代理GitHub请求
func ProxyGitHubRequest(c *gin.Context, u string) {
	_, directLink := matchGitHubURL(u)
	if directLink {
		requestContext, cancelRequest := context.WithTimeout(c.Request.Context(), directLinkRequestTimeout)
		defer cancelRequest()
		c.Request = c.Request.WithContext(requestContext)
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
	if redirectCount > maxRedirects {
		c.String(http.StatusLoopDetected, "重定向次数过多，可能存在循环重定向")
		return
	}
	var directTargetAddresses []netip.Addr
	if directLink {
		targetURL, err := url.Parse(u)
		if err != nil {
			c.String(http.StatusForbidden, "无效的通用直链地址")
			return
		}
		directTargetAddresses, err = validateDirectLinkTarget(c.Request.Context(), targetURL)
		if err != nil {
			if finishDirectLinkContextError(c) {
				return
			}
			c.String(http.StatusForbidden, err.Error())
			return
		}
		matches, targetIsDirectLink := matchGitHubURL(targetURL.String())
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
	if directLink {
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
			transport.TLSClientConfig.ServerName = req.URL.Hostname()
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
			resp, requestErr = httpClient.Do(req)
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
		matches, nextIsDirectLink := matchGitHubURL(nextURL.String())
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

		if matches != nil && !nextIsDirectLink {
			copyResponseHeaders(c, resp.Header)
			removeResponseEntityHeaders(c.Writer.Header())
			c.Header("Location", "/"+nextURL.String())
			c.Status(resp.StatusCode)
			return
		}

		keepCredentials := forwardSourceCredentials && sameOrigin(currentURL, nextURL)
		nextRequestState, redirectErr := redirectedProxyRequest(resp.StatusCode, requestState)
		if redirectErr != nil {
			c.String(http.StatusBadGateway, redirectErr.Error())
			return
		}
		_ = resp.Body.Close()
		proxyGitHubWithRedirect(c, nextURL.String(), redirectCount+1, false, keepCredentials, nextRequestState)
		return
	}

	// 检查并处理被阻止的内容类型
	if c.Request.Method == "GET" {
		if contentType := resp.Header.Get("Content-Type"); blockedContentTypes[strings.ToLower(strings.Split(contentType, ";")[0])] {
			c.JSON(http.StatusForbidden, map[string]string{
				"error":   "Content type not allowed",
				"message": "检测到网页类型，本服务不支持加速网页，请检查您的链接是否正确。",
			})
			return
		}
	}

	// 检查文件大小限制
	cfg := config.GetConfig()
	if directLink && resp.StatusCode == http.StatusPartialContent {
		totalSize, ok := contentRangeTotal(resp.Header.Get("Content-Range"))
		if !ok {
			c.String(http.StatusBadGateway, "上游返回了无效的 Content-Range")
			return
		}
		if totalSize > cfg.Server.FileSize {
			c.String(http.StatusRequestEntityTooLarge,
				fmt.Sprintf("文件过大，限制大小: %d MB", cfg.Server.FileSize/(1024*1024)))
			return
		}
	}
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil && size > cfg.Server.FileSize {
			c.String(http.StatusRequestEntityTooLarge,
				fmt.Sprintf("文件过大，限制大小: %d MB", cfg.Server.FileSize/(1024*1024)))
			return
		}
	}

	responseBody := io.Reader(resp.Body)
	if directLink && c.Request.Method == http.MethodGet {
		select {
		case directLinkStagingSlots <- struct{}{}:
			defer func() { <-directLinkStagingSlots }()
		case <-c.Request.Context().Done():
			finishDirectLinkContextError(c)
			return
		default:
			c.String(http.StatusServiceUnavailable, "直链暂存并发已满，请稍后重试")
			return
		}
		staged, err := os.CreateTemp("", "hubproxy-direct-*")
		if err != nil {
			c.String(http.StatusInternalServerError, "无法暂存直链响应")
			return
		}
		stagedName := staged.Name()
		var quotaWriter *directLinkQuotaWriter
		defer func() {
			if err := staged.Close(); err != nil {
				fmt.Printf("关闭直链临时文件失败: %v\n", err)
			}
			if err := os.Remove(stagedName); err != nil && !os.IsNotExist(err) {
				fmt.Printf("删除直链临时文件失败: %v\n", err)
			}
			if quotaWriter != nil {
				quotaWriter.release()
			}
		}()

		limit := cfg.Server.FileSize
		if limit <= 0 {
			c.String(http.StatusRequestEntityTooLarge, "文件大小限制无效")
			return
		}
		readLimit := limit
		if limit < int64(^uint64(0)>>1) {
			readLimit++
		}
		quotaWriter = &directLinkQuotaWriter{
			file:  staged,
			quota: directLinkStagingQuota,
			limit: readLimit,
		}
		responseBodyWithTimeout := newDirectLinkIdleReadCloser(resp.Body, directLinkBodyIdleTimeout, directRequestCancel)
		resp.Body = responseBodyWithTimeout
		written, copyErr := io.Copy(quotaWriter, io.LimitReader(responseBodyWithTimeout, readLimit))
		if responseBodyWithTimeout.timedOut.Load() {
			c.String(http.StatusGatewayTimeout, "读取直链响应超时")
			return
		}
		if finishDirectLinkContextError(c) {
			return
		}
		if copyErr != nil {
			if errors.Is(copyErr, errDirectLinkSpoolCapacity) {
				c.String(http.StatusServiceUnavailable, "直链暂存空间繁忙，请稍后重试")
				return
			}
			c.String(http.StatusBadGateway, "读取直链响应失败")
			return
		}
		if written > limit {
			c.String(http.StatusRequestEntityTooLarge,
				fmt.Sprintf("文件过大，限制大小: %d MB", limit/(1024*1024)))
			return
		}
		if _, err := staged.Seek(0, io.SeekStart); err != nil {
			c.String(http.StatusInternalServerError, "无法读取直链临时文件")
			return
		}
		responseBody = staged
		resp.Header.Del("Transfer-Encoding")
		resp.Header.Set("Content-Length", strconv.FormatInt(written, 10))
	}
	if directLink {
		for _, header := range directLinkResponseAuthenticationHeaders {
			resp.Header.Del(header)
		}
	}

	// 清理安全相关的头
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Referrer-Policy")
	resp.Header.Del("Strict-Transport-Security")
	if directLink {
		resp.Header.Set("Content-Type", "application/octet-stream")
		resp.Header.Set("Content-Disposition", "attachment")
		resp.Header.Set("X-Content-Type-Options", "nosniff")
	}

	// 获取真实域名
	realHost := c.Request.Header.Get("X-Forwarded-Host")
	if realHost == "" {
		realHost = c.Request.Host
	}
	if !strings.HasPrefix(realHost, "http://") && !strings.HasPrefix(realHost, "https://") {
		realHost = "https://" + realHost
	}

	// 处理.sh和.ps1文件的智能处理
	if strings.HasSuffix(strings.ToLower(u), ".sh") || strings.HasSuffix(strings.ToLower(u), ".ps1") {
		isGzipCompressed := resp.Header.Get("Content-Encoding") == "gzip"

		processedBody, processedSize, err := utils.ProcessSmart(responseBody, isGzipCompressed, realHost)
		if err != nil {
			fmt.Printf("脚本处理失败: %v\n", err)
			c.String(http.StatusBadGateway, "Script processing failed: %v", err)
			return
		}

		// 智能设置响应头
		if processedSize > 0 {
			resp.Header.Del("Content-Length")
			resp.Header.Del("Content-Encoding")
			resp.Header.Set("Transfer-Encoding", "chunked")
		}

		// 复制其他响应头
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}

		c.Status(resp.StatusCode)

		// 输出处理后的内容
		if _, err := io.Copy(c.Writer, processedBody); err != nil {
			return
		}
	} else {
		// 复制响应头
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}

		c.Status(resp.StatusCode)

		// 直接流式转发
		if _, err := io.Copy(c.Writer, responseBody); err != nil {
			fmt.Printf("转发响应体失败: %v\n", err)
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

func copyResponseHeaders(c *gin.Context, headers http.Header) {
	for key, values := range headers {
		for _, value := range values {
			c.Header(key, value)
		}
	}
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
	return left != nil && right != nil &&
		strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Host, right.Host)
}

func contentRangeTotal(value string) (int64, bool) {
	unit, rangeAndTotal, ok := strings.Cut(strings.TrimSpace(value), " ")
	if !ok || !strings.EqualFold(unit, "bytes") {
		return 0, false
	}
	rangePart, totalPart, ok := strings.Cut(rangeAndTotal, "/")
	if !ok || rangePart == "" || totalPart == "" || totalPart == "*" {
		return 0, false
	}
	total, err := strconv.ParseInt(totalPart, 10, 64)
	if err != nil || total <= 0 {
		return 0, false
	}
	startPart, endPart, ok := strings.Cut(rangePart, "-")
	if !ok {
		return 0, false
	}
	start, startErr := strconv.ParseInt(startPart, 10, 64)
	end, endErr := strconv.ParseInt(endPart, 10, 64)
	if startErr != nil || endErr != nil || start < 0 || end < start || end >= total {
		return 0, false
	}
	return total, true
}

func validateDirectLinkTarget(ctx context.Context, targetURL *url.URL) ([]netip.Addr, error) {
	if targetURL == nil || !strings.EqualFold(targetURL.Scheme, "https") || targetURL.Hostname() == "" || targetURL.User != nil {
		return nil, fmt.Errorf("通用直链目标必须是无来源凭据的 HTTPS 地址")
	}

	hostname := strings.TrimSuffix(targetURL.Hostname(), ".")
	addresses := make([]netip.Addr, 0, 1)
	if address, err := netip.ParseAddr(hostname); err == nil {
		addresses = append(addresses, address)
	} else {
		asciiHostname, err := idna.Lookup.ToASCII(hostname)
		if err != nil {
			return nil, fmt.Errorf("无效的通用直链主机名")
		}
		hostname = strings.ToLower(asciiHostname)
		resolved, resolveErr := lookupDirectLinkIPs(ctx, "ip", hostname)
		if resolveErr != nil || len(resolved) == 0 {
			return nil, fmt.Errorf("无法解析通用直链目标地址")
		}
		addresses = append(addresses, resolved...)
	}

	validated := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.IsPrivate() {
			return nil, fmt.Errorf("通用直链目标地址不可访问")
		}
		for _, blocked := range blockedDirectLinkNetworks {
			if blocked.Contains(address) {
				return nil, fmt.Errorf("通用直链目标地址不可访问")
			}
		}
		validated = append(validated, address)
	}
	return validated, nil
}
