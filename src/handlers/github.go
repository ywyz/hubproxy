package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
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
		// 捕获域名和路径，使现有 access 黑白名单仍可限制任意直链。
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
		allowed, reason := utils.GlobalAccessController.CheckGitHubAccess(matches)
		if directLink {
			allowed, reason = utils.GlobalAccessController.CheckDirectLinkAccess(matches)
		}
		if !allowed {
			var repoPath string
			if len(matches) >= 2 {
				username := matches[0]
				repoName := strings.TrimSuffix(matches[1], ".git")
				repoPath = username + "/" + repoName
			}
			fmt.Printf("GitHub仓库 %s 访问被拒绝: %s\n", repoPath, reason)
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
	for index, exp := range githubExps {
		if matches := exp.FindStringSubmatch(u); matches != nil {
			return matches[1:], index == len(githubExps)-1
		}
	}
	return nil, false
}

// ProxyGitHubRequest 代理GitHub请求
func ProxyGitHubRequest(c *gin.Context, u string) {
	_, directLink := matchGitHubURL(u)
	proxyGitHubWithRedirect(c, u, 0, directLink, true)
}

// proxyGitHubWithRedirect 带重定向的GitHub代理请求
func proxyGitHubWithRedirect(c *gin.Context, u string, redirectCount int, directLink, forwardSourceCredentials bool) {
	const maxRedirects = 20
	if redirectCount > maxRedirects {
		c.String(http.StatusLoopDetected, "重定向次数过多，可能存在循环重定向")
		return
	}
	var directTargetAddress netip.Addr
	if directLink {
		targetURL, err := url.Parse(u)
		if err != nil {
			c.String(http.StatusForbidden, "无效的通用直链地址")
			return
		}
		directTargetAddress, err = validateDirectLinkTarget(c.Request.Context(), targetURL)
		if err != nil {
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

	req, err := http.NewRequest(c.Request.Method, u, c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("server error %v", err))
		return
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

	httpClient := *utils.GetGlobalHTTPClient()
	if directLink {
		transport, ok := httpClient.Transport.(*http.Transport)
		if !ok {
			c.String(http.StatusInternalServerError, "通用直链 HTTP 传输配置无效")
			return
		}
		transport = transport.Clone()
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
		req.URL.Host = net.JoinHostPort(directTargetAddress.String(), port)
		httpClient.Transport = transport
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := httpClient.Do(req)
	if err != nil {
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
			proxyGitHubWithRedirect(c, nextURL.String(), redirectCount+1, true, false)
			return
		}

		if matches != nil && !nextIsDirectLink {
			copyResponseHeaders(c, resp.Header)
			c.Header("Location", "/"+nextURL.String())
			c.Status(resp.StatusCode)
			return
		}

		keepCredentials := forwardSourceCredentials && sameOrigin(currentURL, nextURL)
		_ = resp.Body.Close()
		proxyGitHubWithRedirect(c, nextURL.String(), redirectCount+1, false, keepCredentials)
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
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil && size > cfg.Server.FileSize {
			c.String(http.StatusRequestEntityTooLarge,
				fmt.Sprintf("文件过大，限制大小: %d MB", cfg.Server.FileSize/(1024*1024)))
			return
		}
	}

	responseBody := io.Reader(resp.Body)
	if directLink && c.Request.Method == http.MethodGet {
		staged, err := os.CreateTemp("", "hubproxy-direct-*")
		if err != nil {
			c.String(http.StatusInternalServerError, "无法暂存直链响应")
			return
		}
		stagedName := staged.Name()
		defer func() {
			if err := staged.Close(); err != nil {
				fmt.Printf("关闭直链临时文件失败: %v\n", err)
			}
			if err := os.Remove(stagedName); err != nil && !os.IsNotExist(err) {
				fmt.Printf("删除直链临时文件失败: %v\n", err)
			}
		}()

		limit := cfg.Server.FileSize
		if limit <= 0 {
			c.String(http.StatusRequestEntityTooLarge, "文件大小限制无效")
			return
		}
		written, copyErr := io.Copy(staged, io.LimitReader(resp.Body, limit+1))
		if copyErr != nil {
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

	// 清理安全相关的头
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Referrer-Policy")
	resp.Header.Del("Strict-Transport-Security")

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

func copyResponseHeaders(c *gin.Context, headers http.Header) {
	for key, values := range headers {
		for _, value := range values {
			c.Header(key, value)
		}
	}
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil &&
		strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Host, right.Host)
}

func validateDirectLinkTarget(ctx context.Context, targetURL *url.URL) (netip.Addr, error) {
	if targetURL == nil || !strings.EqualFold(targetURL.Scheme, "https") || targetURL.Hostname() == "" || targetURL.User != nil {
		return netip.Addr{}, fmt.Errorf("通用直链目标必须是无来源凭据的 HTTPS 地址")
	}

	hostname := strings.TrimSuffix(targetURL.Hostname(), ".")
	addresses := make([]netip.Addr, 0, 1)
	if address, err := netip.ParseAddr(hostname); err == nil {
		addresses = append(addresses, address)
	} else {
		resolved, resolveErr := lookupDirectLinkIPs(ctx, "ip", hostname)
		if resolveErr != nil || len(resolved) == 0 {
			return netip.Addr{}, fmt.Errorf("无法解析通用直链目标地址")
		}
		addresses = append(addresses, resolved...)
	}

	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.IsPrivate() {
			return netip.Addr{}, fmt.Errorf("通用直链目标地址不可访问")
		}
		for _, blocked := range blockedDirectLinkNetworks {
			if blocked.Contains(address) {
				return netip.Addr{}, fmt.Errorf("通用直链目标地址不可访问")
			}
		}
	}
	return addresses[0].Unmap(), nil
}
