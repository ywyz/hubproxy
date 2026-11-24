package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"hubproxy/config"
	"hubproxy/utils"
)

// DockerProxy Docker代理配置
type DockerProxy struct {
	registry name.Registry
	options  []remote.Option
}

var dockerProxy *DockerProxy

// RegistryDetector Registry检测器
type RegistryDetector struct{}

// detectRegistryDomain 检测Registry域名并返回域名和剩余路径
func (rd *RegistryDetector) detectRegistryDomain(c *gin.Context, path string) (string, string) {
	cfg := config.GetConfig()

	// 兼容Containerd的ns参数
	if ns := c.Query("ns"); ns != "" {
		if mapping, exists := cfg.Registries[ns]; exists && mapping.Enabled {
			return ns, path
		}
	}

	for domain := range cfg.Registries {
		if strings.HasPrefix(path, domain+"/") {
			remainingPath := strings.TrimPrefix(path, domain+"/")
			return domain, remainingPath
		}
	}

	return "", path
}

// isRegistryEnabled 检查Registry是否启用
func (rd *RegistryDetector) isRegistryEnabled(domain string) bool {
	cfg := config.GetConfig()
	if mapping, exists := cfg.Registries[domain]; exists {
		return mapping.Enabled
	}
	return false
}

// getRegistryMapping 获取Registry映射配置
func (rd *RegistryDetector) getRegistryMapping(domain string) (config.RegistryMapping, bool) {
	cfg := config.GetConfig()
	mapping, exists := cfg.Registries[domain]
	return mapping, exists && mapping.Enabled
}

var registryDetector = &RegistryDetector{}

// InitDockerProxy 初始化Docker代理
func InitDockerProxy() {
	registry, err := name.NewRegistry("registry-1.docker.io")
	if err != nil {
		fmt.Printf("创建Docker registry失败: %v\n", err)
		return
	}

	options := []remote.Option{
		remote.WithAuth(authn.Anonymous),
		remote.WithUserAgent("hubproxy/go-containerregistry"),
		remote.WithTransport(utils.GetGlobalHTTPClient().Transport),
	}

	dockerProxy = &DockerProxy{
		registry: registry,
		options:  options,
	}
}

// ProxyDockerRegistryGin 标准Docker Registry API v2代理
func ProxyDockerRegistryGin(c *gin.Context) {
	path := c.Request.URL.Path

	if path == "/v2/" {
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	if strings.HasPrefix(path, "/v2/") {
		handleRegistryRequest(c, path)
	} else {
		c.String(http.StatusNotFound, "Docker Registry API v2 only")
	}
}

// handleRegistryRequest 处理Registry请求
func handleRegistryRequest(c *gin.Context, path string) {
	pathWithoutV2 := strings.TrimPrefix(path, "/v2/")

	if registryDomain, remainingPath := registryDetector.detectRegistryDomain(c, pathWithoutV2); registryDomain != "" {
		if registryDetector.isRegistryEnabled(registryDomain) {
			handleMultiRegistryRequest(c, registryDomain, remainingPath)
			return
		}
	}

	imageName, apiType, reference := parseRegistryPath(pathWithoutV2)
	if imageName == "" || apiType == "" {
		c.String(http.StatusBadRequest, "Invalid path format")
		return
	}

	if !strings.Contains(imageName, "/") {
		imageName = "library/" + imageName
	}

	if allowed, reason := utils.GlobalAccessController.CheckDockerAccess(imageName); !allowed {
		fmt.Printf("Docker镜像 %s 访问被拒绝: %s\n", imageName, reason)
		c.String(http.StatusForbidden, "镜像访问被限制")
		return
	}

	imageRef := fmt.Sprintf("%s/%s", dockerProxy.registry.Name(), imageName)

	switch apiType {
	case "manifests":
		handleManifestRequest(c, imageRef, reference)
	case "blobs":
		handleBlobRequest(c, imageRef, reference, dockerProxy.options)
	case "tags":
		handleTagsRequest(c, imageRef)
	default:
		c.String(http.StatusNotFound, "API endpoint not found")
	}
}

// parseRegistryPath 解析Registry路径
func parseRegistryPath(path string) (imageName, apiType, reference string) {
	if idx := strings.Index(path, "/manifests/"); idx != -1 {
		imageName = path[:idx]
		apiType = "manifests"
		reference = path[idx+len("/manifests/"):]
		return
	}

	if idx := strings.Index(path, "/blobs/"); idx != -1 {
		imageName = path[:idx]
		apiType = "blobs"
		reference = path[idx+len("/blobs/"):]
		return
	}

	if idx := strings.Index(path, "/tags/list"); idx != -1 {
		imageName = path[:idx]
		apiType = "tags"
		reference = "list"
		return
	}

	return "", "", ""
}

// handleManifestRequest 处理manifest请求
func handleManifestRequest(c *gin.Context, imageRef, reference string) {
	if utils.IsCacheEnabled() && c.Request.Method == http.MethodGet {
		cacheKey := utils.BuildManifestCacheKey(imageRef, reference)

		if cachedItem := utils.GlobalCache.Get(cacheKey); cachedItem != nil {
			utils.WriteCachedResponse(c, cachedItem)
			return
		}
	}

	var ref name.Reference
	var err error

	if strings.HasPrefix(reference, "sha256:") {
		ref, err = name.NewDigest(fmt.Sprintf("%s@%s", imageRef, reference))
	} else {
		ref, err = name.NewTag(fmt.Sprintf("%s:%s", imageRef, reference))
	}

	if err != nil {
		fmt.Printf("解析镜像引用失败: %v\n", err)
		c.String(http.StatusBadRequest, "Invalid reference")
		return
	}

	if c.Request.Method == http.MethodHead {
		desc, err := remote.Head(ref, dockerProxy.options...)
		if err != nil {
			fmt.Printf("HEAD请求失败: %v\n", err)
			c.String(http.StatusNotFound, "Manifest not found")
			return
		}

		c.Header("Content-Type", string(desc.MediaType))
		c.Header("Docker-Content-Digest", desc.Digest.String())
		c.Header("Content-Length", fmt.Sprintf("%d", desc.Size))
		c.Status(http.StatusOK)
	} else {
		desc, err := remote.Get(ref, dockerProxy.options...)
		if err != nil {
			fmt.Printf("GET请求失败: %v\n", err)
			c.String(http.StatusNotFound, "Manifest not found")
			return
		}

		headers := map[string]string{
			"Docker-Content-Digest": desc.Digest.String(),
			"Content-Length":        fmt.Sprintf("%d", len(desc.Manifest)),
		}

		if utils.IsCacheEnabled() {
			cacheKey := utils.BuildManifestCacheKey(imageRef, reference)
			ttl := utils.GetManifestTTL(reference)
			utils.GlobalCache.Set(cacheKey, desc.Manifest, string(desc.MediaType), headers, ttl)
		}

		c.Header("Content-Type", string(desc.MediaType))
		for key, value := range headers {
			c.Header(key, value)
		}

		c.Data(http.StatusOK, string(desc.MediaType), desc.Manifest)
	}
}

// remote.Layer verifies the compressed digest, but exposes GET's body and
// only HEAD's metadata. Record the length of the actual GET, including a
// redirect to a registry CDN. Other requests, such as token exchanges and
// registry pings, must not supply a length for the blob.
type blobLengthTransport struct {
	http.RoundTripper
	host, path string
	length     atomic.Int64
}

func (t *blobLengthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(req)
	if err == nil && req.Method == http.MethodGet && resp.StatusCode == http.StatusOK {
		original := req
		for original.Response != nil && original.Response.Request != nil {
			original = original.Response.Request
		}
		if original.URL.Host == t.host && original.URL.Path == t.path {
			t.length.Store(resp.ContentLength)
		}
	}
	return resp, err
}

func writeRegistryBlobError(c *gin.Context, err error) {
	status := http.StatusBadGateway
	var upstream *transport.Error
	if errors.As(err, &upstream) && upstream.StatusCode >= 400 && upstream.StatusCode <= 599 {
		status = upstream.StatusCode
		// Blob fetches authenticate to the registry as HubProxy's upstream
		// identity. The client's download password cannot satisfy that challenge.
		if status == http.StatusUnauthorized {
			status = http.StatusForbidden
		}
	}
	c.String(status, "Registry blob: %s", http.StatusText(status))
}

func handleBlobRequest(c *gin.Context, imageRef, digest string, options []remote.Option) {
	authenticated := DownloadAuthenticated(c)
	if authenticated {
		c.Header("Cache-Control", "private, no-store")
	}
	digestRef, err := name.NewDigest(fmt.Sprintf("%s@%s", imageRef, digest))
	if err != nil {
		fmt.Printf("解析digest引用失败: %v\n", err)
		c.String(http.StatusBadRequest, "Invalid digest reference")
		return
	}

	repo := digestRef.Context()
	blobTransport := &blobLengthTransport{
		RoundTripper: utils.GetGlobalHTTPClient().Transport,
		host:         repo.RegistryStr(),
		path:         "/v2/" + repo.RepositoryStr() + "/blobs/" + digest,
	}
	blobTransport.length.Store(-1)
	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()
	options = append(options[:len(options):len(options)], remote.WithTransport(blobTransport), remote.WithContext(ctx))
	layer, err := remote.Layer(digestRef, options...)
	if err != nil {
		writeRegistryBlobError(c, err)
		return
	}
	var size int64
	var body io.Reader
	if c.Request.Method == http.MethodHead {
		size, err = layer.Size()
		if err != nil {
			writeRegistryBlobError(c, err)
			return
		}
	} else {
		reader, err := layer.Compressed()
		if err != nil {
			writeRegistryBlobError(c, err)
			return
		}
		stream := newDirectLinkIdleReadCloser(reader, directLinkBodyIdleTimeout, cancel)
		defer stream.Close()
		body = stream
		size = blobTransport.length.Load()
		if !authenticated && size < 0 {
			staged, err := stageAnonymousDownload(func(w *directLinkQuotaWriter) error {
				_, err := io.Copy(w, io.LimitReader(stream, anonymousDownloadLimit()+1))
				return err
			})
			if err != nil {
				if stream.timedOut.Load() {
					c.String(http.StatusGatewayTimeout, "Registry blob timed out")
				} else if !handleDownloadStageError(c, err) {
					writeRegistryBlobError(c, err)
				}
				return
			}
			defer staged.cleanup()
			body, size = staged, staged.size
		}
	}
	if !authenticated && size > anonymousDownloadLimit() {
		RequireDownloadLogin(c)
		return
	}
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Docker-Content-Digest", digest)
	if size >= 0 {
		c.Header("Content-Length", fmt.Sprint(size))
	}
	c.Status(http.StatusOK)
	if body != nil {
		if err := copyVerifiedBlob(c.Writer, body, size); err != nil {
			log.Printf("复制镜像层失败: %v", err)
			if c.Writer.Written() {
				panic(http.ErrAbortHandler)
			}
			removeResponseEntityHeaders(c.Writer.Header())
			c.Header("Docker-Content-Digest", "")
			writeRegistryBlobError(c, err)
		}
	}
}

func copyVerifiedBlob(w http.ResponseWriter, body io.Reader, size int64) error {
	if size <= 0 {
		_, err := copyDownloadResponse(w, body)
		return err
	}
	// remote.Layer verifies the digest at EOF. Once Content-Length bytes
	// reach a client, even closing the connection cannot signal a bad digest.
	// Hold just the last byte until verification has finished.
	n, err := copyDownloadResponse(w, io.LimitReader(body, size-1))
	if err != nil {
		return err
	}
	if n != size-1 {
		return io.ErrUnexpectedEOF
	}
	tail, err := io.ReadAll(io.LimitReader(body, 2))
	if err != nil {
		return err
	}
	if len(tail) != 1 {
		return fmt.Errorf("unexpected blob length")
	}
	_, err = downloadResponseWriter(w).Write(tail)
	return err
}

// handleTagsRequest 处理tags列表请求
func handleTagsRequest(c *gin.Context, imageRef string) {
	repo, err := name.NewRepository(imageRef)
	if err != nil {
		fmt.Printf("解析repository失败: %v\n", err)
		c.String(http.StatusBadRequest, "Invalid repository")
		return
	}

	tags, err := remote.List(repo, dockerProxy.options...)
	if err != nil {
		fmt.Printf("获取tags失败: %v\n", err)
		c.String(http.StatusNotFound, "Tags not found")
		return
	}

	response := map[string]interface{}{
		"name": strings.TrimPrefix(imageRef, dockerProxy.registry.Name()+"/"),
		"tags": tags,
	}

	c.JSON(http.StatusOK, response)
}

// ProxyDockerAuthGin Docker认证代理
func ProxyDockerAuthGin(c *gin.Context) {
	if utils.IsTokenCacheEnabled() {
		proxyDockerAuthWithCache(c)
	} else {
		proxyDockerAuthOriginal(c)
	}
}

// proxyDockerAuthWithCache 带缓存的认证代理
func proxyDockerAuthWithCache(c *gin.Context) {
	cacheKey := utils.BuildTokenCacheKey(c.Request.URL.RawQuery)

	if cachedToken := utils.GlobalCache.GetToken(cacheKey); cachedToken != "" {
		utils.WriteTokenResponse(c, cachedToken)
		return
	}

	recorder := &ResponseRecorder{
		ResponseWriter: c.Writer,
		statusCode:     200,
	}
	c.Writer = recorder

	proxyDockerAuthOriginal(c)

	if recorder.statusCode == 200 && len(recorder.body) > 0 {
		ttl := utils.ExtractTTLFromResponse(recorder.body)
		utils.GlobalCache.SetToken(cacheKey, string(recorder.body), ttl)
	}

	c.Writer = recorder.ResponseWriter
	c.Data(recorder.statusCode, "application/json", recorder.body)
}

// ResponseRecorder HTTP响应记录器
type ResponseRecorder struct {
	gin.ResponseWriter
	statusCode int
	body       []byte
}

func (r *ResponseRecorder) WriteHeader(code int) {
	r.statusCode = code
}

func (r *ResponseRecorder) Write(data []byte) (int, error) {
	r.body = append(r.body, data...)
	return len(data), nil
}

func proxyDockerAuthOriginal(c *gin.Context) {
	authURL := buildDockerAuthURL(c)

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: utils.GetGlobalHTTPClient().Transport,
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		c.Request.Method,
		authURL,
		c.Request.Body,
	)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to create request")
		return
	}

	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		c.String(http.StatusBadGateway, "Auth request failed")
		return
	}
	defer resp.Body.Close()

	proxyHost := c.Request.Host
	if proxyHost == "" {
		cfg := config.GetConfig()
		proxyHost = fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		if cfg.Server.Host == "0.0.0.0" {
			proxyHost = fmt.Sprintf("localhost:%d", cfg.Server.Port)
		}
	}

	for key, values := range resp.Header {
		for _, value := range values {
			if key == "Www-Authenticate" {
				value = rewriteAuthHeader(value, proxyHost)
			}
			c.Header(key, value)
		}
	}

	c.Status(resp.StatusCode)
	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		fmt.Printf("复制认证响应失败: %v\n", err)
	}
}

// buildDockerAuthURL 根据 token 请求的 service 参数选择上游认证地址。
// AuthHost 已包含路径（如 ghcr.io/token、quay.io/v2/auth），不再拼接本机 Path，避免 /token/token。
func buildDockerAuthURL(c *gin.Context) string {
	authHost := resolveAuthHost(c.Query("service"))
	var authURL string
	if authHost != "" {
		authURL = "https://" + authHost
	} else {
		authURL = "https://auth.docker.io" + c.Request.URL.Path
	}
	if c.Request.URL.RawQuery != "" {
		authURL += "?" + c.Request.URL.RawQuery
	}
	return authURL
}

// resolveAuthHost 用 service 匹配已启用 Registry 的 AuthHost；Docker Hub 返回空串走默认路径。
func resolveAuthHost(service string) string {
	if service == "" || service == "registry.docker.io" || service == "docker.io" {
		return ""
	}

	cfg := config.GetConfig()
	for domain, mapping := range cfg.Registries {
		if !mapping.Enabled || mapping.AuthHost == "" {
			continue
		}
		if service == domain || service == mapping.Upstream {
			return mapping.AuthHost
		}
	}
	return ""
}

// rewriteAuthHeader 将上游认证 realm 统一改写到本机 /token，避免 quay 等变成 /v2/auth 误入 Registry 路由。
func rewriteAuthHeader(authHeader, proxyHost string) string {
	proxyToken := "http://" + proxyHost + "/token"

	cfg := config.GetConfig()
	for _, mapping := range cfg.Registries {
		if mapping.AuthHost == "" {
			continue
		}
		authHeader = strings.ReplaceAll(authHeader, "https://"+mapping.AuthHost, proxyToken)
	}
	authHeader = strings.ReplaceAll(authHeader, "https://auth.docker.io/token", proxyToken)
	authHeader = strings.ReplaceAll(authHeader, "https://auth.docker.io", "http://"+proxyHost)

	return authHeader
}

// handleMultiRegistryRequest 处理多Registry请求
func handleMultiRegistryRequest(c *gin.Context, registryDomain, remainingPath string) {
	mapping, exists := registryDetector.getRegistryMapping(registryDomain)
	if !exists {
		c.String(http.StatusBadRequest, "Registry not configured")
		return
	}

	imageName, apiType, reference := parseRegistryPath(remainingPath)
	if imageName == "" || apiType == "" {
		c.String(http.StatusBadRequest, "Invalid path format")
		return
	}

	fullImageName := registryDomain + "/" + imageName
	if allowed, reason := utils.GlobalAccessController.CheckDockerAccess(fullImageName); !allowed {
		fmt.Printf("镜像 %s 访问被拒绝: %s\n", fullImageName, reason)
		c.String(http.StatusForbidden, "镜像访问被限制")
		return
	}

	upstreamImageRef := fmt.Sprintf("%s/%s", mapping.Upstream, imageName)

	switch apiType {
	case "manifests":
		handleUpstreamManifestRequest(c, upstreamImageRef, reference, mapping)
	case "blobs":
		handleBlobRequest(c, upstreamImageRef, reference, createUpstreamOptions(mapping))
	case "tags":
		handleUpstreamTagsRequest(c, upstreamImageRef, mapping)
	default:
		c.String(http.StatusNotFound, "API endpoint not found")
	}
}

// handleUpstreamManifestRequest 处理上游Registry的manifest请求
func handleUpstreamManifestRequest(c *gin.Context, imageRef, reference string, mapping config.RegistryMapping) {
	if utils.IsCacheEnabled() && c.Request.Method == http.MethodGet {
		cacheKey := utils.BuildManifestCacheKey(imageRef, reference)

		if cachedItem := utils.GlobalCache.Get(cacheKey); cachedItem != nil {
			utils.WriteCachedResponse(c, cachedItem)
			return
		}
	}

	var ref name.Reference
	var err error

	if strings.HasPrefix(reference, "sha256:") {
		ref, err = name.NewDigest(fmt.Sprintf("%s@%s", imageRef, reference))
	} else {
		ref, err = name.NewTag(fmt.Sprintf("%s:%s", imageRef, reference))
	}

	if err != nil {
		fmt.Printf("解析镜像引用失败: %v\n", err)
		c.String(http.StatusBadRequest, "Invalid reference")
		return
	}

	options := createUpstreamOptions(mapping)

	if c.Request.Method == http.MethodHead {
		desc, err := remote.Head(ref, options...)
		if err != nil {
			fmt.Printf("HEAD请求失败: %v\n", err)
			c.String(http.StatusNotFound, "Manifest not found")
			return
		}

		c.Header("Content-Type", string(desc.MediaType))
		c.Header("Docker-Content-Digest", desc.Digest.String())
		c.Header("Content-Length", fmt.Sprintf("%d", desc.Size))
		c.Status(http.StatusOK)
	} else {
		desc, err := remote.Get(ref, options...)
		if err != nil {
			fmt.Printf("GET请求失败: %v\n", err)
			c.String(http.StatusNotFound, "Manifest not found")
			return
		}

		headers := map[string]string{
			"Docker-Content-Digest": desc.Digest.String(),
			"Content-Length":        fmt.Sprintf("%d", len(desc.Manifest)),
		}

		if utils.IsCacheEnabled() {
			cacheKey := utils.BuildManifestCacheKey(imageRef, reference)
			ttl := utils.GetManifestTTL(reference)
			utils.GlobalCache.Set(cacheKey, desc.Manifest, string(desc.MediaType), headers, ttl)
		}

		c.Header("Content-Type", string(desc.MediaType))
		for key, value := range headers {
			c.Header(key, value)
		}

		c.Data(http.StatusOK, string(desc.MediaType), desc.Manifest)
	}
}

// handleUpstreamTagsRequest 处理上游Registry的tags请求
func handleUpstreamTagsRequest(c *gin.Context, imageRef string, mapping config.RegistryMapping) {
	repo, err := name.NewRepository(imageRef)
	if err != nil {
		fmt.Printf("解析repository失败: %v\n", err)
		c.String(http.StatusBadRequest, "Invalid repository")
		return
	}

	options := createUpstreamOptions(mapping)
	tags, err := remote.List(repo, options...)
	if err != nil {
		fmt.Printf("获取tags失败: %v\n", err)
		c.String(http.StatusNotFound, "Tags not found")
		return
	}

	response := map[string]interface{}{
		"name": strings.TrimPrefix(imageRef, mapping.Upstream+"/"),
		"tags": tags,
	}

	c.JSON(http.StatusOK, response)
}

// createUpstreamOptions 创建上游Registry选项
func createUpstreamOptions(mapping config.RegistryMapping) []remote.Option {
	options := []remote.Option{
		remote.WithAuth(authn.Anonymous),
		remote.WithUserAgent("hubproxy/go-containerregistry"),
		remote.WithTransport(utils.GetGlobalHTTPClient().Transport),
	}

	// 预留将来不同Registry的差异化认证逻辑扩展点
	switch mapping.AuthType {
	case "github":
	case "google":
	case "quay":
	}

	return options
}
