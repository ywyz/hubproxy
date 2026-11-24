package utils

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// GitHub URL正则表达式
var githubRegex = regexp.MustCompile(`(?:^|[\s'"(=,\[{;|&<>])(https?://(?:github\.com|raw\.githubusercontent\.com|raw\.github\.com|gist\.githubusercontent\.com|gist\.github\.com|api\.github\.com)/[^\s'")]*)`)
var shellHostLabel = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// MaxShellSize 限制最大处理大小为 10MB
const MaxShellSize = 10 * 1024 * 1024

// ProcessSmart Shell脚本智能处理函数
func ProcessSmart(input io.Reader, isCompressed bool, host string) (io.Reader, int64, error) {
	content, err := readShellContent(input, isCompressed)
	if err != nil {
		return nil, 0, err
	}

	if len(content) == 0 {
		return strings.NewReader(""), 0, nil
	}

	if !bytes.Contains(content, []byte("github.com")) && !bytes.Contains(content, []byte("githubusercontent.com")) {
		return bytes.NewReader(content), int64(len(content)), nil
	}

	origin, ok := shellProxyOrigin(host)
	if !ok {
		return nil, 0, fmt.Errorf("无效的脚本代理主机名")
	}
	processed, err := processGitHubURLs(content, origin)
	if err != nil {
		return nil, 0, err
	}
	return bytes.NewReader(processed), int64(len(processed)), nil
}

func readShellContent(input io.Reader, isCompressed bool) ([]byte, error) {
	var reader io.Reader = input

	if isCompressed {
		peek := make([]byte, 2)
		n, err := input.Read(peek)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("读取数据失败: %v", err)
		}

		if n >= 2 && peek[0] == 0x1f && peek[1] == 0x8b {
			combinedReader := io.MultiReader(bytes.NewReader(peek[:n]), input)
			gzReader, err := gzip.NewReader(combinedReader)
			if err != nil {
				return nil, fmt.Errorf("gzip解压失败: %v", err)
			}
			defer gzReader.Close()
			reader = gzReader
		} else {
			reader = io.MultiReader(bytes.NewReader(peek[:n]), input)
		}
	}

	limit := int64(MaxShellSize + 1)
	limitedReader := io.LimitReader(reader, limit)

	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("读取内容失败: %v", err)
	}

	if int64(len(data)) > MaxShellSize {
		return nil, fmt.Errorf("脚本文件过大，超过 %d MB 限制", MaxShellSize/1024/1024)
	}

	return data, nil
}

// Only a DNS name or IP literal and an optional numeric port may enter shell
// source. URL authorities can otherwise contain characters significant to a shell.
func shellProxyOrigin(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > 280 {
		return "", false
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.User != nil ||
		u.Host == "" || u.Path != "" && u.Path != "/" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	hostname := u.Hostname()
	if addr, err := netip.ParseAddr(hostname); err == nil {
		if addr.Zone() != "" {
			return "", false
		}
		hostname = addr.String()
		if addr.Is6() {
			hostname = "[" + hostname + "]"
		}
	} else {
		domain := strings.TrimSuffix(hostname, ".")
		if len(domain) > 253 {
			return "", false
		}
		for _, label := range strings.Split(domain, ".") {
			if !shellHostLabel.MatchString(label) {
				return "", false
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", false
		}
		hostname += ":" + strconv.FormatUint(n, 10)
	}
	return u.Scheme + "://" + hostname, true
}

func processGitHubURLs(content []byte, origin string) ([]byte, error) {
	var out bytes.Buffer
	size := len(content)
	offset := 0
	for {
		match := githubRegex.FindSubmatchIndex(content[offset:])
		if match == nil {
			break
		}
		start, end := offset+match[2], offset+match[3]
		target := content[start:end]
		size += len(origin) + 1
		upgrade := bytes.HasPrefix(target, []byte("http://"))
		if upgrade {
			size++
		}
		if size > MaxShellSize {
			return nil, fmt.Errorf("改写后的脚本超过大小限制")
		}
		out.Write(content[offset:start])
		out.WriteString(origin)
		out.WriteByte('/')
		if upgrade {
			out.WriteString("https")
			target = target[len("http"):]
		}
		out.Write(target)
		offset = end
	}
	if offset == 0 {
		return content, nil
	}
	out.Write(content[offset:])
	return out.Bytes(), nil
}
