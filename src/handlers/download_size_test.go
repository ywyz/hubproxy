package handlers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestLargeFileLoginAndResume(t *testing.T) {
	const size = maxAnonymousFileSize + 17
	const creds = "[downloadAuth]\nusername='reader'\npassword='test-password'\n"
	for _, tc := range []struct{ name, target string }{
		{"GitHub", "https://github.com/owner/repo/releases/download/v1/file.bin"},
		{"HuggingFace", "https://huggingface.co/owner/repo/resolve/main/file.bin"},
		{"direct", "https://packages.example.org/files/file.bin"},
		{"mirror", "mirrors/packages.example.org/repository/file.bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := newGitHubProxyTestRouter(t, creds)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("local download credentials reached the upstream")
				}
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.Header().Set("Accept-Ranges", "bytes")
				w.Header().Set("Content-Type", "application/octet-stream")
				if r.Header.Get("Range") == "" {
					w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
					return
				}
				var offset int64
				if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-", &offset); err != nil {
					t.Errorf("could not parse request range: %v", err)
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset, size))
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte{byte(offset)})
			}))
			defer server.Close()
			configureDirectLinkTestUpstream(t, server, "packages.example.org")
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				w := performGitHubProxyRequest(router, method, tc.target, nil)
				if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "Basic") {
					t.Fatalf("anonymous %s: %d %v", method, w.Code, w.Header())
				}
			}
			results := make(chan error, 3)
			for _, offset := range []int64{0, maxAnonymousFileSize, size - 1} {
				go func() {
					headers := http.Header{"Range": {fmt.Sprintf("bytes=%d-%d", offset, offset)}}
					w := performGitHubProxyRequest(router, http.MethodGet, tc.target, headers)
					if w.Code != http.StatusUnauthorized {
						results <- fmt.Errorf("anonymous range at %d: %d", offset, w.Code)
						return
					}
					headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("reader:test-password")))
					w = performGitHubProxyRequest(router, http.MethodGet, tc.target, headers)
					wantRange := fmt.Sprintf("bytes %d-%d/%d", offset, offset, size)
					if w.Code != http.StatusPartialContent || w.Header().Get("Content-Range") != wantRange ||
						w.Body.Len() != 1 || w.Body.Bytes()[0] != byte(offset) ||
						w.Header().Get("Cache-Control") != "private, no-store" {
						results <- fmt.Errorf("authenticated range at %d: %d %v %q", offset, w.Code, w.Header(), w.Body.String())
						return
					}
					results <- nil
				}()
			}
			for range 3 {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestUnknownLengthDownloads(t *testing.T) {
	router := newGitHubProxyTestRouter(t, "[server]\nfileSize=4\n[downloadAuth]\nusername='reader'\npassword='test-password'\n")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, r.URL.Query().Get("body"))
	}))
	defer server.Close()
	routeGlobalHTTPClientToTestUpstream(t, server)
	const target = "https://huggingface.co/owner/repo/resolve/main/file?body="
	for _, tc := range []struct {
		body  string
		login bool
		want  int
	}{
		{"1234", false, 200}, {"12345", false, 401}, {"12345", true, 200},
	} {
		h := http.Header{}
		if tc.login {
			h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("reader:test-password")))
		}
		w := performGitHubProxyRequest(router, http.MethodGet, target+tc.body, h)
		if w.Code != tc.want || (tc.want == 200 && w.Body.String() != tc.body) ||
			(tc.want == 401 && strings.Contains(w.Body.String(), tc.body)) {
			t.Errorf("size %d login=%v: %d %q", len(tc.body), tc.login, w.Code, w.Body.String())
		}
	}
}

func TestChunkedPartialDownload(t *testing.T) {
	router := newGitHubProxyTestRouter(t, "[server]\nfileSize=4\n[downloadAuth]\nusername='reader'\npassword='test-password'\n")
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 1-2/"+r.URL.Query().Get("total"))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusPartialContent)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, r.URL.Query().Get("body"))
	}))
	defer upstream.Close()
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	for _, tc := range []struct {
		total, body string
		login       bool
		status      int
	}{
		{"4", "BC", false, 206}, {"4", "B", false, 502}, {"4", "BCD", false, 502},
		{"*", "BC", false, 401}, {"*", "BC", true, 206}, {"5", "BC", false, 401}, {"5", "BC", true, 206},
	} {
		headers := http.Header{"Range": {"bytes=1-2"}}
		if tc.login {
			headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("reader:test-password")))
		}
		target := "https://huggingface.co/owner/repo/resolve/main/file?total=" + tc.total + "&body=" + tc.body
		w := performGitHubProxyRequest(router, http.MethodGet, target, headers)
		if w.Code != tc.status || (w.Code == 206 && (w.Header().Get("Content-Length") != "2" || w.Body.String() != "BC")) {
			t.Errorf("total=%s body=%q login=%v: %d %v %q", tc.total, tc.body, tc.login, w.Code, w.Header(), w.Body.String())
		}
	}
}

func TestDownloadResponseIsolatesProxyOrigin(t *testing.T) {
	router := newGitHubProxyTestRouter(t, "")
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/livescript")
		w.Header().Set("Connection", "X-Origin-Private")
		w.Header().Set("X-Origin-Private", "upstream-only")
		w.Header().Set("X-Accel-Redirect", "/internal")
		w.Header().Set("X-Accel-Expires", "3600")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Alt-Svc", "clear")
		w.Header().Set("Set-Cookie", "upstream=value")
		_, _ = io.WriteString(w, "file contents")
	}))
	defer upstream.Close()
	routeGlobalHTTPClientToTestUpstream(t, upstream)
	w := performGitHubProxyRequest(router, http.MethodGet, "https://huggingface.co/owner/repo/resolve/main/file", nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") || w.Body.String() != "file contents" {
		t.Fatalf("attachment response: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	for _, key := range []string{"X-Accel-Redirect", "X-Accel-Expires", "X-Origin-Private", "Access-Control-Allow-Origin", "Alt-Svc", "Set-Cookie"} {
		if w.Header().Get(key) != "" {
			t.Errorf("unexpected upstream header %s", key)
		}
	}
}
