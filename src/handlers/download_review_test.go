package handlers

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type downloadPipeResponse struct {
	*httptest.ResponseRecorder
	connection net.Conn
	deadlines  int
}

func (r *downloadPipeResponse) SetWriteDeadline(deadline time.Time) error {
	r.deadlines++
	if deadline.After(time.Now().Add(250 * time.Millisecond)) {
		deadline = time.Now().Add(250 * time.Millisecond)
	}
	return r.connection.SetWriteDeadline(deadline)
}

func (r *downloadPipeResponse) Write(p []byte) (int, error) {
	return r.connection.Write(p)
}

func TestDownloadWriterBoundsStalledGinResponses(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // An unknown-length response exercises staging.
		_, _ = w.Write(bytes.Repeat([]byte{'a'}, 2*downloadBlockSize))
	}))
	defer upstream.Close()
	router := newGitHubProxyTestRouter(t, "")
	target := configureDirectLinkTestUpstream(t, upstream, "download.example.org")

	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	raw := &downloadPipeResponse{ResponseRecorder: httptest.NewRecorder(), connection: writer}
	// Accept the first block, then leave the next block waiting for its deadline.
	go func() { _, _ = io.CopyN(io.Discard, reader, downloadBlockSize) }()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		router.ServeHTTP(raw, httptest.NewRequest(http.MethodGet, "/"+target+"/download.zip", nil))
	}()
	select {
	case abort := <-done:
		if abort != http.ErrAbortHandler || raw.deadlines != 2 {
			t.Fatalf("stream aborted with %v after %d deadlines", abort, raw.deadlines)
		}
		if len(directLinkRequestSlots) != 0 || directLinkStagingQuota.used != 0 {
			t.Fatalf("stalled response retained %d slot(s) and %d staged bytes", len(directLinkRequestSlots), directLinkStagingQuota.used)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a stalled download did not return at the write deadline")
	}
}

func TestDownloadDispositionPreservesOnlySafeFilename(t *testing.T) {
	for _, tc := range []struct{ header, name string }{
		{`inline; filename="opaque download.zip"; size=3`, "opaque download.zip"},
		{`attachment; filename=download.zip; filename*=UTF-8''%E8%BD%AF%E4%BB%B6.zip`, "软件.zip"},
		{`inline; filename="../archive.zip"`, ""},
		{`attachment; filename="C:\folder\archive.zip"`, ""},
		{`inline; filename="con.txt"`, ""},
		{`inline; filename*=UTF-8''first%0Asecond`, ""},
		{`inline; filename="unterminated`, ""},
	} {
		disposition, params, err := mime.ParseMediaType(downloadDisposition(tc.header))
		if err != nil || disposition != "attachment" || params["filename"] != tc.name || len(params) > 1 {
			t.Errorf("disposition for %q = %q %v (%v)", tc.header, disposition, params, err)
		}
	}
}

func TestDirectLinkSpecialAddresses(t *testing.T) {
	for _, tc := range []struct {
		host    string
		allowed bool
	}{
		{"[fec0::10]", false}, {"[febf::10]", false}, {"[feff::10]", false},
		{"[64:ff9b:1::12]", false}, {"[64:ff9b::a00:1]", false}, {"[100:0:0:1::12]", false}, {"[4000::1]", false},
		{"[64:ff9b::808:808]", true}, {"[2606:4700:4700::1111]", true},
	} {
		_, _, err := validateDirectLinkTarget(context.Background(), &url.URL{Scheme: "https", Host: tc.host})
		if (err == nil) != tc.allowed {
			t.Errorf("target %s allowed=%t, want %t", tc.host, err == nil, tc.allowed)
		}
	}
}

func TestSameOriginUsesEffectiveAuthorities(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"https://github.com", "https://GITHUB.COM.:0443", true},
		{"https://bücher.example", "https://xn--bcher-kva.example", true},
		{"http://example.org", "http://example.org:80", true},
		{"http://example.org", "http://example.org:443", false},
		{"https://github.com", "https://github.com:8443", false},
		{"https://github.com", "http://github.com", false},
		{"https://github.com", "https://git.example", false},
	} {
		left, err := url.Parse(tc.a)
		if err != nil {
			t.Fatal(err)
		}
		right, err := url.Parse(tc.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := sameOrigin(left, right); got != tc.same {
			t.Errorf("sameOrigin(%s,%s) = %t, want %t", tc.a, tc.b, got, tc.same)
		}
	}
}
