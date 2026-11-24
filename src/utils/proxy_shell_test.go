package utils

import (
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

func TestProcessSmartRewritesGitHubURLs(t *testing.T) {
	input := `curl -L https://github.com/user/repo/releases/download/v1/file.sh`
	reader, size, err := ProcessSmart(strings.NewReader(input), false, "proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Fatal(err)
	}

	want := "https://proxy.example.com/https://github.com/user/repo/releases/download/v1/file.sh"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("processed script = %q, want contains %q", buf.String(), want)
	}
	if size != int64(len(buf.String())) {
		t.Fatalf("size = %d, want %d", size, len(buf.String()))
	}
}

func TestProcessSmartKeepsNonGitHubContent(t *testing.T) {
	input := "echo hello"
	reader, _, err := ProcessSmart(strings.NewReader(input), false, "proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Fatal(err)
	}
	if buf.String() != input {
		t.Fatalf("content changed: %q", buf.String())
	}
}

func TestReadShellContentGzip(t *testing.T) {
	var compressed strings.Builder
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write([]byte("echo https://github.com/u/r")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	reader, _, err := ProcessSmart(strings.NewReader(compressed.String()), true, "proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "https://proxy.example.com/https://github.com/u/r") {
		t.Fatalf("gzip content not rewritten: %q", buf.String())
	}
}

func TestProcessSmartValidatesAuthority(t *testing.T) {
	const script = "fetch http://github.com/u/r"
	for _, host := range []string{"https://user@proxy.example", "https://proxy.example/path", "proxy.example:65536", "bad name", "my(host).example", "host?x=1"} {
		if _, _, err := ProcessSmart(strings.NewReader(script), false, host); err == nil {
			t.Errorf("accepted invalid shell origin %q", host)
		}
	}
	for _, host := range []string{"proxy.example:8443", "[2001:db8::1]:8443"} {
		reader, _, err := ProcessSmart(strings.NewReader(script), false, host)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(reader)
		if want := "fetch https://" + host + "/https://github.com/u/r"; err != nil || string(b) != want {
			t.Errorf("incorrect proxy authority for %q: %q, %v", host, b, err)
		}
	}
}

func TestProcessSmartBoundsRewrittenScript(t *testing.T) {
	const link = "https://github.com/u/r "
	const origin = "https://proxy.example"
	// The complete transformed script fits exactly, then exceeds the limit by one.
	script := link + strings.Repeat("x", MaxShellSize-len(link)-len(origin)-1)
	if _, size, err := ProcessSmart(strings.NewReader(script), false, origin); err != nil || size != MaxShellSize {
		t.Fatalf("exact limit: size %d, error %v", size, err)
	}
	if _, _, err := ProcessSmart(strings.NewReader(script+"x"), false, origin); err == nil {
		t.Fatal("accepted an oversized rewritten script")
	}
}
