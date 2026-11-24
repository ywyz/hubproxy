package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPackageMirrorServesRepositoryArtifacts(t *testing.T) {
	const repo = "pkgs.omarchy.org/stable/x86_64/"
	const database = "repository database bytes"
	const script = "#!/bin/sh\n# https://github.com/example/project\n"
	const xml = "<repomd><revision>1</revision></repomd>"
	const missing = "<p>Not found</p>"
	const version = `"db-v1"`
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stable/x86_64/omarchy.db":
			w.Header().Set("ETag", version)
			http.ServeContent(w, r, "omarchy.db", time.Time{}, strings.NewReader(database))
		case "/stable/x86_64/repodata/repomd.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(xml))
		case "/stable/x86_64/setup.sh":
			_, _ = w.Write([]byte(script))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(missing))
		}
	}))
	defer upstream.Close()
	router := newGitHubProxyTestRouter(t, `[access]
directLinkWhiteList = ["pkgs.omarchy.org/stable/x86_64/*"]`)
	configureDirectLinkTestUpstream(t, upstream, "pkgs.omarchy.org")

	for _, tc := range []struct {
		name, file string
		header     http.Header
		status     int
		want       string
	}{
		{"pacman database", "omarchy.db", nil, http.StatusOK, database},
		{"cached database", "omarchy.db", http.Header{"If-None-Match": {version}}, http.StatusNotModified, ""},
		{"resumed database", "omarchy.db", http.Header{"Range": {"bytes=0-3"}}, http.StatusPartialContent, database[:4]},
		{"XML metadata", "repodata/repomd.xml", nil, http.StatusOK, xml},
		{"signed repository script", "setup.sh", nil, http.StatusOK, script},
		{"absent signature", "omarchy.db.sig", nil, http.StatusNotFound, missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := performGitHubProxyRequest(router, http.MethodGet, "mirrors/"+repo+tc.file, tc.header)
			if response.Code != tc.status || response.Body.String() != tc.want {
				t.Fatalf("response = %d %q, want %d %q", response.Code, response.Body.String(), tc.status, tc.want)
			}
			if tc.status == http.StatusOK && (response.Header().Get("Content-Type") != "application/octet-stream" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff") {
				t.Fatalf("unexpected attachment headers: %v", response.Header())
			}
		})
	}
}

func TestPackageMirrorUsesDirectAccessListAcrossRedirects(t *testing.T) {
	const target = "github.com/example/project/releases/download/version/package"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+target, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	router := newGitHubProxyTestRouter(t, `[access]
directLinkWhiteList = ["mirror.example.org/packages/*"]
whiteList = ["example/project"]`)
	configureDirectLinkTestUpstream(t, upstream, "mirror.example.org")
	for _, url := range []string{"mirrors/" + target, "mirrors/mirror.example.org/packages/package"} {
		response := performGitHubProxyRequest(router, http.MethodGet, url, nil)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s returned %d, want 403", url, response.Code)
		}
	}
}
