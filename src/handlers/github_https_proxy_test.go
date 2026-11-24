package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hubproxy/utils"
)

func newNamedTLSTestServer(t *testing.T, hostname string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestDirectLinkThroughHTTPSProxyVerifiesBothTLSNames(t *testing.T) {
	const proxyName = "proxy.example.test"
	const downloadName = "downloads.example.test"
	origin := newNamedTLSTestServer(t, downloadName, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != downloadName || r.TLS.ServerName != downloadName {
			t.Errorf("origin Host = %q, TLS name = %q, want %q", r.Host, r.TLS.ServerName, downloadName)
		}
		_, _ = io.WriteString(w, "download")
	})
	proxy := newNamedTLSTestServer(t, proxyName, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "93.184.216.34:443" || r.TLS.ServerName != proxyName {
			t.Errorf("proxy got %s %q with TLS name %q", r.Method, r.Host, r.TLS.ServerName)
			http.Error(w, "unexpected tunnel", http.StatusBadRequest)
			return
		}
		upstream, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer client.Close()
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		go func() {
			_, _ = io.Copy(upstream, buffered.Reader)
			upstream.Close()
		}()
		_, _ = io.Copy(client, upstream)
	})
	roots := x509.NewCertPool()
	roots.AddCert(proxy.Certificate())
	roots.AddCert(origin.Certificate())

	for _, tc := range []struct {
		name, proxyHost, originHost, invalidHost string
	}{
		{"matching names", proxyName, downloadName, ""},
		{"wrong proxy name", "other-proxy.example.test", downloadName, "other-proxy.example.test"},
		{"wrong destination name", proxyName, "other-download.example.test", "other-download.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := newGitHubProxyTestRouter(t, "")
			routeGlobalHTTPClientToTestUpstream(t, proxy, tc.originHost)
			transport := utils.GetGlobalHTTPClient().Transport.(*http.Transport)
			transport.TLSClientConfig = &tls.Config{RootCAs: roots}
			proxyHostPort := net.JoinHostPort(tc.proxyHost, "443")
			transport.Proxy = http.ProxyURL(&url.URL{Scheme: "https", Host: proxyHostPort})
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr != proxyHostPort {
					return nil, fmt.Errorf("dialed %q, want proxy %q", addr, proxyHostPort)
				}
				return (&net.Dialer{}).DialContext(ctx, network, proxy.Listener.Addr().String())
			}
			res := performGitHubProxyRequest(router, http.MethodGet, "https://"+tc.originHost+"/file.bin", nil)
			if tc.invalidHost != "" {
				if res.Code == http.StatusOK || !strings.Contains(res.Body.String(), "certificate") || !strings.Contains(res.Body.String(), tc.invalidHost) {
					t.Fatalf("want certificate rejection for %s, got %d %q", tc.invalidHost, res.Code, res.Body.String())
				}
				return
			}
			if res.Code != http.StatusOK || res.Body.String() != "download" {
				t.Fatalf("response = %d %q, want 200 download", res.Code, res.Body.String())
			}
		})
	}
}
