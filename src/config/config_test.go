package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigUsesConfigPathAndEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.toml")
	data := []byte(`
[server]
host = "127.0.0.1"
port = 5999

[access]
whiteList = ["legacy/*"]
blackList = ["legacy/blocked"]
directLinkWhiteList = ["downloads.example.com/files/*"]
directLinkBlackList = ["downloads.example.com/files/private/*"]
proxy = "socks5://127.0.0.1:1080"
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFIG_PATH", path)
	t.Setenv("SERVER_PORT", "6001")
	t.Setenv("ACCESS_PROXY", "")

	if err := LoadConfig(); err != nil {
		t.Fatal(err)
	}

	cfg := GetConfig()
	if cfg.Server.Host != "127.0.0.1" {
		t.Fatalf("Server.Host = %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 6001 {
		t.Fatalf("Server.Port = %d, want 6001", cfg.Server.Port)
	}
	if cfg.Access.Proxy != "" {
		t.Fatalf("Access.Proxy = %q, want empty override", cfg.Access.Proxy)
	}
	if len(cfg.Access.WhiteList) != 1 || cfg.Access.WhiteList[0] != "legacy/*" {
		t.Fatalf("Access.WhiteList = %#v", cfg.Access.WhiteList)
	}
	if len(cfg.Access.BlackList) != 1 || cfg.Access.BlackList[0] != "legacy/blocked" {
		t.Fatalf("Access.BlackList = %#v", cfg.Access.BlackList)
	}
	if len(cfg.Access.DirectLinkWhiteList) != 1 || cfg.Access.DirectLinkWhiteList[0] != "downloads.example.com/files/*" {
		t.Fatalf("Access.DirectLinkWhiteList = %#v", cfg.Access.DirectLinkWhiteList)
	}
	if len(cfg.Access.DirectLinkBlackList) != 1 || cfg.Access.DirectLinkBlackList[0] != "downloads.example.com/files/private/*" {
		t.Fatalf("Access.DirectLinkBlackList = %#v", cfg.Access.DirectLinkBlackList)
	}
}
