package utils

import (
	"os"
	"path/filepath"
	"testing"

	"hubproxy/config"
)

func TestParseDockerImage(t *testing.T) {
	tests := []struct {
		name       string
		image      string
		namespace  string
		repository string
		tag        string
		fullName   string
	}{
		{"official", "nginx", "library", "nginx", "latest", "library/nginx"},
		{"tagged", "redis:7", "library", "redis", "7", "library/redis"},
		{"namespaced", "user/app:v1", "user", "app", "v1", "user/app"},
		{"registry", "ghcr.io/user/app:v2", "user", "app", "v2", "user/app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GlobalAccessController.ParseDockerImage(tt.image)
			if got.Namespace != tt.namespace || got.Repository != tt.repository || got.Tag != tt.tag || got.FullName != tt.fullName {
				t.Fatalf("ParseDockerImage(%q) = %#v", tt.image, got)
			}
		})
	}
}

func TestDockerAccessLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := []byte(`
[access]
whiteList = ["library/*", "good/*"]
blackList = ["good/bad"]
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", path)
	if err := config.LoadConfig(); err != nil {
		t.Fatal(err)
	}

	if allowed, reason := GlobalAccessController.CheckDockerAccess("nginx"); !allowed {
		t.Fatalf("nginx denied: %s", reason)
	}
	if allowed, _ := GlobalAccessController.CheckDockerAccess("good/bad:latest"); allowed {
		t.Fatal("blacklisted image allowed")
	}
	if allowed, _ := GlobalAccessController.CheckDockerAccess("other/app"); allowed {
		t.Fatal("image outside whitelist allowed")
	}
}

func TestGitHubAccessLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := []byte(`
[access]
whiteList = ["allowed/*"]
blackList = ["allowed/blocked"]
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", path)
	if err := config.LoadConfig(); err != nil {
		t.Fatal(err)
	}

	if allowed, reason := GlobalAccessController.CheckGitHubAccess([]string{"allowed", "repo"}); !allowed {
		t.Fatalf("allowed/repo denied: %s", reason)
	}
	if allowed, _ := GlobalAccessController.CheckGitHubAccess([]string{"allowed", "blocked"}); allowed {
		t.Fatal("blacklisted repo allowed")
	}
	if allowed, _ := GlobalAccessController.CheckGitHubAccess([]string{"other", "repo"}); allowed {
		t.Fatal("repo outside whitelist allowed")
	}
}

func TestDirectLinkAccessDoesNotTrimPathOrQuery(t *testing.T) {
	controller := &AccessController{}
	allowed := []string{"downloads.example.com/files/app.zip"}

	if controller.checkDirectLinkList("DOWNLOADS.EXAMPLE.COM:443", "files/app.zip ", allowed) {
		t.Fatal("path ending in an encoded space matched the path without that space")
	}
	if !controller.checkDirectLinkList("downloads.example.com", "files/app.zip", allowed) {
		t.Fatal("equivalent host and exact path did not match")
	}
}

func TestDirectLinkAccessNormalizesNumericPorts(t *testing.T) {
	controller := &AccessController{}
	for _, test := range []struct {
		name    string
		host    string
		allowed []string
	}{
		{name: "leading-zero default port", host: "downloads.example.com:0443", allowed: []string{"downloads.example.com/files/*"}},
		{name: "leading-zero non-default port", host: "downloads.example.com:08443", allowed: []string{"downloads.example.com:8443/files/*"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !controller.checkDirectLinkList(test.host, "files/app.zip", test.allowed) {
				t.Fatalf("host %q did not match numerically equivalent rule %q", test.host, test.allowed[0])
			}
		})
	}
}

func TestDirectLinkAccessLegacyAllowlistDoesNotAuthorizeDirectLinks(t *testing.T) {
	loadAccessConfig(t, `
[access]
whiteList = ["*/allowed-repo"]
`)

	if allowed, _ := GlobalAccessController.CheckDirectLinkAccess([]string{"downloads.example.com", "allowed-repo"}); allowed {
		t.Fatal("legacy repository allowlist authorized a direct link")
	}
}

func TestDirectLinkAccessDedicatedListsAreIsolated(t *testing.T) {
	loadAccessConfig(t, `
[access]
whiteList = ["allowed/*"]
blackList = ["downloads.example.com/files/public.zip"]
directLinkWhiteList = ["downloads.example.com/files/*"]
directLinkBlackList = ["downloads.example.com/files/private/*"]
`)

	if allowed, reason := GlobalAccessController.CheckDirectLinkAccess([]string{"downloads.example.com", "files/public.zip"}); !allowed {
		t.Fatalf("dedicated direct-link allowlist entry denied: %s", reason)
	}
	if allowed, _ := GlobalAccessController.CheckDirectLinkAccess([]string{"downloads.example.com", "files/private/secret.zip"}); allowed {
		t.Fatal("dedicated direct-link blacklist entry was allowed")
	}
	if allowed, reason := GlobalAccessController.CheckGitHubAccess([]string{"allowed", "repo"}); !allowed {
		t.Fatalf("legacy repository allowlist stopped working: %s", reason)
	}
	if allowed, _ := GlobalAccessController.CheckGitHubAccess([]string{"other", "repo"}); allowed {
		t.Fatal("legacy repository allowlist was bypassed")
	}

	loadAccessConfig(t, `
[access]
directLinkWhiteList = ["downloads.example.com/files/*"]
directLinkBlackList = ["*/*"]
`)
	if allowed, reason := GlobalAccessController.CheckGitHubAccess([]string{"other", "repo"}); !allowed {
		t.Fatalf("direct-link lists leaked into repository access control: %s", reason)
	}
	if allowed, reason := GlobalAccessController.CheckDockerAccess("other/app"); !allowed {
		t.Fatalf("direct-link lists leaked into image access control: %s", reason)
	}
}

func TestDirectLinkAccessEmptyAllowlistDenies(t *testing.T) {
	loadAccessConfig(t, `
[access]
directLinkWhiteList = []
`)

	if allowed, _ := GlobalAccessController.CheckDirectLinkAccess([]string{"downloads.example.com", "files/app.zip"}); allowed {
		t.Fatal("empty direct-link allowlist allowed a direct link")
	}
}

func TestDirectLinkAccessRequiresExplicitGlobalWildcard(t *testing.T) {
	t.Run("host wildcard alone is denied", func(t *testing.T) {
		loadAccessConfig(t, `
[access]
directLinkWhiteList = ["*"]
`)

		if allowed, _ := GlobalAccessController.CheckDirectLinkAccess([]string{"downloads.example.com", "files/app.zip"}); allowed {
			t.Fatal("host wildcard without an explicit path wildcard allowed all direct links")
		}
	})

	t.Run("explicit host and path wildcard allows all", func(t *testing.T) {
		loadAccessConfig(t, `
[access]
directLinkWhiteList = ["*/*"]
`)

		if allowed, reason := GlobalAccessController.CheckDirectLinkAccess([]string{"downloads.example.com", "files/app.zip"}); !allowed {
			t.Fatalf("explicit global direct-link wildcard denied: %s", reason)
		}
	})
}

func loadAccessConfig(t *testing.T, data string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_PATH", path)
	if err := config.LoadConfig(); err != nil {
		t.Fatal(err)
	}
}
