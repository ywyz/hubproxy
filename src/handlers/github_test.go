package handlers

import "testing"

func TestCheckGitHubURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		user string
		repo string
	}{
		{"release", "https://github.com/user/repo/releases/download/v1/file.tar.gz", "user", "repo"},
		{"raw", "https://raw.githubusercontent.com/user/repo/main/file.sh", "user", "repo"},
		{"api", "https://api.github.com/repos/user/repo/releases/latest", "user", "repo"},
		{"huggingface", "https://huggingface.co/user/model/resolve/main/file", "user", "model/resolve/main/file"},
		{"direct", "https://ollama.com/download/OllamaSetup.exe", "ollama.com", "download/OllamaSetup.exe"},
		{"direct with query", "https://downloads.example.com/files/app.zip?arch=amd64", "downloads.example.com", "files/app.zip?arch=amd64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckGitHubURL(tt.url)
			if len(got) < 2 || got[0] != tt.user || got[1] != tt.repo {
				t.Fatalf("CheckGitHubURL(%q) = %#v", tt.url, got)
			}
		})
	}
}

func TestCheckGitHubURLRejectsInvalidDirectLinks(t *testing.T) {
	tests := []string{
		"http://downloads.example.com/files/app.zip",
		"ftp://downloads.example.com/files/app.zip",
		"https://downloads.example.com",
		"not-a-url",
	}

	for _, rawURL := range tests {
		if got := CheckGitHubURL(rawURL); got != nil {
			t.Fatalf("CheckGitHubURL(%q) unexpectedly matched: %#v", rawURL, got)
		}
	}
}
