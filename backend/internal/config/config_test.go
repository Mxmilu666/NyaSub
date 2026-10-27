package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_LISTEN", "127.0.0.1:9999")
	t.Setenv("APP_BASE_URL", "https://nyasub.example.com")
	t.Setenv("APP_DATA_DIR", dir)
	t.Setenv("APP_LOG_LEVEL", "warn")
	t.Setenv("APP_SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SecureCookies {
		t.Fatal("https base URL must enable secure cookies")
	}
	if cfg.LogLevelName != "warn" {
		t.Fatalf("unexpected log level %q", cfg.LogLevelName)
	}
	if cfg.SessionTTL.Hours() != 168 {
		t.Fatalf("unexpected session ttl %v", cfg.SessionTTL)
	}
}

func TestLoadRejectsWeakSecretAndPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_DATA_DIR", dir)
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("APP_SESSION_SECRET", "short")
	if _, err := Load(); err == nil {
		t.Fatal("expected weak secret rejection")
	}

	t.Setenv("APP_SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("APP_BASE_URL", "https://example.com/nyasub")
	if _, err := Load(); err == nil {
		t.Fatal("expected base URL path rejection")
	}
}

func TestSecretPersistsWhenNotConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APP_DATA_DIR", dir)
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("APP_SESSION_SECRET", "")
	first, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "session_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret permissions = %o", info.Mode().Perm())
	}
	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if string(first.SessionSecret) != string(second.SessionSecret) {
		t.Fatal("session secret was not reused")
	}
}
