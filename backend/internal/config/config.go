package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sessionTTL = 7 * 24 * time.Hour

// Config holds all runtime configuration. Values are read from the environment
// exactly once at startup.
type Config struct {
	Listen         string
	BaseURL        string
	DataDir        string
	WebDir         string
	SessionSecret  []byte
	SecureCookies  bool
	SessionTTL     time.Duration
	LogLevel       slog.Level
	LogLevelName   string
	TrustedProxies []string
}

// Load reads configuration from the environment, creates the data directory and
// (when APP_SESSION_SECRET is unset) persists a random secret in the data
// directory so sessions survive restarts.
func Load() (*Config, error) {
	listen := envOr("APP_LISTEN", "127.0.0.1:8080")
	dataDir := envOr("APP_DATA_DIR", "./data")
	webDir := envOr("APP_WEB_DIR", "./web")
	baseURL := strings.TrimRight(envOr("APP_BASE_URL", "http://localhost:8080"), "/")

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("APP_BASE_URL must be an absolute http(s) URL, got %q", baseURL)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("APP_BASE_URL must not contain a query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("APP_BASE_URL must not contain a path; serve NyaSub at the root of a host or subdomain")
	}

	levelName := strings.ToLower(envOr("APP_LOG_LEVEL", "info"))
	level, err := parseLevel(levelName)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	secret, err := loadOrCreateSecret(dataDir)
	if err != nil {
		return nil, err
	}

	secure := parsed.Scheme == "https"
	if v := os.Getenv("APP_COOKIE_SECURE"); v != "" {
		secure = v == "1" || strings.EqualFold(v, "true")
	}

	var proxies []string
	if raw := os.Getenv("APP_TRUSTED_PROXIES"); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				proxies = append(proxies, p)
			}
		}
	}

	return &Config{
		Listen:         listen,
		BaseURL:        baseURL,
		DataDir:        dataDir,
		WebDir:         webDir,
		SessionSecret:  secret,
		SecureCookies:  secure,
		SessionTTL:     sessionTTL,
		LogLevel:       level,
		LogLevelName:   levelName,
		TrustedProxies: proxies,
	}, nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func parseLevel(name string) (slog.Level, error) {
	switch name {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("APP_LOG_LEVEL must be debug, info, warn or error, got %q", name)
	}
}

func loadOrCreateSecret(dataDir string) ([]byte, error) {
	if raw := os.Getenv("APP_SESSION_SECRET"); raw != "" {
		if len(raw) < 32 {
			return nil, errors.New("APP_SESSION_SECRET must be at least 32 characters")
		}
		return []byte(raw), nil
	}

	path := filepath.Join(dataDir, "session_secret")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return []byte(strings.TrimSpace(string(b))), nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read session secret: %w", err)
	}

	buf := make([]byte, 48)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate session secret: %w", err)
	}
	secret := []byte(base64.RawURLEncoding.EncodeToString(buf))
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("persist session secret: %w", err)
	}
	return secret, nil
}
