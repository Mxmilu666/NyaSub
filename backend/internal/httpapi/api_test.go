package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"nyasub/internal/config"
	"nyasub/internal/importers"
	"nyasub/internal/mihomo"
	"nyasub/internal/store"
)

type testEnv struct {
	t      *testing.T
	app    *App
	db     *gorm.DB
	srv    *httptest.Server
	client *http.Client
	cfg    *config.Config
	csrf   string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		BaseURL: "http://placeholder.invalid", DataDir: dir, WebDir: dir + "/web",
		SessionSecret: []byte("0123456789abcdef0123456789abcdef0123456789abcdef"),
		SecureCookies: false, SessionTTL: time.Hour, LogLevel: slog.LevelError, LogLevelName: "error",
	}
	db, err := store.Open(dir)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(db))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := New(cfg, db, logger, "test-version")
	srv := httptest.NewServer(app.Router())
	cfg.BaseURL = srv.URL
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	env := &testEnv{t: t, app: app, db: db, srv: srv, cfg: cfg, client: &http.Client{Jar: jar}}
	t.Cleanup(func() {
		srv.Close()
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	})
	resp, body := env.doRaw(http.MethodGet, "/api/auth/csrf", nil, false, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	require.NoError(t, json.Unmarshal(body, &csrf))
	require.NotEmpty(t, csrf.Token)
	env.csrf = csrf.Token
	return env
}

func (e *testEnv) do(method, path string, body any) (*http.Response, []byte) {
	return e.doRaw(method, path, body, true, e.cfg.BaseURL)
}

func (e *testEnv) doRaw(method, path string, body any, withCSRF bool, origin string) (*http.Response, []byte) {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(e.t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, reader)
	require.NoError(e.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if withCSRF {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	resp, err := e.client.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)
	return resp, raw
}

func (e *testEnv) setup() {
	e.t.Helper()
	resp, body := e.do(http.MethodPost, "/api/auth/setup", map[string]any{
		"username": "admin", "password": "super-secret-password",
	})
	require.Equal(e.t, http.StatusCreated, resp.StatusCode, string(body))
}

func (e *testEnv) createNode(name, protocol string, cfg mihomo.Config, tags ...string) string {
	e.t.Helper()
	resp, body := e.do(http.MethodPost, "/api/nodes", map[string]any{
		"name": name, "protocol": protocol, "tags": tags, "config": cfg,
	})
	require.Equal(e.t, http.StatusCreated, resp.StatusCode, string(body))
	var out struct {
		Node struct {
			ID string `json:"id"`
		} `json:"node"`
	}
	require.NoError(e.t, json.Unmarshal(body, &out))
	require.NotEmpty(e.t, out.Node.ID)
	return out.Node.ID
}

func (e *testEnv) createChain(name, entry, exit string) string {
	e.t.Helper()
	resp, body := e.do(http.MethodPost, "/api/chains", map[string]any{
		"name": name, "entry_node_id": entry, "exit_node_id": exit, "enabled": true,
	})
	require.Equal(e.t, http.StatusCreated, resp.StatusCode, string(body))
	var out struct {
		Chain struct {
			ID string `json:"id"`
		} `json:"chain"`
	}
	require.NoError(e.t, json.Unmarshal(body, &out))
	return out.Chain.ID
}

func (e *testEnv) createProfile(name string, nodeIDs, chainIDs []string, defaultType, defaultID string, force bool) string {
	e.t.Helper()
	resp, body := e.do(http.MethodPost, "/api/profiles", map[string]any{
		"name": name, "description": "test profile", "node_ids": nodeIDs, "chain_ids": chainIDs,
		"default_exit_type": defaultType, "default_exit_id": defaultID, "force_default_exit": force,
		"groups": []any{}, "rules": []any{}, "dns": map[string]any{}, "general": map[string]any{},
	})
	require.Equal(e.t, http.StatusCreated, resp.StatusCode, string(body))
	var out struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
	}
	require.NoError(e.t, json.Unmarshal(body, &out))
	return out.Profile.ID
}

func (e *testEnv) createToken(profileID string) (string, string) {
	e.t.Helper()
	resp, body := e.do(http.MethodPost, "/api/profiles/"+profileID+"/tokens", nil)
	require.Equal(e.t, http.StatusCreated, resp.StatusCode, string(body))
	var out struct {
		URL     string `json:"url"`
		TokenID string `json:"token_id"`
	}
	require.NoError(e.t, json.Unmarshal(body, &out))
	return out.URL, out.TokenID
}

func simpleVLESS(server string) mihomo.Config {
	return mihomo.Config{Server: server, Port: 443, UUID: "11111111-1111-4111-8111-111111111111", Network: "tcp", TLS: true, SNI: server}
}

func simpleVMess(server string) mihomo.Config {
	return mihomo.Config{
		Server: server, Port: 8443, UUID: "22222222-2222-4222-8222-222222222222", Cipher: "auto",
		Network: "ws", TLS: true, SNI: server, WS: &mihomo.WSOptions{Path: "/ws", Headers: map[string]string{"Host": server}},
	}
}

func TestSetupSessionAndDuplicateSetup(t *testing.T) {
	env := newTestEnv(t)

	_, body := env.do(http.MethodGet, "/api/auth/status", nil)
	require.JSONEq(t, `{"initialized":false}`, string(body))

	resp, body := env.do(http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "short"})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, string(body), "weak_password")

	resp, body = env.do(http.MethodPost, "/api/auth/setup", map[string]any{"username": "admin", "password": "super-secret-password"})
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))
	require.NotEmpty(t, resp.Header.Get("Set-Cookie"))
	require.Contains(t, strings.ToLower(resp.Header.Get("Set-Cookie")), "httponly")
	require.Contains(t, strings.ToLower(resp.Header.Get("Set-Cookie")), "samesite=lax")

	var sessions []store.Session
	require.NoError(t, env.db.Find(&sessions).Error)
	require.Len(t, sessions, 1)
	require.Len(t, sessions[0].TokenHash, 64)
	require.NotEqual(t, "super-secret-password", sessions[0].TokenHash)

	resp, body = env.do(http.MethodGet, "/api/auth/me", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	resp, body = env.do(http.MethodPost, "/api/auth/setup", map[string]any{"username": "other", "password": "another-secret-password"})
	require.Equal(t, http.StatusConflict, resp.StatusCode, string(body))
	require.Contains(t, string(body), "already_initialized")

	_, body = env.do(http.MethodGet, "/api/auth/status", nil)
	require.JSONEq(t, `{"initialized":true}`, string(body))
}

func TestLoginLogoutAndSessionExpiry(t *testing.T) {
	env := newTestEnv(t)
	env.setup()

	resp, body := env.do(http.MethodPost, "/api/auth/logout", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))
	resp, _ = env.do(http.MethodGet, "/api/auth/me", nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, body = env.do(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "wrong-password"})
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))
	require.NotContains(t, string(body), "wrong-password")

	resp, body = env.do(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "super-secret-password"})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	resp, _ = env.do(http.MethodGet, "/api/auth/me", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, env.db.Model(&store.Session{}).Where("1 = 1").Update("expires_at", time.Now().Add(-time.Hour)).Error)
	resp, _ = env.do(http.MethodGet, "/api/auth/me", nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestUnauthenticatedManagementAndCSRF(t *testing.T) {
	env := newTestEnv(t)
	resp, body := env.do(http.MethodGet, "/api/nodes", nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))
	resp, body = env.do(http.MethodGet, "/api/profiles", nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))
	resp, body = env.do(http.MethodGet, "/api/backup", nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, string(body))

	env.setup()
	// Logout so the next login is unauthenticated but CSRF is still required.
	resp, _ = env.do(http.MethodPost, "/api/auth/logout", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	resp, body = env.doRaw(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "super-secret-password"}, false, env.cfg.BaseURL)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, string(body))
	require.Contains(t, string(body), "csrf")

	resp, body = env.doRaw(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "super-secret-password"}, true, "https://evil.example")
	require.Equal(t, http.StatusForbidden, resp.StatusCode, string(body))
}

func TestNodeImportPreviewAndDedup(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	content := "vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=tls&sni=a.example.com#A\n" +
		"bad-line\n" +
		"trojan://pw@b.example.com:443?security=tls&sni=b.example.com#B\n"
	resp, body := env.do(http.MethodPost, "/api/nodes/import/preview", map[string]any{
		"content": content, "format": "uri", "tags": []string{"batch"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var preview struct {
		Items []struct {
			Name      string   `json:"name"`
			Protocol  string   `json:"protocol"`
			Tags      []string `json:"tags"`
			Duplicate bool     `json:"duplicate"`
			Line      int      `json:"line"`
		} `json:"items"`
		Issues []struct {
			Line int `json:"line"`
		} `json:"issues"`
	}
	require.NoError(t, json.Unmarshal(body, &preview))
	require.Len(t, preview.Items, 2)
	require.Len(t, preview.Issues, 1)
	require.Equal(t, 2, preview.Issues[0].Line)
	require.Equal(t, []string{"batch"}, preview.Items[0].Tags)

	resp, body = env.do(http.MethodPost, "/api/nodes/import", map[string]any{
		"content": content, "format": "uri", "tags": []string{"batch"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var imported struct {
		Created int `json:"created"`
		Skipped int `json:"skipped"`
	}
	require.NoError(t, json.Unmarshal(body, &imported))
	require.Equal(t, 2, imported.Created)

	resp, body = env.do(http.MethodPost, "/api/nodes/import", map[string]any{
		"content": content, "format": "uri", "tags": []string{"batch"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.NoError(t, json.Unmarshal(body, &imported))
	require.Equal(t, 0, imported.Created)
	require.Equal(t, 2, imported.Skipped)

	var nodes []store.Node
	require.NoError(t, env.db.Preload("Tags").Find(&nodes).Error)
	require.Len(t, nodes, 2)
}

func TestMihomoYAMLImport(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	content := `
proxies:
  - name: Y-VLESS
    type: vless
    server: y.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: grpc
    tls: true
    servername: y.example.com
    grpc-opts:
      grpc-service-name: svc
  - name: Y-SS
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw
`
	resp, body := env.do(http.MethodPost, "/api/nodes/import", map[string]any{"content": content, "format": "yaml"})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var out struct {
		Created int `json:"created"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	require.Equal(t, 2, out.Created)

	_, body = env.do(http.MethodGet, "/api/nodes", nil)
	require.Contains(t, string(body), "Y-VLESS")
	require.Contains(t, string(body), "Y-SS")
}

type staticSubscriptionFetcher struct {
	content string
	err     error
	called  string
}

func (s *staticSubscriptionFetcher) Fetch(_ context.Context, rawURL string) (string, error) {
	s.called = rawURL
	return s.content, s.err
}

func TestSubscriptionURLImport(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	plain := "vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=tls#A\n" +
		"trojan://pw@b.example.com:443?security=tls#B\n"
	stub := &staticSubscriptionFetcher{content: base64.StdEncoding.EncodeToString([]byte(plain))}
	env.app.subFetcher = stub

	resp, body := env.do(http.MethodPost, "/api/nodes/import/preview", map[string]any{
		"url": "https://subscription.example/list?token=secret", "tags": []string{"sub"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.Equal(t, "https://subscription.example/list?token=secret", stub.called)
	var preview struct {
		Items []struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(body, &preview))
	require.Len(t, preview.Items, 2)
	require.Equal(t, []string{"sub"}, preview.Items[0].Tags)

	resp, body = env.do(http.MethodPost, "/api/nodes/import", map[string]any{
		"url": "https://subscription.example/list?token=secret", "tags": []string{"sub"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var imported struct {
		Created int `json:"created"`
	}
	require.NoError(t, json.Unmarshal(body, &imported))
	require.Equal(t, 2, imported.Created)
}

func TestSubscriptionURLImportValidation(t *testing.T) {
	env := newTestEnv(t)
	env.setup()

	resp, body := env.do(http.MethodPost, "/api/nodes/import/preview", map[string]any{
		"url": "https://subscription.example/list", "content": "vless://x",
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(body))
	require.Contains(t, string(body), "invalid_import_source")

	resp, body = env.do(http.MethodPost, "/api/nodes/import/preview", map[string]any{})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(body))
	require.Contains(t, string(body), "content_required")

	env.app.subFetcher = &staticSubscriptionFetcher{err: importers.ErrBlockedSubscriptionTarget}
	resp, body = env.do(http.MethodPost, "/api/nodes/import/preview", map[string]any{
		"url": "https://subscription.example/list",
	})
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode, string(body))
	require.Contains(t, string(body), "subscription_target_blocked")
}

func TestSubscriptionURLImportRejectsLoopback(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	resp, body := env.do(http.MethodPost, "/api/nodes/import/preview", map[string]any{
		"url": "http://127.0.0.1:9/subscription",
	})
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode, string(body))
	require.Contains(t, string(body), "subscription_target_blocked")
}

func TestChainCycleAndSelfRejected(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	a := env.createNode("A", "vless", simpleVLESS("a.example.com"))
	b := env.createNode("B", "vmess", simpleVMess("b.example.com"))
	env.createChain("A to B", a, b)

	resp, body := env.do(http.MethodPost, "/api/chains", map[string]any{
		"name": "B to A", "entry_node_id": b, "exit_node_id": a, "enabled": true,
	})
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode, string(body))
	require.Contains(t, string(body), "chain_cycle")

	resp, body = env.do(http.MethodPost, "/api/chains", map[string]any{
		"name": "self", "entry_node_id": a, "exit_node_id": a, "enabled": true,
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(body))
	require.Contains(t, string(body), "must differ")
}

func TestNodeDeleteDependencyChecks(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	a := env.createNode("A", "vless", simpleVLESS("a.example.com"))
	b := env.createNode("B", "vmess", simpleVMess("b.example.com"))
	chainID := env.createChain("A to B", a, b)
	profileID := env.createProfile("P", []string{a, b}, []string{chainID}, "chain", chainID, true)

	resp, body := env.do(http.MethodDelete, "/api/nodes/"+a, nil)
	require.Equal(t, http.StatusConflict, resp.StatusCode, string(body))
	require.Contains(t, string(body), "node_in_use")
	require.Contains(t, string(body), "A to B")

	// Remove the profile, then the chain dependency, then retry.
	resp, body = env.do(http.MethodDelete, "/api/profiles/"+profileID, nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))
	resp, body = env.do(http.MethodDelete, "/api/chains/"+chainID+"?force=true", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))

	// A profile that only references nodes still blocks a non-forced delete.
	profileOnlyID := env.createProfile("OnlyNodes", []string{a, b}, []string{}, "node", b, false)
	resp, body = env.do(http.MethodDelete, "/api/nodes/"+a, nil)
	require.Equal(t, http.StatusConflict, resp.StatusCode, string(body))
	require.Contains(t, string(body), "profiles")

	resp, body = env.do(http.MethodDelete, "/api/nodes/"+a+"?force=true", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))

	resp, body = env.do(http.MethodGet, "/api/profiles/"+profileOnlyID, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var profile struct {
		Profile struct {
			NodeIDs       []string `json:"node_ids"`
			DefaultExitID string   `json:"default_exit_id"`
		} `json:"profile"`
	}
	require.NoError(t, json.Unmarshal(body, &profile))
	require.Equal(t, []string{b}, profile.Profile.NodeIDs)
	require.Equal(t, b, profile.Profile.DefaultExitID)
}

func TestSubscriptionTokenRotationRevocationAndDefaultExit(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	a := env.createNode("HK-01", "vless", simpleVLESS("hk.example.com"))
	b := env.createNode("US-02", "vmess", simpleVMess("us.example.com"))
	h := env.createNode("HY-03", "hysteria2", mihomo.Config{
		Server: "hy.example.com", Port: 443, Password: "hy-secret", SNI: "hy.example.com",
	})
	chainID := env.createChain("chain", a, b)
	profileID := env.createProfile("Daily", []string{a, b, h}, []string{chainID}, "chain", chainID, true)

	subURL, tokenID := env.createToken(profileID)

	// Subscription access is independent of the management session cookie.
	anon := &http.Client{}
	resp, err := anon.Get(subURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	yamlBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(yamlBody))
	require.Contains(t, resp.Header.Get("Content-Type"), "application/yaml")
	require.Contains(t, resp.Header.Get("Content-Disposition"), `filename="NyaSub.yaml"`)
	require.Empty(t, resp.Header.Get("Set-Cookie"))
	require.Contains(t, string(yamlBody), "dialer-proxy:")
	require.Contains(t, string(yamlBody), "MATCH,")
	require.Contains(t, string(yamlBody), "HK-01 → ")
	etag := resp.Header.Get("ETag")
	require.NotEmpty(t, etag)

	// Xray/V2Ray subscription returns base64-encoded share links, not YAML.
	respX, err := anon.Get(subURL + "?format=xray")
	require.NoError(t, err)
	defer respX.Body.Close()
	xrayBody, _ := io.ReadAll(respX.Body)
	require.Equal(t, http.StatusOK, respX.StatusCode, string(xrayBody))
	require.Contains(t, respX.Header.Get("Content-Type"), "text/plain")
	require.Contains(t, respX.Header.Get("Content-Disposition"), `filename="NyaSub.txt"`)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(xrayBody)))
	require.NoError(t, err)
	parsed := importers.Parse(string(decoded), "uri")
	require.Empty(t, parsed.Issues)
	require.Len(t, parsed.Items, 3)
	protocols := map[mihomo.Protocol]bool{}
	for _, item := range parsed.Items {
		protocols[item.Protocol] = true
	}
	require.True(t, protocols[mihomo.ProtocolVLESS])
	require.True(t, protocols[mihomo.ProtocolVMess])
	require.True(t, protocols[mihomo.ProtocolHysteria2])
	require.Contains(t, string(decoded), "hysteria2://")

	req, _ := http.NewRequest(http.MethodGet, subURL, nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := anon.Do(req)
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusNotModified, resp2.StatusCode)

	var token store.SubscriptionToken
	require.NoError(t, env.db.Where("id = ?", tokenID).First(&token).Error)
	require.Len(t, token.TokenHash, 64)
	require.NotContains(t, token.TokenHash, strings.TrimPrefix(subURL, env.cfg.BaseURL+"/s/"))

	// Rotation revokes the previous URL.
	newURL, newTokenID := env.createToken(profileID)
	resp3, err := anon.Get(subURL)
	require.NoError(t, err)
	resp3.Body.Close()
	require.Equal(t, http.StatusNotFound, resp3.StatusCode)
	resp4, err := anon.Get(newURL)
	require.NoError(t, err)
	resp4.Body.Close()
	require.Equal(t, http.StatusOK, resp4.StatusCode)

	// Explicit revocation.
	resp5, body := env.do(http.MethodDelete, "/api/subscription-tokens/"+newTokenID, nil)
	require.Equal(t, http.StatusNoContent, resp5.StatusCode, string(body))
	resp6, err := anon.Get(newURL)
	require.NoError(t, err)
	resp6.Body.Close()
	require.Equal(t, http.StatusNotFound, resp6.StatusCode)
}

func TestProfileGroupsRulesAndNodeNameConflicts(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	a := env.createNode("Same", "vless", simpleVLESS("a.example.com"))
	b := env.createNode("Same", "vmess", simpleVMess("b.example.com"))
	profileResp, profileBody := env.do(http.MethodPost, "/api/profiles", map[string]any{
		"name": "Groups", "description": "", "node_ids": []string{a, b}, "chain_ids": []string{},
		"default_exit_type": "node", "default_exit_id": b, "force_default_exit": false,
		"groups": []map[string]any{
			{"name": "Proxy", "type": "select", "proxies": []string{"node:" + a, "node:" + b}},
			{"name": "Auto", "type": "url-test", "proxies": []string{"node:" + a}, "url": "https://www.gstatic.com/generate_204", "interval": 300},
		},
		"rules": []map[string]any{
			{"type": "DOMAIN-SUFFIX", "payload": "example.com", "target": "group:Proxy"},
		},
		"dns":     map[string]any{"enable": true},
		"general": map[string]any{"mode": "rule"},
	})
	require.Equal(t, http.StatusCreated, profileResp.StatusCode, string(profileBody))
	var created struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
	}
	require.NoError(t, json.Unmarshal(profileBody, &created))

	subURL, _ := env.createToken(created.Profile.ID)
	resp, err := http.Get(subURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(raw), "name: Same")
	require.Contains(t, string(raw), "name: Same (2)")
	require.Contains(t, string(raw), "DOMAIN-SUFFIX,example.com,Proxy")
	require.Contains(t, string(raw), "dns:")
	require.Contains(t, string(raw), "enable: true")
	// Both colliding names are present and the selected default is in the group.
	require.Contains(t, string(raw), "name: Proxy")
	require.Contains(t, string(raw), "name: Auto")
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	a := env.createNode("A", "vless", simpleVLESS("a.example.com"), "tag1")
	b := env.createNode("B", "vmess", simpleVMess("b.example.com"))
	chainID := env.createChain("chain", a, b)
	profileID := env.createProfile("P", []string{a, b}, []string{chainID}, "chain", chainID, true)
	subURL, _ := env.createToken(profileID)
	anon := &http.Client{}
	resp, err := anon.Get(subURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, backup := env.do(http.MethodGet, "/api/backup", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(backup), "\"password_hash\"")
	require.Contains(t, string(backup), "\"token_hash\"")

	// Destroy data then restore the snapshot.
	resp, body := env.do(http.MethodDelete, "/api/profiles/"+profileID, nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))
	resp, body = env.do(http.MethodDelete, "/api/chains/"+chainID+"?force=true", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))
	resp, body = env.do(http.MethodDelete, "/api/nodes/"+a+"?force=true", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))

	resp, body = env.do(http.MethodPost, "/api/backup/restore", json.RawMessage(backup))
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.Contains(t, string(body), "relogin_required")

	// Current session was replaced by the snapshot; the subscription URL works.
	resp, err = anon.Get(subURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var node store.Node
	require.NoError(t, env.db.Where("id = ?", a).First(&node).Error)
	require.Equal(t, "A", node.Name)
}

func TestAuthRateLimit(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	env.do(http.MethodPost, "/api/auth/logout", nil)
	for i := 0; i < 5; i++ {
		resp, _ := env.do(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "wrong-password"})
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
	resp, body := env.do(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "super-secret-password"})
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode, string(body))
	require.NotEmpty(t, resp.Header.Get("Retry-After"))
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	// Log in from a second client.
	jar2, _ := cookiejar.New(nil)
	client2 := &http.Client{Jar: jar2}
	csrfResp, err := client2.Get(env.srv.URL + "/api/auth/csrf")
	require.NoError(t, err)
	var csrfBody struct {
		Token string `json:"csrf_token"`
	}
	require.NoError(t, json.NewDecoder(csrfResp.Body).Decode(&csrfBody))
	csrfResp.Body.Close()
	loginBody, _ := json.Marshal(map[string]any{"username": "admin", "password": "super-secret-password"})
	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", env.cfg.BaseURL)
	req.Header.Set("X-CSRF-Token", csrfBody.Token)
	resp, err := client2.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, body := env.do(http.MethodPut, "/api/auth/password", map[string]any{
		"current_password": "super-secret-password", "new_password": "another-secret-password",
	})
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))

	resp, err = client2.Get(env.srv.URL + "/api/auth/me")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = env.do(http.MethodGet, "/api/auth/me", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The new password logs in; the old one does not.
	env.do(http.MethodPost, "/api/auth/logout", nil)
	resp, _ = env.do(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "super-secret-password"})
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp, body = env.do(http.MethodPost, "/api/auth/login", map[string]any{"username": "admin", "password": "another-secret-password"})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
}

func TestErrorFormatAndSecurityHeaders(t *testing.T) {
	env := newTestEnv(t)
	resp, body := env.do(http.MethodGet, "/api/nodes", nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	require.Equal(t, "unauthorized", envelope.Error.Code)
	require.NotEmpty(t, envelope.Error.Message)
	require.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	require.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	require.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'self'")

	resp, body = env.do(http.MethodGet, "/api/does-not-exist", nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode, string(body))
	require.Contains(t, string(body), "not_found")

}

func TestConcurrentSetupOnlyOneWins(t *testing.T) {
	env := newTestEnv(t)
	type result struct {
		status int
		body   string
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	doSetup := func(username string) {
		body, _ := json.Marshal(map[string]any{"username": username, "password": "super-secret-password"})
		req, err := http.NewRequest(http.MethodPost, env.srv.URL+"/api/auth/setup", bytes.NewReader(body))
		if err != nil {
			results <- result{status: 0, body: err.Error()}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", env.cfg.BaseURL)
		req.Header.Set("X-CSRF-Token", env.csrf)
		<-start
		resp, err := env.client.Do(req)
		if err != nil {
			results <- result{status: 0, body: err.Error()}
			return
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		results <- result{status: resp.StatusCode, body: string(raw)}
	}
	go doSetup("admin-one")
	go doSetup("admin-two")
	close(start)
	a, b := <-results, <-results
	statuses := []int{a.status, b.status}
	created, conflict := 0, 0
	for _, status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflict++
		}
	}
	require.Equal(t, 1, created, "statuses: %v bodies: %s / %s", statuses, a.body, b.body)
	require.Equal(t, 1, conflict, "statuses: %v", statuses)

	var count int64
	require.NoError(t, env.db.Model(&store.User{}).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestSessionManagementAndLogLevel(t *testing.T) {
	env := newTestEnv(t)
	env.setup()

	// Create a second session.
	jar2, _ := cookiejar.New(nil)
	client2 := &http.Client{Jar: jar2}
	csrfResp, err := client2.Get(env.srv.URL + "/api/auth/csrf")
	require.NoError(t, err)
	var csrfBody struct {
		Token string `json:"csrf_token"`
	}
	require.NoError(t, json.NewDecoder(csrfResp.Body).Decode(&csrfBody))
	csrfResp.Body.Close()
	body, _ := json.Marshal(map[string]any{"username": "admin", "password": "super-secret-password"})
	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", env.cfg.BaseURL)
	req.Header.Set("X-CSRF-Token", csrfBody.Token)
	resp, err := client2.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, body = env.do(http.MethodGet, "/api/auth/sessions", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var list struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	require.Len(t, list.Sessions, 2)
	var otherID string
	for _, session := range list.Sessions {
		if !session.Current {
			otherID = session.ID
		}
	}
	require.NotEmpty(t, otherID)
	resp, body = env.do(http.MethodDelete, "/api/auth/sessions/"+otherID, nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(body))
	resp, body = env.do(http.MethodGet, "/api/auth/sessions", nil)
	require.NoError(t, json.Unmarshal(body, &list))
	require.Len(t, list.Sessions, 1)

	resp, body = env.do(http.MethodPut, "/api/settings/log-level", map[string]any{"level": "warn"})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.Contains(t, string(body), "warn")
	resp, body = env.do(http.MethodGet, "/api/settings", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.Contains(t, string(body), `"log_level":"warn"`)

	resp, body = env.do(http.MethodPut, "/api/settings/log-level", map[string]any{"level": "verbose"})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(body))
}

func TestNodeCountryNormalization(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	resp, body := env.do(http.MethodPost, "/api/nodes", map[string]any{
		"name": "BT-UK", "country": "uk", "protocol": "vless", "config": simpleVLESS("uk.example.com"),
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))
	var created struct {
		Node struct {
			Country string `json:"country"`
		} `json:"node"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	require.Equal(t, "GB", created.Node.Country)

	resp, body = env.do(http.MethodPost, "/api/nodes", map[string]any{
		"name": "Bad", "country": "XX1", "protocol": "vless", "config": simpleVLESS("bad.example.com"),
	})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(body))
	require.Contains(t, string(body), "invalid_country")
}

func TestDeleteTagGlobally(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	id := env.createNode("Tagged", "vless", simpleVLESS("tag.example.com"), "premium", "hk")

	resp, body := env.do(http.MethodDelete, "/api/nodes/tags?tag=premium", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var deleted struct {
		Deleted int64 `json:"deleted"`
	}
	require.NoError(t, json.Unmarshal(body, &deleted))
	require.Equal(t, int64(1), deleted.Deleted)

	resp, body = env.do(http.MethodGet, "/api/nodes/"+id, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.Contains(t, string(body), "Tagged")
	require.NotContains(t, string(body), `"premium"`)
	require.Contains(t, string(body), `"hk"`)

	resp, body = env.do(http.MethodGet, "/api/nodes/tags", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.NotContains(t, string(body), "premium")
	require.Contains(t, string(body), "hk")
}

func TestSubscriptionURLIsViewableAfterCreation(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	id := env.createNode("Viewable", "vless", simpleVLESS("view.example.com"))
	profileID := env.createProfile("Viewable Profile", []string{id}, nil, "", "", false)
	subURL, _ := env.createToken(profileID)

	resp, body := env.do(http.MethodGet, "/api/profiles", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var list struct {
		Profiles []struct {
			Token *struct {
				URL     string `json:"url"`
				XrayURL string `json:"xray_url"`
			} `json:"token"`
		} `json:"profiles"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	require.Len(t, list.Profiles, 1)
	require.NotNil(t, list.Profiles[0].Token)
	require.Equal(t, subURL, list.Profiles[0].Token.URL)
	require.Equal(t, subURL+"?format=xray", list.Profiles[0].Token.XrayURL)

	resp, body = env.do(http.MethodGet, "/api/profiles/"+profileID+"/tokens", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var tokens struct {
		Tokens []struct {
			URL     string `json:"url"`
			XrayURL string `json:"xray_url"`
		} `json:"tokens"`
	}
	require.NoError(t, json.Unmarshal(body, &tokens))
	require.Len(t, tokens.Tokens, 1)
	require.Equal(t, subURL, tokens.Tokens[0].URL)
	require.Equal(t, subURL+"?format=xray", tokens.Tokens[0].XrayURL)
}

func TestACL4SSRProfileTemplate(t *testing.T) {
	env := newTestEnv(t)
	env.setup()
	nodeID := env.createNode("HK-01", "vless", simpleVLESS("hk.example.com"))
	resp, body := env.do(http.MethodPost, "/api/profiles", map[string]any{
		"name": "ACL4", "description": "", "template": "acl4ssr",
		"node_ids": []string{nodeID}, "chain_ids": []string{},
		"default_exit_type": "", "default_exit_id": "", "force_default_exit": false,
		"groups": []any{}, "rules": []any{}, "dns": map[string]any{}, "general": map[string]any{},
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(body))
	var created struct {
		Profile struct {
			ID       string `json:"id"`
			Template string `json:"template"`
		} `json:"profile"`
	}
	require.NoError(t, json.Unmarshal(body, &created))
	require.Equal(t, "acl4ssr", created.Profile.Template)

	resp, body = env.do(http.MethodGet, "/api/profiles/"+created.Profile.ID+"/preview", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	require.Contains(t, string(body), "rule-providers:")
	require.Contains(t, string(body), "acl4ssr-01")
	require.Contains(t, string(body), "RULE-SET,")
	require.Contains(t, string(body), "MATCH,")
	require.Contains(t, string(body), "漏网之鱼")

	resp, body = env.do(http.MethodPost, "/api/profiles", map[string]any{
		"name": "Bad", "template": "unknown", "node_ids": []string{nodeID},
	})
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode, string(body))
}
