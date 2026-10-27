package importers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"nyasub/internal/mihomo"
)

func mustParseOne(t *testing.T, uri string) *Item {
	t.Helper()
	item, err := ParseURI(uri)
	require.NoError(t, err)
	return item
}

func TestParseVLESSRealityAndWebSocket(t *testing.T) {
	item := mustParseOne(t, "vless://11111111-1111-4111-8111-111111111111@hk.example.com:443?encryption=none&security=reality&sni=hk.example.com&fp=chrome&pbk=pubkey&sid=abcd&type=ws&path=%2Fray&host=cdn.example.com&flow=xtls-rprx-vision&alpn=h2,http%2F1.1#HK%20Node")
	require.Equal(t, mihomo.ProtocolVLESS, item.Protocol)
	require.Equal(t, "HK Node", item.Name)
	require.Equal(t, "hk.example.com", item.Config.Server)
	require.Equal(t, 443, item.Config.Port)
	require.Equal(t, "11111111-1111-4111-8111-111111111111", item.Config.UUID)
	require.True(t, item.Config.TLS)
	require.Equal(t, "pubkey", item.Config.Reality.PublicKey)
	require.Equal(t, "abcd", item.Config.Reality.ShortID)
	require.Equal(t, "ws", item.Config.Network)
	require.Equal(t, "/ray", item.Config.WS.Path)
	require.Equal(t, "cdn.example.com", item.Config.WS.Headers["Host"])
	require.Equal(t, []string{"h2", "http/1.1"}, item.Config.ALPN)
	require.Equal(t, "xtls-rprx-vision", item.Config.Flow)
}

func TestParseVMessBase64JSON(t *testing.T) {
	payload := map[string]any{
		"v": "2", "ps": "JP-03", "add": "jp.example.com", "port": "443",
		"id": "22222222-2222-4222-8222-222222222222", "aid": "0", "scy": "auto",
		"net": "grpc", "type": "gun", "serviceName": "svc", "tls": "tls",
		"sni": "jp.example.com", "alpn": "h2", "fp": "chrome",
	}
	raw, _ := json.Marshal(payload)
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	item := mustParseOne(t, "vmess://"+encoded)
	require.Equal(t, mihomo.ProtocolVMess, item.Protocol)
	require.Equal(t, "JP-03", item.Name)
	require.Equal(t, "jp.example.com", item.Config.Server)
	require.Equal(t, 443, item.Config.Port)
	require.Equal(t, "grpc", item.Config.Network)
	require.Equal(t, "svc", item.Config.GRPC.ServiceName)
	require.True(t, item.Config.TLS)
	require.Equal(t, []string{"h2"}, item.Config.ALPN)
}

func TestParseTrojanSSHysteria2TUIC(t *testing.T) {
	trojan := mustParseOne(t, "trojan://secret@tj.example.com:443?security=tls&sni=tj.example.com&type=grpc&serviceName=grpcsvc#TJ")
	require.Equal(t, mihomo.ProtocolTrojan, trojan.Protocol)
	require.Equal(t, "secret", trojan.Config.Password)
	require.Equal(t, "grpcsvc", trojan.Config.GRPC.ServiceName)

	ssUser := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:sspass"))
	ss := mustParseOne(t, "ss://"+ssUser+"@ss.example.com:8388#SS")
	require.Equal(t, mihomo.ProtocolSS, ss.Protocol)
	require.Equal(t, "aes-256-gcm", ss.Config.Cipher)
	require.Equal(t, "sspass", ss.Config.Password)

	legacyPayload := base64.RawStdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:legacy@old.example.com:9000"))
	legacy := mustParseOne(t, "ss://"+legacyPayload+"#Legacy")
	require.Equal(t, "old.example.com", legacy.Config.Server)
	require.Equal(t, 9000, legacy.Config.Port)
	require.Equal(t, "legacy", legacy.Config.Password)

	hy2 := mustParseOne(t, "hysteria2://authpass@hy.example.com:8443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=obfspass&up=50%20mbps&down=100%20mbps#HY2")
	require.Equal(t, mihomo.ProtocolHysteria2, hy2.Protocol)
	require.Equal(t, "authpass", hy2.Config.Password)
	require.True(t, hy2.Config.SkipCertVerify)
	require.Equal(t, "salamander", hy2.Config.Obfs)
	require.Equal(t, "50 mbps", hy2.Config.Up)
	require.Equal(t, "100 mbps", hy2.Config.Down)

	tuic := mustParseOne(t, "tuic://33333333-3333-4333-8333-333333333333:tpass@tu.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tu.example.com&allow_insecure=1&reduce_rtt=1&disable_sni=1#TUIC")
	require.Equal(t, mihomo.ProtocolTUIC, tuic.Protocol)
	require.Equal(t, "33333333-3333-4333-8333-333333333333", tuic.Config.UUID)
	require.Equal(t, "tpass", tuic.Config.Password)
	require.Equal(t, "bbr", tuic.Config.CongestionController)
	require.Equal(t, "native", tuic.Config.UDPRelayMode)
	require.True(t, tuic.Config.DisableSNI)
	require.NotNil(t, tuic.Config.ReduceRTT)
	require.True(t, *tuic.Config.ReduceRTT)
}

func TestParseSocksHTTPAndSSPlugin(t *testing.T) {
	socks := mustParseOne(t, "socks5://user:pass@socks.example.com:1080?udp=1#SOCKS")
	require.Equal(t, mihomo.ProtocolSOCKS5, socks.Protocol)
	require.Equal(t, "user", socks.Config.Username)
	require.Equal(t, "pass", socks.Config.Password)
	require.NotNil(t, socks.Config.UDP)
	require.True(t, *socks.Config.UDP)

	httpNode := mustParseOne(t, "https://user:pass@http.example.com:8443#HTTP")
	require.Equal(t, mihomo.ProtocolHTTP, httpNode.Protocol)
	require.True(t, httpNode.Config.TLS)

	ssUser := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw"))
	plugin := mustParseOne(t, "ss://"+ssUser+"@ss.example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#Plugin")
	require.Equal(t, "obfs", plugin.Config.Plugin)
	require.Equal(t, "http", plugin.Config.PluginOpts["mode"])
	require.Equal(t, "bing.com", plugin.Config.PluginOpts["host"])
}

func TestUnknownAndUnsupportedFieldsAreExplicit(t *testing.T) {
	_, err := ParseURI("vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=tls&unknown=x#A")
	require.ErrorContains(t, err, "unknown")
	_, err = ParseURI("vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=reality&pbk=p&spx=%2F#A")
	require.ErrorContains(t, err, "spx")
	_, err = ParseURI("trojan://pw@a.example.com:443?headertype=http#A")
	require.ErrorContains(t, err, "header type")
	_, err = ParseURI("not-a-link")
	require.Error(t, err)
}

func TestParseYAMLProxiesAndFullConfig(t *testing.T) {
	full := `
mixed-port: 7890
proxies:
  - name: YAML VLESS
    type: vless
    server: v.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: ws
    tls: true
    servername: v.example.com
    ws-opts:
      path: /ws
      headers:
        Host: v.example.com
    packet-encoding: xudp
  - name: YAML SS
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pass
    udp: true
proxy-groups: []
rules: []
`
	result := Parse(full, "yaml")
	require.Empty(t, result.Issues)
	require.Len(t, result.Items, 2)
	require.Equal(t, mihomo.ProtocolVLESS, result.Items[0].Protocol)
	require.Equal(t, "xudp", result.Items[0].Config.Extra["packet-encoding"])
	require.Equal(t, "/ws", result.Items[0].Config.WS.Path)
	require.Equal(t, mihomo.ProtocolSS, result.Items[1].Protocol)
	require.NotNil(t, result.Items[1].Config.UDP)

	seq := `
- name: A
  type: trojan
  server: a.example.com
  port: 443
  password: pw
`
	seqResult := Parse(seq, "yaml")
	require.Empty(t, seqResult.Issues)
	require.Len(t, seqResult.Items, 1)

	single := `
name: single
type: socks5
server: s.example.com
port: 1080
`
	singleResult := Parse(single, "yaml")
	require.Empty(t, singleResult.Issues)
	require.Len(t, singleResult.Items, 1)
}

func TestYAMLImportErrors(t *testing.T) {
	unknown := `
proxies:
  - name: A
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
    bogus-field: true
`
	result := Parse(unknown, "yaml")
	require.Empty(t, result.Items)
	require.Contains(t, testError(result), "unsupported field")

	alias := `
proxies:
  - &p
    name: A
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
  - *p
`
	aliasResult := Parse(alias, "yaml")
	require.Contains(t, testError(aliasResult), "aliases")

	bad := `
proxies:
  - name: A
    type: vless
    server: s.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    unknown: x
`
	require.Contains(t, testError(Parse(bad, "yaml")), "unsupported field")
}

func TestParseBatchReportsPerLineIssues(t *testing.T) {
	content := strings.Join([]string{
		"vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=tls#A",
		"bad-line",
		"trojan://pw@b.example.com:443?security=tls#B",
	}, "\n")
	result := Parse(content, "uri")
	require.Len(t, result.Items, 2)
	require.Len(t, result.Issues, 1)
	require.Equal(t, 2, result.Issues[0].Line)
}

func testError(result Result) string {
	if len(result.Issues) == 0 {
		return ""
	}
	parts := make([]string, 0, len(result.Issues))
	for _, issue := range result.Issues {
		parts = append(parts, issue.Message)
	}
	return strings.Join(parts, "; ")
}

func TestParseBase64V2RaySubscription(t *testing.T) {
	plain := strings.Join([]string{
		"vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=tls#A",
		"trojan://pw@b.example.com:443?security=tls#B",
	}, "\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	encoded = encoded[:20] + "\n" + encoded[20:]
	result := Parse(encoded, "auto")
	require.Empty(t, result.Issues)
	require.Len(t, result.Items, 2)
	require.Equal(t, "A", result.Items[0].Name)
	require.Equal(t, "B", result.Items[1].Name)
	require.Equal(t, "uri", result.Items[0].Source)
}

func TestParseBase64MihomoSubscription(t *testing.T) {
	plain := `
mixed-port: 7890
mode: rule
proxies:
  - name: B64-SS
    type: ss
    server: s.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw
`
	result := Parse(base64.RawURLEncoding.EncodeToString([]byte(plain)), "auto")
	require.Empty(t, result.Issues)
	require.Len(t, result.Items, 1)
	require.Equal(t, "B64-SS", result.Items[0].Name)

	single := "name: B64-ONE\ntype: socks5\nserver: one.example.com\nport: 1080\n"
	singleResult := Parse(base64.StdEncoding.EncodeToString([]byte(single)), "auto")
	require.Empty(t, singleResult.Issues)
	require.Len(t, singleResult.Items, 1)
	require.Equal(t, "B64-ONE", singleResult.Items[0].Name)
}

func TestSubscriptionFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "NyaSub/1.0", r.Header.Get("User-Agent"))
		switch r.URL.Path {
		case "/ok":
			_, _ = io.WriteString(w, "vless://11111111-1111-4111-8111-111111111111@a.example.com:443#A")
		case "/empty":
			w.WriteHeader(http.StatusOK)
		case "/large":
			_, _ = io.WriteString(w, strings.Repeat("a", MaxSubscriptionBytes+1))
		default:
			http.Error(w, "no", http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	fetcher := &SubscriptionFetcher{client: srv.Client()}
	ctx := context.Background()

	content, err := fetcher.Fetch(ctx, srv.URL+"/ok")
	require.NoError(t, err)
	require.Contains(t, content, "vless://")

	_, err = fetcher.Fetch(ctx, srv.URL+"/empty")
	require.ErrorIs(t, err, ErrEmptySubscription)

	_, err = fetcher.Fetch(ctx, srv.URL+"/large")
	require.ErrorIs(t, err, ErrSubscriptionTooLarge)

	_, err = fetcher.Fetch(ctx, srv.URL+"/missing")
	require.ErrorIs(t, err, ErrSubscriptionFetch)

	_, err = fetcher.Fetch(ctx, "file:///etc/passwd")
	require.ErrorIs(t, err, ErrInvalidSubscriptionURL)

	_, err = fetcher.Fetch(ctx, "https://user:pass@example.com/sub")
	require.ErrorIs(t, err, ErrInvalidSubscriptionURL)

	_, err = fetcher.Fetch(ctx, "https://example.com/"+strings.Repeat("a", maxSubscriptionURL))
	require.ErrorIs(t, err, ErrInvalidSubscriptionURL)
}

func TestSubscriptionFetcherRejectsPrivateTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should not be reached")
	}))
	defer srv.Close()
	_, err := NewSubscriptionFetcher().Fetch(context.Background(), srv.URL)
	require.ErrorIs(t, err, ErrBlockedSubscriptionTarget)
	require.NotContains(t, err.Error(), srv.URL)
	require.NotContains(t, err.Error(), "http")
}

func TestSubscriptionErrorsDoNotContainURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()
	fetcher := &SubscriptionFetcher{client: srv.Client()}
	_, err := fetcher.Fetch(context.Background(), srv.URL+"/private-token")
	require.ErrorIs(t, err, ErrSubscriptionFetch)
	require.NotContains(t, err.Error(), "private-token")
	require.NotContains(t, err.Error(), srv.URL)
}

func TestIsPublicIP(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1"} {
		require.False(t, isPublicIP(net.ParseIP(raw)), raw)
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		require.True(t, isPublicIP(net.ParseIP(raw)), raw)
	}
}

const sampleVLESSEncryption = "mlkem768x25519plus.native.0rtt.1wZcnLa4tFbs8Hu210chlpE4xbn3qESjp67toIqe2Dg"
const invalidVLESSEncryption = "mlkem768x25519plus.native.0rtt.-phJ1ZNPr5oDHsjMLvks2AR_svkbeOCplqs5lUlQwed5rUoAg3KwuwbQlpOqb7InU8AgHnbHOlkzL6zJzdodzLgpojYT9SIBlJLIRsBJjzBw6spz-XFa6pKSgyEqRlFmJKqzD8detXVqmGEapakzD9NEhFcg6js5B4IDkYBJIXkBAOXC4XqLfLo3QiVuLJjOJfeunuM10mMkmaFB3-sIzQcVQDMGqyfOYQjIlGR3rtyZ41zDf_pcJZi_6ttpvRMwJwauFOK"

func TestParseVLESSEncryption(t *testing.T) {
	item := mustParseOne(t, "vless://11111111-1111-4111-8111-111111111111@sub.example.com:443?encryption="+sampleVLESSEncryption+"&security=tls#ENC")
	require.Equal(t, mihomo.ProtocolVLESS, item.Protocol)
	require.Equal(t, sampleVLESSEncryption, item.Config.Encryption)

	_, err := ParseURI("vless://11111111-1111-4111-8111-111111111111@a.example.com:443?encryption=mlkem768x25519plus.bogus.0rtt.1wZcnLa4tFbs8Hu210chlpE4xbn3qESjp67toIqe2Dg")
	require.ErrorContains(t, err, "encryption")

	_, err = ParseURI("vless://11111111-1111-4111-8111-111111111111@a.example.com:443?encryption=" + invalidVLESSEncryption)
	require.ErrorContains(t, err, "key length")
}

func TestYAMLImportVLESSEncryption(t *testing.T) {
	content := `
proxies:
  - name: ENC
    type: vless
    server: enc.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    encryption: "` + sampleVLESSEncryption + `"
`
	result := Parse(content, "yaml")
	require.Empty(t, result.Issues)
	require.Len(t, result.Items, 1)
	require.Equal(t, sampleVLESSEncryption, result.Items[0].Config.Encryption)
}

func TestYAMLImportSSH(t *testing.T) {
	content := `
proxies:
  - name: SSH-NODE
    type: ssh
    server: ssh.example.com
    port: 22
    username: root
    password: secret
    host-key:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"
    host-key-algorithms:
      - ssh-ed25519
`
	result := Parse(content, "yaml")
	require.Empty(t, result.Issues)
	require.Len(t, result.Items, 1)
	item := result.Items[0]
	require.Equal(t, mihomo.ProtocolSSH, item.Protocol)
	require.Equal(t, "root", item.Config.Username)
	require.Equal(t, "secret", item.Config.Password)
	require.Equal(t, []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"}, item.Config.HostKey)
	require.Equal(t, []string{"ssh-ed25519"}, item.Config.HostKeyAlgorithms)
}

func TestYAMLImportShadowsocksUDPOverTCP(t *testing.T) {
	content := `
proxies:
  - name: UK
    type: ss
    server: 45.196.97.89
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp: true
    udp-over-tcp: true
    udp-over-tcp-version: 2
`
	result := Parse(content, "yaml")
	require.Empty(t, result.Issues)
	require.Len(t, result.Items, 1)
	require.True(t, result.Items[0].Config.UDPOverTCP)
	require.Equal(t, 2, result.Items[0].Config.UDPOverTCPVersion)
}
