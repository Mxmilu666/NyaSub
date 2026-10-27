package mihomo

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func testNode(id, name string, protocol Protocol, cfg Config) Node {
	return Node{ID: id, Name: name, Protocol: protocol, Config: cfg}
}

func vlessCfg(server string) Config {
	return Config{Server: server, Port: 443, UUID: "11111111-1111-4111-8111-111111111111", Network: "tcp", TLS: true, SNI: server}
}

func vmessCfg(server string) Config {
	return Config{Server: server, Port: 8443, UUID: "22222222-2222-4222-8222-222222222222", Cipher: "auto", Network: "ws", TLS: true, SNI: server, WS: &WSOptions{Path: "/ws", Headers: map[string]string{"Host": server}}}
}

type parsedConfig struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Proxies []string `yaml:"proxies"`
		URL     string   `yaml:"url"`
	} `yaml:"proxy-groups"`
	Rules []string `yaml:"rules"`
}

func parseGenerated(t *testing.T, raw []byte) parsedConfig {
	t.Helper()
	var out parsedConfig
	require.NoError(t, yaml.Unmarshal(raw, &out))
	return out
}

func TestChainGenerationAndDialerProxy(t *testing.T) {
	entry := testNode("00000000-0000-4000-8000-000000000001", "HK-01", ProtocolVLESS, vlessCfg("hk.example.com"))
	exit := testNode("00000000-0000-4000-8000-000000000002", "US-02", ProtocolVMess, vmessCfg("us.example.com"))
	spec := Spec{
		Nodes:  []Node{entry, exit},
		Chains: []Chain{{ID: "chain-1", Name: "HK to US", Entry: entry, Exit: exit, Enabled: true}},
	}
	result, err := Generate(spec)
	require.NoError(t, err)
	require.Equal(t, "🇭🇰 HK-01", result.NodeNames[entry.ID])
	require.Equal(t, "🇺🇸 US-02", result.NodeNames[exit.ID])
	require.Equal(t, "🇭🇰 → 🇺🇸 HK-01 → US-02", result.ChainNames["chain-1"])

	parsed := parseGenerated(t, result.YAML)
	require.Len(t, parsed.Proxies, 3)
	chainProxy := parsed.Proxies[2]
	require.Equal(t, "🇭🇰 → 🇺🇸 HK-01 → US-02", chainProxy["name"])
	require.Equal(t, "🇭🇰 HK-01", chainProxy["dialer-proxy"])
	require.Equal(t, "us.example.com", chainProxy["server"])
	require.Equal(t, "/ws", chainProxy["ws-opts"].(map[string]any)["path"])
	// The original exit node is untouched.
	require.NotContains(t, parsed.Proxies[1], "dialer-proxy")
	require.Equal(t, "🇺🇸 US-02", parsed.Proxies[1]["name"])
}

func TestNodeNameCollisionIsDeterministic(t *testing.T) {
	n1 := testNode("00000000-0000-4000-8000-000000000002", "Same", ProtocolVLESS, vlessCfg("b.example.com"))
	n2 := testNode("00000000-0000-4000-8000-000000000001", "Same", ProtocolVLESS, vlessCfg("a.example.com"))
	exit := testNode("00000000-0000-4000-8000-000000000003", "Exit", ProtocolVMess, vmessCfg("exit.example.com"))
	spec := Spec{
		Nodes:  []Node{n1, n2, exit},
		Chains: []Chain{{ID: "chain", Entry: n2, Exit: exit, Enabled: true}},
	}
	first, err := Generate(spec)
	require.NoError(t, err)
	second, err := Generate(spec)
	require.NoError(t, err)
	require.Equal(t, first.YAML, second.YAML)
	require.Equal(t, first.ETag, second.ETag)
	require.Equal(t, "Same", first.NodeNames[n2.ID])
	require.Equal(t, "Same (2)", first.NodeNames[n1.ID])

	parsed := parseGenerated(t, first.YAML)
	chain := parsed.Proxies[3]
	require.Equal(t, "Same → Exit", chain["name"])
	require.Equal(t, "Same", chain["dialer-proxy"])
	require.Equal(t, "Exit", parsed.Proxies[0]["name"])
	require.Equal(t, "Same", parsed.Proxies[1]["name"])
	require.Equal(t, "Same (2)", parsed.Proxies[2]["name"])
}

func TestDefaultExitForceModes(t *testing.T) {
	entry := testNode("n1", "HK-01", ProtocolVLESS, vlessCfg("hk.example.com"))
	exit := testNode("n2", "US-02", ProtocolVMess, vmessCfg("us.example.com"))
	chain := Chain{ID: "c1", Name: "chain", Entry: entry, Exit: exit, Enabled: true}

	forced, err := Generate(Spec{
		Nodes: []Node{entry, exit}, Chains: []Chain{chain},
		DefaultExitType: "chain", DefaultExitID: "c1", ForceDefaultExit: true,
	})
	require.NoError(t, err)
	require.Equal(t, "🇭🇰 → 🇺🇸 HK-01 → US-02", forced.Match)
	require.Contains(t, parseGenerated(t, forced.YAML).Rules, "MATCH,🇭🇰 → 🇺🇸 HK-01 → US-02")

	soft, err := Generate(Spec{
		Nodes: []Node{entry, exit}, Chains: []Chain{chain},
		DefaultExitType: "chain", DefaultExitID: "c1",
	})
	require.NoError(t, err)
	parsed := parseGenerated(t, soft.YAML)
	require.Len(t, parsed.Groups, 1)
	require.Equal(t, "select", parsed.Groups[0].Type)
	require.Equal(t, "🇭🇰 → 🇺🇸 HK-01 → US-02", parsed.Groups[0].Proxies[0])
	require.Equal(t, "MATCH,"+parsed.Groups[0].Name, parsed.Rules[len(parsed.Rules)-1])
}

func TestGroupRulesAndReferences(t *testing.T) {
	entry := testNode("n1", "日本 01", ProtocolVLESS, vlessCfg("jp.example.com"))
	exit := testNode("n2", "US-02", ProtocolVMess, vmessCfg("us.example.com"))
	groups := []Group{
		{Name: "Proxy", Type: "select", Proxies: []string{"group:Auto", "chain:c1", "node:n1", "DIRECT"}},
		{Name: "Auto", Type: "url-test", Proxies: []string{"chain:c1", "node:n1"}, URL: "https://www.gstatic.com/generate_204", Interval: 300},
	}
	rules := []Rule{
		{Type: "DOMAIN-SUFFIX", Payload: "google.com", Target: "group:Proxy"},
		{Type: "IP-CIDR", Payload: "10.0.0.0/8", Target: "DIRECT", NoResolve: true},
	}
	result, err := Generate(Spec{
		Nodes: []Node{entry, exit}, Chains: []Chain{{ID: "c1", Entry: entry, Exit: exit, Enabled: true}},
		Groups: groups, Rules: rules,
	})
	require.NoError(t, err)
	parsed := parseGenerated(t, result.YAML)
	require.Equal(t, "Proxy", parsed.Groups[0].Name)
	require.Equal(t, []string{"Auto", "🇯🇵 → 🇺🇸 日本 01 → US-02", "🇯🇵 日本 01", "DIRECT"}, parsed.Groups[0].Proxies)
	require.Equal(t, "https://www.gstatic.com/generate_204", parsed.Groups[1].URL)
	require.Contains(t, parsed.Rules, "DOMAIN-SUFFIX,google.com,Proxy")
	require.Contains(t, parsed.Rules, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
	require.Equal(t, "MATCH,Proxy", parsed.Rules[len(parsed.Rules)-1])
}

func TestGroupCycleRejected(t *testing.T) {
	n := testNode("n1", "A", ProtocolSS, Config{Server: "a.example.com", Port: 8388, Cipher: "aes-256-gcm", Password: "x"})
	_, err := Generate(Spec{
		Nodes: []Node{n},
		Groups: []Group{
			{Name: "A", Type: "select", Proxies: []string{"group:B"}},
			{Name: "B", Type: "select", Proxies: []string{"group:A"}},
		},
	})
	require.ErrorContains(t, err, "cycle")
}

func TestDefaultExitNodeAndForcedMode(t *testing.T) {
	a := testNode("n1", "A", ProtocolSS, Config{Server: "a.example.com", Port: 8388, Cipher: "aes-256-gcm", Password: "x"})
	b := testNode("n2", "B", ProtocolSS, Config{Server: "b.example.com", Port: 8388, Cipher: "aes-256-gcm", Password: "y"})
	result, err := Generate(Spec{Nodes: []Node{a, b}, DefaultExitType: "node", DefaultExitID: "n2", ForceDefaultExit: true})
	require.NoError(t, err)
	require.Equal(t, "B", result.Match)
}

func TestUnicodeAndQuotingYAML(t *testing.T) {
	names := []string{"日本 01", "on", "a: b", "#hash", "true", "quote\"d"}
	nodes := make([]Node, 0, len(names))
	for i, name := range names {
		nodes = append(nodes, testNode(string(rune('a'+i)), name, ProtocolSS, Config{
			Server: "s.example.com", Port: 8000 + i, Cipher: "aes-256-gcm", Password: "pw",
		}))
	}
	result, err := Generate(Spec{Nodes: nodes})
	require.NoError(t, err)
	require.Contains(t, string(result.YAML), "日本 01")
	parsed := parseGenerated(t, result.YAML)
	require.Len(t, parsed.Proxies, len(names))
	seen := map[string]bool{}
	for _, p := range parsed.Proxies {
		seen[p["name"].(string)] = true
	}
	for _, name := range names {
		display := exportDisplayName(name, "")
		require.True(t, seen[display], "missing name %q", display)
	}
}

func TestGenerateRejectsSelfChainAndMissingDefaults(t *testing.T) {
	n := testNode("n1", "A", ProtocolSS, Config{Server: "a.example.com", Port: 8388, Cipher: "aes-256-gcm", Password: "x"})
	_, err := Generate(Spec{Nodes: []Node{n}, Chains: []Chain{{ID: "c1", Entry: n, Exit: n, Enabled: true}}})
	require.ErrorContains(t, err, "same entry and exit")
	_, err = Generate(Spec{Nodes: []Node{n}, DefaultExitType: "node", DefaultExitID: "missing"})
	require.ErrorContains(t, err, "default exit")
}

func TestProxyExtraFieldsPreserved(t *testing.T) {
	n := testNode("n1", "A", ProtocolVLESS, Config{
		Server: "a.example.com", Port: 443, UUID: "11111111-1111-4111-8111-111111111111",
		Network: "tcp", TLS: true, Extra: map[string]any{"packet-encoding": "xudp", "tfo": true},
	})
	result, err := Generate(Spec{Nodes: []Node{n}})
	require.NoError(t, err)
	parsed := parseGenerated(t, result.YAML)
	require.Equal(t, "xudp", parsed.Proxies[0]["packet-encoding"])
	require.Equal(t, true, parsed.Proxies[0]["tfo"])
	require.True(t, strings.Contains(string(result.YAML), "packet-encoding: xudp"))
}

func TestVLESSEncryptionExported(t *testing.T) {
	cfg := vlessCfg("enc.example.com")
	cfg.Encryption = "mlkem768x25519plus.native.0rtt.1wZcnLa4tFbs8Hu210chlpE4xbn3qESjp67toIqe2Dg"
	result, err := Generate(Spec{Nodes: []Node{testNode("n1", "ENC", ProtocolVLESS, cfg)}})
	require.NoError(t, err)
	parsed := parseGenerated(t, result.YAML)
	require.Equal(t, cfg.Encryption, parsed.Proxies[0]["encryption"])
}

func TestSSHExport(t *testing.T) {
	cfg := Config{
		Server: "ssh.example.com", Port: 22, Username: "root", Password: "pw",
		HostKey: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"}, HostKeyAlgorithms: []string{"ssh-ed25519"},
	}
	result, err := Generate(Spec{Nodes: []Node{testNode("n1", "SSH", ProtocolSSH, cfg)}})
	require.NoError(t, err)
	parsed := parseGenerated(t, result.YAML)
	require.Equal(t, "ssh", parsed.Proxies[0]["type"])
	require.Equal(t, "root", parsed.Proxies[0]["username"])
	require.Equal(t, "ssh-ed25519", parsed.Proxies[0]["host-key-algorithms"].([]any)[0])
}

func TestShadowsocksUDPOverTCPExport(t *testing.T) {
	cfg := Config{
		Server: "ss.example.com", Port: 8388, Cipher: "aes-128-gcm", Password: "pw",
		UDP: boolPtr(true), UDPOverTCP: true, UDPOverTCPVersion: 2,
	}
	result, err := Generate(Spec{Nodes: []Node{testNode("n1", "SS-UOT", ProtocolSS, cfg)}})
	require.NoError(t, err)
	parsed := parseGenerated(t, result.YAML)
	require.Equal(t, true, parsed.Proxies[0]["udp-over-tcp"])
	require.Equal(t, 2, parsed.Proxies[0]["udp-over-tcp-version"])
}

func TestCountryManualOverride(t *testing.T) {
	auto := testNode("n1", "BT-UK", ProtocolVLESS, vlessCfg("a.example.com"))
	manual := testNode("n2", "JP-01", ProtocolVLESS, vlessCfg("b.example.com"))
	manual.Country = "GB"
	result, err := Generate(Spec{Nodes: []Node{auto, manual}})
	require.NoError(t, err)
	require.Equal(t, "🇬🇧 BT-UK", result.NodeNames[auto.ID])
	require.Equal(t, "🇬🇧 JP-01", result.NodeNames[manual.ID])
}

func TestACL4SSRGeneration(t *testing.T) {
	a := testNode("n1", "HK-01", ProtocolVLESS, vlessCfg("hk.example.com"))
	b := testNode("n2", "US-02", ProtocolVMess, vmessCfg("us.example.com"))
	result, err := Generate(Spec{Nodes: []Node{a, b}, UseACL4SSR: true})
	require.NoError(t, err)
	require.Equal(t, "🐟 漏网之鱼", result.Match)
	require.NotEmpty(t, result.GroupNames)

	parsed := parseGenerated(t, result.YAML)
	require.NotEmpty(t, parsed.Groups)
	require.Contains(t, parsed.Rules, "MATCH,🐟 漏网之鱼")
	require.Contains(t, parsed.Rules, "GEOIP,CN,🎯 全球直连")
	require.Contains(t, parsed.Rules, "RULE-SET,acl4ssr-01,🎯 全球直连")

	var doc struct {
		RuleProviders map[string]map[string]any `yaml:"rule-providers"`
	}
	require.NoError(t, yaml.Unmarshal(result.YAML, &doc))
	require.NotEmpty(t, doc.RuleProviders)
	require.Equal(t, "classical", doc.RuleProviders["acl4ssr-01"]["behavior"])

	selectIndex := -1
	for i := range parsed.Groups {
		if parsed.Groups[i].Name == "🚀 节点选择" {
			selectIndex = i
		}
	}
	require.GreaterOrEqual(t, selectIndex, 0)
	require.Contains(t, parsed.Groups[selectIndex].Proxies, "🇭🇰 HK-01")
	require.Contains(t, parsed.Groups[selectIndex].Proxies, "🇺🇸 US-02")
}

func TestACL4SSRExcludesLandingNodesFromSelection(t *testing.T) {
	entry := testNode("n1", "HK-01", ProtocolVLESS, vlessCfg("hk.example.com"))
	landing := testNode("n2", "JP-01", ProtocolVMess, vmessCfg("jp.example.com"))
	landing.Tags = []string{"落地机"}
	chain := Chain{ID: "c1", Entry: entry, Exit: landing, Enabled: true}
	result, err := Generate(Spec{
		Nodes: []Node{entry, landing}, Chains: []Chain{chain}, UseACL4SSR: true,
	})
	require.NoError(t, err)
	parsed := parseGenerated(t, result.YAML)
	groups := map[string][]string{}
	for _, group := range parsed.Groups {
		groups[group.Name] = group.Proxies
	}
	require.NotContains(t, groups["🚀 节点选择"], "🇯🇵 JP-01")
	require.NotContains(t, groups["♻️ 自动选择"], "🇯🇵 JP-01")
	require.Contains(t, groups["🌍 国外媒体"], "🇯🇵 JP-01")
	require.Contains(t, groups["🚀 节点选择"], "🇭🇰 → 🇯🇵 HK-01 → JP-01")
}
