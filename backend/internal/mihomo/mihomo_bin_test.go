package mihomo

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGeneratedConfigPassesOfficialMihomo is skipped unless a Mihomo binary is
// available. Set MIHOMO_BIN=/path/to/mihomo (or install `mihomo` in PATH) to
// validate the generated document against the official parser.
func TestGeneratedConfigPassesOfficialMihomo(t *testing.T) {
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		bin, _ = exec.LookPath("mihomo")
	}
	if bin == "" {
		t.Skip("mihomo binary not available; set MIHOMO_BIN to validate")
	}
	nodes := []Node{
		testNode("n1", "HK-01", ProtocolVLESS, Config{
			Server: "hk.example.com", Port: 443,
			UUID: "11111111-1111-4111-8111-111111111111", Flow: "xtls-rprx-vision",
			Network: "tcp", TLS: true, SNI: "hk.example.com", Fingerprint: "chrome",
			Reality: &RealityOptions{PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", ShortID: "abcd"},
		}),
		testNode("n2", "US-02", ProtocolVMess, vmessCfg("us.example.com")),
		testNode("n3", "TJ-01", ProtocolTrojan, Config{
			Server: "tj.example.com", Port: 443, Password: "secret", Network: "grpc",
			SNI: "tj.example.com", GRPC: &GRPCOptions{ServiceName: "grpc"},
		}),
		testNode("n4", "SS-01", ProtocolSS, Config{
			Server: "ss.example.com", Port: 8388, Cipher: "aes-256-gcm", Password: "sspass",
			UDP: boolPtr(true), Extra: map[string]any{"tfo": true},
		}),
		testNode("n5", "HY2-01", ProtocolHysteria2, Config{
			Server: "hy.example.com", Port: 8443, Password: "hypass", SNI: "hy.example.com",
			SkipCertVerify: true, Fingerprint: "chrome", Obfs: "salamander", ObfsPassword: "obfs", Up: "50 mbps", Down: "100 mbps",
		}),
		testNode("n6", "TUIC-01", ProtocolTUIC, Config{
			Server: "tu.example.com", Port: 443, UUID: "33333333-3333-4333-8333-333333333333",
			Password: "tupass", SNI: "tu.example.com", ALPN: []string{"h3"},
			Fingerprint: "chrome", CongestionController: "bbr", UDPRelayMode: "native",
		}),
		testNode("n7", "SOCKS-01", ProtocolSOCKS5, Config{
			Server: "socks.example.com", Port: 1080, Username: "user", Password: "pass", UDP: boolPtr(true),
			TLS: true, SNI: "socks.example.com", ALPN: []string{"h2"}, Fingerprint: "chrome",
		}),
		testNode("n8", "HTTP-01", ProtocolHTTP, Config{
			Server: "http.example.com", Port: 8080, Username: "user", Password: "pass",
			TLS: true, SNI: "http.example.com", ALPN: []string{"h2"}, Fingerprint: "chrome",
		}),
	}
	spec := Spec{
		Nodes: nodes,
		Chains: []Chain{{
			ID: "c1", Name: "chain", Entry: nodes[0], Exit: nodes[1], Enabled: true,
		}},
		Groups: []Group{
			{Name: "Proxy", Type: "select", Proxies: []string{"chain:c1", "node:n2", "node:n3", "DIRECT"}},
			{Name: "Auto", Type: "url-test", Proxies: []string{"node:n1", "node:n4"}, URL: "https://www.gstatic.com/generate_204", Interval: 300},
		},
		Rules: []Rule{
			{Type: "DOMAIN-SUFFIX", Payload: "example.com", Target: "group:Proxy"},
			{Type: "IP-CIDR", Payload: "10.0.0.0/8", Target: "DIRECT", NoResolve: true},
		},
		DNS: map[string]any{
			"enable":        true,
			"ipv6":          false,
			"enhanced-mode": "fake-ip",
			"fake-ip-range": "198.18.0.1/16",
			"nameserver":    []any{"https://1.1.1.1/dns-query"},
		},
		General:          map[string]any{"mode": "rule", "log-level": "info"},
		DefaultExitType:  "chain",
		DefaultExitID:    "c1",
		ForceDefaultExit: true,
	}
	result, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, result.YAML, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-t", "-f", path, "-d", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mihomo rejected generated config: %v\n%s", err, out)
	}
}

func boolPtr(v bool) *bool { return &v }
