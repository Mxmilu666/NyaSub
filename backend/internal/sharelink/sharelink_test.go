package sharelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"nyasub/internal/importers"
	"nyasub/internal/mihomo"
)

func TestBuildRoundTripsThroughImporter(t *testing.T) {
	udp := true
	tests := []struct {
		name     string
		node     mihomo.Node
		protocol mihomo.Protocol
		check    func(t *testing.T, config mihomo.Config)
	}{
		{
			name: "vless-reality-ws",
			node: mihomo.Node{Name: "🇭🇰 HK-01", Protocol: mihomo.ProtocolVLESS, Config: mihomo.Config{
				Server: "hk.example.com", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
				TLS: true, SNI: "cdn.example.com", Network: "ws", Flow: "xtls-rprx-vision",
				Reality: &mihomo.RealityOptions{PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", ShortID: "abcd"},
				WS:      &mihomo.WSOptions{Path: "/ws", Headers: map[string]string{"Host": "cdn.example.com"}},
				ALPN:    []string{"h2", "http/1.1"}, Fingerprint: "chrome", UDP: &udp,
			}},
			protocol: mihomo.ProtocolVLESS,
			check: func(t *testing.T, config mihomo.Config) {
				if config.Server != "hk.example.com" || config.Port != 443 {
					t.Fatalf("server/port = %s/%d", config.Server, config.Port)
				}
				if config.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
					t.Fatalf("uuid = %q", config.UUID)
				}
				if !config.TLS || config.Reality == nil || config.Reality.PublicKey == "" {
					t.Fatalf("reality/tls lost: %+v", config)
				}
				if config.Network != "ws" || config.WS == nil || config.WS.Path != "/ws" {
					t.Fatalf("ws lost: %+v", config)
				}
				if config.WS.Headers["Host"] != "cdn.example.com" {
					t.Fatalf("ws host lost: %+v", config.WS)
				}
				if config.SNI != "cdn.example.com" || config.Flow != "xtls-rprx-vision" {
					t.Fatalf("tls fields lost: %+v", config)
				}
				if config.UDP == nil || !*config.UDP {
					t.Fatalf("udp lost")
				}
			},
		},
		{
			name: "vmess-ws",
			node: mihomo.Node{Name: "US-02", Protocol: mihomo.ProtocolVMess, Config: mihomo.Config{
				Server: "us.example.com", Port: 8443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
				AlterID: 0, Cipher: "auto", TLS: true, SNI: "us.example.com", Network: "ws",
				WS: &mihomo.WSOptions{Path: "/vm", Headers: map[string]string{"Host": "us.example.com"}},
			}},
			protocol: mihomo.ProtocolVMess,
			check: func(t *testing.T, config mihomo.Config) {
				if config.Server != "us.example.com" || config.Port != 8443 || config.Network != "ws" {
					t.Fatalf("vmess base lost: %+v", config)
				}
				if !config.TLS || config.SNI != "us.example.com" {
					t.Fatalf("vmess tls lost: %+v", config)
				}
				if config.WS == nil || config.WS.Path != "/vm" || config.WS.Headers["Host"] != "us.example.com" {
					t.Fatalf("vmess ws lost: %+v", config.WS)
				}
			},
		},
		{
			name: "trojan-grpc",
			node: mihomo.Node{Name: "JP-03", Protocol: mihomo.ProtocolTrojan, Config: mihomo.Config{
				Server: "jp.example.com", Port: 443, Password: "secret", TLS: true, SNI: "jp.example.com",
				Network: "grpc", GRPC: &mihomo.GRPCOptions{ServiceName: "svc"}, UDP: &udp,
			}},
			protocol: mihomo.ProtocolTrojan,
			check: func(t *testing.T, config mihomo.Config) {
				if config.Password != "secret" || config.Network != "grpc" || config.GRPC == nil {
					t.Fatalf("trojan lost: %+v", config)
				}
				if config.GRPC.ServiceName != "svc" || config.SNI != "jp.example.com" {
					t.Fatalf("trojan grpc lost: %+v", config)
				}
			},
		},
		{
			name: "hysteria2",
			node: mihomo.Node{Name: "HY-05", Protocol: mihomo.ProtocolHysteria2, Config: mihomo.Config{
				Server: "hy.example.com", Port: 443, Password: "hy-pass", SNI: "hy.example.com",
				ALPN: []string{"h3"}, SkipCertVerify: true, Obfs: "salamander", ObfsPassword: "obfs-pass",
				Up: "100 mbps", Down: "500 mbps", Ports: "20000-30000", HopInterval: "30s",
				Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			}},
			protocol: mihomo.ProtocolHysteria2,
			check: func(t *testing.T, config mihomo.Config) {
				if config.Password != "hy-pass" || config.Server != "hy.example.com" {
					t.Fatalf("hysteria2 base lost: %+v", config)
				}
				if !config.TLS || config.SNI != "hy.example.com" || !config.SkipCertVerify {
					t.Fatalf("hysteria2 tls lost: %+v", config)
				}
				if config.Obfs != "salamander" || config.ObfsPassword != "obfs-pass" {
					t.Fatalf("hysteria2 obfs lost: %+v", config)
				}
				if config.Ports != "20000-30000" || config.HopInterval != "30s" {
					t.Fatalf("hysteria2 port hopping lost: %+v", config)
				}
				if config.Fingerprint != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
					t.Fatalf("hysteria2 pin lost: %+v", config)
				}
			},
		},
		{
			name: "ss-obfs",
			node: mihomo.Node{Name: "SG-04", Protocol: mihomo.ProtocolSS, Config: mihomo.Config{
				Server: "sg.example.com", Port: 8388, Cipher: "aes-256-gcm", Password: "p@ss",
				Plugin: "obfs", PluginOpts: map[string]any{"mode": "tls", "host": "bing.com"}, UDP: &udp,
			}},
			protocol: mihomo.ProtocolSS,
			check: func(t *testing.T, config mihomo.Config) {
				if config.Cipher != "aes-256-gcm" || config.Password != "p@ss" {
					t.Fatalf("ss credentials lost: %+v", config)
				}
				if config.Plugin != "obfs" || config.PluginOpts["mode"] != "tls" || config.PluginOpts["host"] != "bing.com" {
					t.Fatalf("ss plugin lost: %+v", config)
				}
			},
		},
		{
			name: "socks5-tls",
			node: mihomo.Node{Name: "SOCKS", Protocol: mihomo.ProtocolSOCKS5, Config: mihomo.Config{
				Server: "socks.example.com", Port: 1080, Username: "u", Password: "p", TLS: true, SNI: "socks.example.com",
			}},
			protocol: mihomo.ProtocolSOCKS5,
			check: func(t *testing.T, config mihomo.Config) {
				if config.Username != "u" || config.Password != "p" || !config.TLS {
					t.Fatalf("socks lost: %+v", config)
				}
			},
		},
		{
			name: "http",
			node: mihomo.Node{Name: "HTTP", Protocol: mihomo.ProtocolHTTP, Config: mihomo.Config{
				Server: "http.example.com", Port: 8080, Username: "u", Password: "p",
			}},
			protocol: mihomo.ProtocolHTTP,
			check: func(t *testing.T, config mihomo.Config) {
				if config.Username != "u" || config.Password != "p" || config.Port != 8080 {
					t.Fatalf("http lost: %+v", config)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			link, err := Build(test.node)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if !strings.HasPrefix(link, string(test.protocol)+"://") {
				t.Fatalf("scheme = %q", link)
			}
			item, err := importers.ParseURI(link)
			if err != nil {
				t.Fatalf("round trip failed: %v\n%s", err, link)
			}
			if item.Protocol != test.protocol {
				t.Fatalf("protocol = %s", item.Protocol)
			}
			if item.Name != test.node.Name {
				t.Fatalf("name = %q, want %q", item.Name, test.node.Name)
			}
			test.check(t, item.Config)
		})
	}
}

func TestVMessGRPCUsesPathAndStandardInsecureField(t *testing.T) {
	node := mihomo.Node{Name: "gRPC", Protocol: mihomo.ProtocolVMess, Config: mihomo.Config{
		Server: "grpc.example.com", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLS: true, SNI: "grpc.example.com", Network: "grpc",
		GRPC: &mihomo.GRPCOptions{ServiceName: "my-service"}, SkipCertVerify: true,
	}}
	link, err := Build(node)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("json: %v", err)
	}
	if fields["path"] != "my-service" {
		t.Fatalf("gRPC path = %v, want service name", fields["path"])
	}
	if fields["type"] != "none" {
		t.Fatalf("type = %v, want none", fields["type"])
	}
	if fields["insecure"] != "1" {
		t.Fatalf("insecure = %v", fields["insecure"])
	}
	if _, exists := fields["mode"]; exists {
		t.Fatalf("unexpected gRPC mode field")
	}
}

func TestBuildRejectsXrayIncompatibleProtocols(t *testing.T) {
	for _, protocol := range []mihomo.Protocol{mihomo.ProtocolTUIC, mihomo.ProtocolSSH} {
		_, err := Build(mihomo.Node{Name: "x", Protocol: protocol, Config: mihomo.Config{Server: "example.com", Port: 443}})
		if !errors.Is(err, ErrUnsupportedProtocol) {
			t.Fatalf("%s: err = %v", protocol, err)
		}
	}
}
