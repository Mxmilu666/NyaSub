package mihomo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

type Protocol string

const (
	ProtocolVLESS     Protocol = "vless"
	ProtocolVMess     Protocol = "vmess"
	ProtocolTrojan    Protocol = "trojan"
	ProtocolSS        Protocol = "ss"
	ProtocolHysteria2 Protocol = "hysteria2"
	ProtocolTUIC      Protocol = "tuic"
	ProtocolSOCKS5    Protocol = "socks5"
	ProtocolHTTP      Protocol = "http"
	ProtocolSSH       Protocol = "ssh"
)

var Protocols = []Protocol{
	ProtocolVLESS, ProtocolVMess, ProtocolTrojan, ProtocolSS,
	ProtocolHysteria2, ProtocolTUIC, ProtocolSOCKS5, ProtocolHTTP, ProtocolSSH,
}

func ProtocolValid(p Protocol) bool {
	for _, candidate := range Protocols {
		if p == candidate {
			return true
		}
	}
	return false
}

// MihomoType normalises internal protocol names to Mihomo's `type` values.
func (p Protocol) MihomoType() string {
	if p == ProtocolSS {
		return "ss"
	}
	return string(p)
}

func ProtocolFromMihomoType(t string) (Protocol, bool) {
	switch strings.ToLower(t) {
	case "vless":
		return ProtocolVLESS, true
	case "vmess":
		return ProtocolVMess, true
	case "trojan":
		return ProtocolTrojan, true
	case "ss", "shadowsocks":
		return ProtocolSS, true
	case "hysteria2", "hy2":
		return ProtocolHysteria2, true
	case "tuic":
		return ProtocolTUIC, true
	case "socks5", "socks":
		return ProtocolSOCKS5, true
	case "http", "https":
		return ProtocolHTTP, true
	case "ssh":
		return ProtocolSSH, true
	default:
		return "", false
	}
}

type RealityOptions struct {
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type WSOptions struct {
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
}

type GRPCOptions struct {
	ServiceName string `json:"service_name,omitempty"`
}

type HTTPOptions struct {
	Method  string              `json:"method,omitempty"`
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type H2Options struct {
	Host []string `json:"host,omitempty"`
	Path string   `json:"path,omitempty"`
}

// Config is the extensible protocol configuration stored as JSON. Fields that
// are not first-class are preserved verbatim in Extra (using Mihomo key names)
// so imports never silently lose supported parameters.
type Config struct {
	Server               string          `json:"server"`
	Port                 int             `json:"port"`
	UUID                 string          `json:"uuid,omitempty"`
	AlterID              int             `json:"alter_id,omitempty"`
	Cipher               string          `json:"cipher,omitempty"`
	Password             string          `json:"password,omitempty"`
	Username             string          `json:"username,omitempty"`
	Network              string          `json:"network,omitempty"`
	TLS                  bool            `json:"tls,omitempty"`
	SNI                  string          `json:"sni,omitempty"`
	ALPN                 []string        `json:"alpn,omitempty"`
	SkipCertVerify       bool            `json:"skip_cert_verify,omitempty"`
	Fingerprint          string          `json:"fingerprint,omitempty"`
	Flow                 string          `json:"flow,omitempty"`
	Encryption           string          `json:"encryption,omitempty"`
	Reality              *RealityOptions `json:"reality,omitempty"`
	WS                   *WSOptions      `json:"ws,omitempty"`
	GRPC                 *GRPCOptions    `json:"grpc,omitempty"`
	HTTP                 *HTTPOptions    `json:"http_opts,omitempty"`
	H2                   *H2Options      `json:"h2_opts,omitempty"`
	UDP                  *bool           `json:"udp,omitempty"`
	UDPOverTCP           bool            `json:"udp_over_tcp,omitempty"`
	UDPOverTCPVersion    int             `json:"udp_over_tcp_version,omitempty"`
	Up                   string          `json:"up,omitempty"`
	Down                 string          `json:"down,omitempty"`
	Obfs                 string          `json:"obfs,omitempty"`
	ObfsPassword         string          `json:"obfs_password,omitempty"`
	CongestionController string          `json:"congestion_controller,omitempty"`
	UDPRelayMode         string          `json:"udp_relay_mode,omitempty"`
	ReduceRTT            *bool           `json:"reduce_rtt,omitempty"`
	DisableSNI           bool            `json:"disable_sni,omitempty"`
	Plugin               string          `json:"plugin,omitempty"`
	PluginOpts           map[string]any  `json:"plugin_opts,omitempty"`
	PrivateKey           string          `json:"private_key,omitempty"`
	PrivateKeyPassphrase string          `json:"private_key_passphrase,omitempty"`
	HostKey              []string        `json:"host_key,omitempty"`
	HostKeyAlgorithms    []string        `json:"host_key_algorithms,omitempty"`
	Ports                string          `json:"ports,omitempty"`
	HopInterval          string          `json:"hop_interval,omitempty"`
	Extra                map[string]any  `json:"extra,omitempty"`
}

type Node struct {
	ID       string
	Name     string
	Country  string
	Protocol Protocol
	Config   Config
	Tags     []string
}

type Chain struct {
	ID      string
	Name    string
	Entry   Node
	Exit    Node
	Enabled bool
}

type Group struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Proxies   []string `json:"proxies"`
	URL       string   `json:"url,omitempty"`
	Interval  int      `json:"interval,omitempty"`
	Tolerance int      `json:"tolerance,omitempty"`
	Lazy      bool     `json:"lazy,omitempty"`
	Strategy  string   `json:"strategy,omitempty"`
}

type Rule struct {
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Target    string `json:"target"`
	NoResolve bool   `json:"no_resolve,omitempty"`
}

type Spec struct {
	Nodes            []Node
	Chains           []Chain
	Groups           []Group
	Rules            []Rule
	DNS              map[string]any
	General          map[string]any
	DefaultExitType  string
	DefaultExitID    string
	ForceDefaultExit bool
	UseACL4SSR       bool
}

type Result struct {
	YAML       []byte
	ETag       string
	NodeNames  map[string]string
	ChainNames map[string]string
	GroupNames map[string]string
	Match      string
}

var (
	hostnameRe     = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)
	paddingRe      = regexp.MustCompile(`^[0-9]+-[0-9]+-[0-9]+$`)
	sshAlgorithmRe = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)
	extraKeyRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	cipherRe       = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
	updownRe       = regexp.MustCompile(`(?i)^[0-9]+(\.[0-9]+)?\s*(b|kb|mb|gb|tb|bps|kbps|mbps|gbps|tbps)?$`)
)

var reservedExtraKeys = map[string]bool{
	"name": true, "type": true, "server": true, "port": true,
	"dialer-proxy": true, "proxy-groups": true, "proxies": true, "rules": true,
}

// modeledKeys are rendered explicitly; allowing them in Extra would create
// duplicate or ambiguous YAML keys.
var modeledKeys = map[string]bool{
	"uuid": true, "alterId": true, "cipher": true, "password": true,
	"username": true, "network": true, "tls": true, "servername": true,
	"sni": true, "alpn": true, "skip-cert-verify": true, "client-fingerprint": true,
	"flow": true, "encryption": true, "reality-opts": true, "ws-opts": true, "grpc-opts": true,
	"http-opts": true, "h2-opts": true, "udp": true, "udp-over-tcp": true, "udp-over-tcp-version": true, "up": true, "down": true,
	"obfs": true, "obfs-password": true, "congestion-controller": true,
	"udp-relay-mode": true, "reduce-rtt": true, "disable-sni": true,
	"plugin": true, "plugin-opts": true, "ports": true, "hop-interval": true,
	"private-key": true, "private-key-passphrase": true, "host-key": true, "host-key-algorithms": true,
	"fingerprint": true,
}

// ValidateConfig verifies protocol-specific invariants and rejects unknown
// dangerous extra fields. Error messages never include credential values.
func ValidateConfig(p Protocol, c Config) error {
	if !ProtocolValid(p) {
		return fmt.Errorf("unsupported protocol %q", p)
	}
	if strings.TrimSpace(c.Server) == "" {
		return fmt.Errorf("server must not be empty")
	}
	if len(c.Server) > 253 {
		return fmt.Errorf("server is too long")
	}
	if strings.TrimSpace(c.Server) != c.Server || !hostnameRe.MatchString(c.Server) {
		return fmt.Errorf("server contains invalid characters")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if len(c.Password) > 512 {
		return fmt.Errorf("password is too long")
	}
	if len(c.UUID) > 128 || len(c.SNI) > 253 || len(c.Flow) > 64 || len(c.Fingerprint) > 64 {
		return fmt.Errorf("protocol field is too long")
	}
	if len(c.Username) > 128 || strings.ContainsAny(c.Username, "\r\n") {
		return fmt.Errorf("username is too long or contains line breaks")
	}
	if len(c.PrivateKey) > 32*1024 || len(c.PrivateKeyPassphrase) > 512 {
		return fmt.Errorf("ssh key or passphrase is too long")
	}
	if len(c.HostKey) > 32 || len(c.HostKeyAlgorithms) > 16 {
		return fmt.Errorf("too many ssh host keys or algorithms")
	}
	for _, key := range c.HostKey {
		if key == "" || len(key) > 4096 || strings.ContainsAny(key, "\r\n") {
			return fmt.Errorf("invalid ssh host key")
		}
	}
	for _, algorithm := range c.HostKeyAlgorithms {
		if algorithm == "" || len(algorithm) > 64 || !sshAlgorithmRe.MatchString(algorithm) {
			return fmt.Errorf("invalid ssh host key algorithm")
		}
	}
	if len(c.ALPN) > 8 {
		return fmt.Errorf("too many ALPN values")
	}
	for _, a := range c.ALPN {
		if a == "" || len(a) > 32 || strings.ContainsAny(a, " \t\r\n,") {
			return fmt.Errorf("invalid ALPN value")
		}
	}
	if c.SNI != "" && !hostnameRe.MatchString(c.SNI) {
		return fmt.Errorf("sni contains invalid characters")
	}
	if c.UUID != "" {
		if _, err := uuid.Parse(c.UUID); err != nil {
			return fmt.Errorf("uuid is not a valid UUID")
		}
	}
	if c.Network != "" && c.Network != "tcp" && c.Network != "ws" && c.Network != "grpc" && c.Network != "h2" && c.Network != "http" {
		return fmt.Errorf("unsupported transport network %q", c.Network)
	}
	if c.UDP != nil && p != ProtocolVLESS && p != ProtocolVMess && p != ProtocolTrojan && p != ProtocolSS && p != ProtocolSOCKS5 {
		return fmt.Errorf("udp is not configurable for protocol %s", p)
	}
	if c.UDPOverTCPVersion != 0 && c.UDPOverTCPVersion != 1 && c.UDPOverTCPVersion != 2 {
		return fmt.Errorf("udp-over-tcp-version must be 1 or 2")
	}
	if c.AlterID < 0 || c.AlterID > 65535 {
		return fmt.Errorf("alter_id out of range")
	}
	if c.Cipher != "" && !cipherRe.MatchString(c.Cipher) {
		return fmt.Errorf("cipher contains invalid characters")
	}
	for key := range c.Extra {
		if reservedExtraKeys[key] || modeledKeys[key] || !extraKeyRe.MatchString(key) {
			return fmt.Errorf("unsupported extra field %q", key)
		}
	}
	if raw, err := json.Marshal(c.Extra); err == nil && len(raw) > 64*1024 {
		return fmt.Errorf("extra fields are too large")
	}
	if c.WS != nil {
		if len(c.WS.Path) > 2048 || strings.ContainsAny(c.WS.Path, "\r\n") {
			return fmt.Errorf("invalid websocket path")
		}
		for k, v := range c.WS.Headers {
			if k == "" || len(k) > 128 || strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("invalid websocket header")
			}
		}
	}
	if c.GRPC != nil && (len(c.GRPC.ServiceName) > 256 || strings.ContainsAny(c.GRPC.ServiceName, "\r\n")) {
		return fmt.Errorf("invalid grpc service name")
	}
	if c.WS != nil && c.Network != "ws" {
		return fmt.Errorf("websocket options require network ws")
	}
	if c.GRPC != nil && c.Network != "grpc" {
		return fmt.Errorf("grpc options require network grpc")
	}
	if c.HTTP != nil && c.Network != "http" {
		return fmt.Errorf("http options require network http")
	}
	if c.H2 != nil && c.Network != "h2" {
		return fmt.Errorf("h2 options require network h2")
	}

	switch p {
	case ProtocolVLESS:
		if c.UUID == "" {
			return fmt.Errorf("vless requires a uuid")
		}
		if c.Network != "" && c.Network != "tcp" && c.Network != "ws" && c.Network != "grpc" && c.Network != "h2" && c.Network != "http" {
			return fmt.Errorf("vless does not support network %q", c.Network)
		}
		if err := validateVLESSEncryption(c.Encryption); err != nil {
			return err
		}
		if c.Reality != nil && c.Reality.PublicKey == "" {
			return fmt.Errorf("reality public key is required")
		}
	case ProtocolVMess:
		if c.UUID == "" {
			return fmt.Errorf("vmess requires a uuid")
		}
	case ProtocolTrojan:
		if c.Password == "" {
			return fmt.Errorf("trojan requires a password")
		}
		if c.Network != "" && c.Network != "tcp" && c.Network != "ws" && c.Network != "grpc" {
			return fmt.Errorf("trojan does not support network %q", c.Network)
		}
	case ProtocolSS:
		if c.Password == "" {
			return fmt.Errorf("shadowsocks requires a password")
		}
		if c.Cipher == "" {
			return fmt.Errorf("shadowsocks requires a cipher")
		}
	case ProtocolHysteria2:
		if c.Password == "" {
			return fmt.Errorf("hysteria2 requires a password")
		}
		if c.Up != "" && !updownRe.MatchString(c.Up) {
			return fmt.Errorf("invalid hysteria2 up rate")
		}
		if c.Down != "" && !updownRe.MatchString(c.Down) {
			return fmt.Errorf("invalid hysteria2 down rate")
		}
		if c.Obfs != "" && c.Obfs != "salamander" {
			return fmt.Errorf("unsupported hysteria2 obfs %q", c.Obfs)
		}
	case ProtocolTUIC:
		if c.UUID == "" || c.Password == "" {
			return fmt.Errorf("tuic requires uuid and password")
		}
		if c.Network != "" {
			return fmt.Errorf("tuic does not support a transport network")
		}
	case ProtocolSSH:
		if strings.TrimSpace(c.Username) == "" {
			return fmt.Errorf("ssh requires a username")
		}
		if c.Password == "" && c.PrivateKey == "" {
			return fmt.Errorf("ssh requires a password or private key")
		}
	case ProtocolSOCKS5, ProtocolHTTP:
		if (c.Username == "") != (c.Password == "") {
			return fmt.Errorf("%s requires both username and password when authentication is used", p)
		}
		if c.Network != "" {
			return fmt.Errorf("%s does not support a transport network", p)
		}
	}
	if err := validateProtocolFields(p, c); err != nil {
		return err
	}
	return nil
}

// validateVLESSEncryption accepts the formats understood by Mihomo's
// transport/vless/encryption client: "none"/empty, or
// mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<padding-or-key>...
// Key length is intentionally not pinned to 32/1184 bytes: newer clients have
// emitted other key encodings, and Mihomo itself performs the final parse.
func validateVLESSEncryption(value string) error {
	if value == "" || value == "none" {
		return nil
	}
	if len(value) > 4096 {
		return fmt.Errorf("vless encryption value is too long")
	}
	parts := strings.Split(value, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return fmt.Errorf("unsupported vless encryption value")
	}
	switch parts[1] {
	case "native", "xorpub", "random":
	default:
		return fmt.Errorf("unsupported vless encryption mode")
	}
	switch parts[2] {
	case "1rtt", "0rtt":
	default:
		return fmt.Errorf("unsupported vless encryption RTT mode")
	}
	keys := 0
	for _, part := range parts[3:] {
		if len(part) < 20 {
			if !paddingRe.MatchString(part) {
				return fmt.Errorf("invalid vless encryption padding")
			}
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return fmt.Errorf("invalid vless encryption key")
		}
		if len(key) != 32 && len(key) != 1184 {
			return fmt.Errorf("invalid vless encryption key length (Mihomo accepts 32 or 1184 bytes, got %d)", len(key))
		}
		keys++
	}
	if keys == 0 {
		return fmt.Errorf("vless encryption requires a key")
	}
	return nil
}

func ValidateName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("must be valid UTF-8")
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("must not be empty")
	}
	if len([]rune(trimmed)) > 80 {
		return fmt.Errorf("must be at most 80 characters")
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("must not contain control characters")
		}
	}
	if strings.ContainsRune(trimmed, ',') {
		return fmt.Errorf("must not contain commas (Mihomo rule targets are comma-delimited)")
	}
	return nil
}

func CloneConfig(c Config) Config {
	raw, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(raw, &out)
	return out
}

// validateProtocolFields rejects fields that the renderer would not emit for
// this protocol. This prevents silent data loss in API writes and imports.
func validateProtocolFields(p Protocol, c Config) error {
	bad := map[string]bool{}
	set := func(name string, present bool) {
		if present {
			bad[name] = true
		}
	}
	commonUnsupported := func() {
		set("flow", c.Flow != "" && p != ProtocolVLESS)
		set("encryption", c.Encryption != "" && p != ProtocolVLESS)
		set("reality", c.Reality != nil && p != ProtocolVLESS)
		set("plugin", c.Plugin != "" && p != ProtocolSS)
		set("plugin_opts", len(c.PluginOpts) > 0 && p != ProtocolSS)
		set("up", c.Up != "" && p != ProtocolHysteria2)
		set("down", c.Down != "" && p != ProtocolHysteria2)
		set("obfs", c.Obfs != "" && p != ProtocolHysteria2)
		set("obfs_password", c.ObfsPassword != "" && p != ProtocolHysteria2)
		set("ports", c.Ports != "" && p != ProtocolHysteria2)
		set("hop_interval", c.HopInterval != "" && p != ProtocolHysteria2)
		set("congestion_controller", c.CongestionController != "" && p != ProtocolTUIC)
		set("udp_relay_mode", c.UDPRelayMode != "" && p != ProtocolTUIC)
		set("reduce_rtt", c.ReduceRTT != nil && p != ProtocolTUIC)
		set("disable_sni", c.DisableSNI && p != ProtocolTUIC)
		set("username", c.Username != "" && p != ProtocolSOCKS5 && p != ProtocolHTTP && p != ProtocolSSH)
		set("alter_id", c.AlterID != 0 && p != ProtocolVMess)
		set("udp_over_tcp", c.UDPOverTCP && p != ProtocolSS)
		set("udp_over_tcp_version", c.UDPOverTCPVersion != 0 && p != ProtocolSS)
		set("private_key", c.PrivateKey != "" && p != ProtocolSSH)
		set("private_key_passphrase", c.PrivateKeyPassphrase != "" && p != ProtocolSSH)
		set("host_key", len(c.HostKey) > 0 && p != ProtocolSSH)
		set("host_key_algorithms", len(c.HostKeyAlgorithms) > 0 && p != ProtocolSSH)
		set("cipher", c.Cipher != "" && p != ProtocolVMess && p != ProtocolSS)
		set("uuid", c.UUID != "" && p != ProtocolVLESS && p != ProtocolVMess && p != ProtocolTUIC)
		set("password", c.Password != "" && p != ProtocolTrojan && p != ProtocolSS && p != ProtocolHysteria2 && p != ProtocolTUIC && p != ProtocolSOCKS5 && p != ProtocolHTTP && p != ProtocolSSH)
		set("alpn", len(c.ALPN) > 0 && (p == ProtocolSS || p == ProtocolSSH))
		set("sni", c.SNI != "" && (p == ProtocolSS || p == ProtocolSSH))
		set("fingerprint", c.Fingerprint != "" && (p == ProtocolSS || p == ProtocolSSH))
		set("skip_cert_verify", c.SkipCertVerify && (p == ProtocolSS || p == ProtocolSSH))
		set("tls", c.TLS && (p == ProtocolSS || p == ProtocolSSH))
		set("network", c.Network != "" && p != ProtocolVLESS && p != ProtocolVMess && p != ProtocolTrojan)
	}
	commonUnsupported()
	if len(bad) == 0 {
		return nil
	}
	keys := make([]string, 0, len(bad))
	for key := range bad {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return fmt.Errorf("%s does not support fields: %s", p, strings.Join(keys, ", "))
}
