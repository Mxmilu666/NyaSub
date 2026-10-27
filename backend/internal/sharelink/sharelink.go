package sharelink

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"nyasub/internal/mihomo"
)

var ErrUnsupportedProtocol = errors.New("protocol cannot be represented as a share link")

// Build converts a node into a standard share link understood by Xray/V2Ray
// clients. The caller supplies the final display name so it stays consistent
// with the generated Mihomo config (including flag prefixes and deduplication).
func Build(node mihomo.Node) (string, error) {
	c := node.Config
	switch node.Protocol {
	case mihomo.ProtocolVLESS:
		return buildVLESS(node.Name, c), nil
	case mihomo.ProtocolVMess:
		return buildVMess(node.Name, c)
	case mihomo.ProtocolTrojan:
		return buildTrojan(node.Name, c), nil
	case mihomo.ProtocolHysteria2:
		return buildHysteria2(node.Name, c), nil
	case mihomo.ProtocolSS:
		return buildSS(node.Name, c), nil
	case mihomo.ProtocolSOCKS5, mihomo.ProtocolHTTP:
		return buildUserPassProxy(node.Name, node.Protocol, c), nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedProtocol, node.Protocol)
	}
}

func hostPort(c mihomo.Config) string {
	return net.JoinHostPort(strings.Trim(c.Server, "[]"), strconv.Itoa(c.Port))
}

func newURL(scheme, hostport, name string) *url.URL {
	return &url.URL{Scheme: scheme, Host: hostport, Fragment: name}
}

func boolValue(value *bool) string {
	if value != nil && *value {
		return "1"
	}
	return "0"
}

func addTLSQuery(q url.Values, c mihomo.Config) {
	if c.SNI != "" {
		q.Set("sni", c.SNI)
	}
	if len(c.ALPN) > 0 {
		q.Set("alpn", strings.Join(c.ALPN, ","))
	}
	if c.Fingerprint != "" {
		q.Set("fp", c.Fingerprint)
	}
	if c.SkipCertVerify {
		q.Set("allowInsecure", "1")
	}
}

func addTransportQuery(q url.Values, c mihomo.Config) string {
	network := c.Network
	if network == "" {
		network = "tcp"
	}
	q.Set("type", network)
	switch network {
	case "ws":
		if c.WS != nil {
			q.Set("path", firstNonEmpty(c.WS.Path, "/"))
			if host := c.WS.Headers["Host"]; host != "" {
				q.Set("host", host)
			}
			if c.WS.MaxEarlyData > 0 {
				q.Set("ed", strconv.Itoa(c.WS.MaxEarlyData))
			}
			if c.WS.EarlyDataHeaderName != "" {
				q.Set("eh", c.WS.EarlyDataHeaderName)
			}
		}
	case "grpc":
		if c.GRPC != nil {
			q.Set("serviceName", c.GRPC.ServiceName)
		}
	case "h2":
		if c.H2 != nil {
			q.Set("path", firstNonEmpty(c.H2.Path, "/"))
			if len(c.H2.Host) > 0 {
				q.Set("host", strings.Join(c.H2.Host, ","))
			}
		}
	case "http":
		if c.HTTP != nil {
			if len(c.HTTP.Path) > 0 {
				q.Set("path", c.HTTP.Path[0])
			}
			if hosts := c.HTTP.Headers["Host"]; len(hosts) > 0 {
				q.Set("host", strings.Join(hosts, ","))
			}
		}
	}
	return network
}

func addExtraQuery(q url.Values, extra map[string]any) {
	for _, key := range []string{"tfo", "mptcp", "packet-encoding", "ip-version"} {
		value, ok := extra[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			if typed {
				q.Set(key, "1")
			} else {
				q.Set(key, "0")
			}
		case string:
			if typed != "" {
				q.Set(key, typed)
			}
		}
	}
}

func buildVLESS(name string, c mihomo.Config) string {
	q := url.Values{}
	encryption := firstNonEmpty(c.Encryption, "none")
	q.Set("encryption", encryption)
	if c.Reality != nil {
		q.Set("security", "reality")
		q.Set("pbk", c.Reality.PublicKey)
		if c.Reality.ShortID != "" {
			q.Set("sid", c.Reality.ShortID)
		}
	} else if c.TLS {
		q.Set("security", "tls")
	}
	addTransportQuery(q, c)
	addTLSQuery(q, c)
	if c.Flow != "" {
		q.Set("flow", c.Flow)
	}
	if c.UDP != nil {
		q.Set("udp", boolValue(c.UDP))
	}
	addExtraQuery(q, c.Extra)
	u := newURL("vless", hostPort(c), name)
	u.User = url.User(c.UUID)
	u.RawQuery = q.Encode()
	return u.String()
}

func buildVMess(name string, c mihomo.Config) (string, error) {
	network := c.Network
	if network == "" {
		network = "tcp"
	}
	fields := map[string]any{
		"v": "2", "ps": name, "add": strings.Trim(c.Server, "[]"),
		"port": strconv.Itoa(c.Port), "id": c.UUID, "aid": strconv.Itoa(c.AlterID),
		"scy": firstNonEmpty(c.Cipher, "auto"), "net": network, "type": "none",
	}
	if c.TLS {
		fields["tls"] = "tls"
	}
	if c.SNI != "" {
		fields["sni"] = c.SNI
	}
	if len(c.ALPN) > 0 {
		fields["alpn"] = strings.Join(c.ALPN, ",")
	}
	if c.Fingerprint != "" {
		fields["fp"] = c.Fingerprint
	}
	switch network {
	case "ws":
		if c.WS != nil {
			fields["path"] = firstNonEmpty(c.WS.Path, "/")
			if host := c.WS.Headers["Host"]; host != "" {
				fields["host"] = host
			}
		}
	case "grpc":
		if c.GRPC != nil {
			// v2rayN/Xray use `path` for the gRPC service name. The extra
			// `servicename` key keeps NyaSub's own importer lossless.
			fields["path"] = c.GRPC.ServiceName
			fields["servicename"] = c.GRPC.ServiceName
		}
	case "h2":
		if c.H2 != nil {
			fields["path"] = firstNonEmpty(c.H2.Path, "/")
			if len(c.H2.Host) > 0 {
				fields["host"] = strings.Join(c.H2.Host, ",")
			}
		}
	case "http":
		if c.HTTP != nil {
			if len(c.HTTP.Path) > 0 {
				fields["path"] = c.HTTP.Path[0]
			}
			if hosts := c.HTTP.Headers["Host"]; len(hosts) > 0 {
				fields["host"] = strings.Join(hosts, ",")
			}
		}
	}
	if c.SkipCertVerify {
		fields["insecure"] = "1"
	}
	if value, ok := c.Extra["tfo"].(bool); ok {
		fields["tfo"] = value
	}
	if value, ok := c.Extra["mptcp"].(bool); ok {
		fields["mptcp"] = value
	}
	if value, ok := c.Extra["packet-encoding"].(string); ok && value != "" {
		fields["packetencoding"] = value
	}
	if value, ok := c.Extra["ip-version"].(string); ok && value != "" {
		fields["ip-version"] = value
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.RawStdEncoding.EncodeToString(raw), nil
}

func buildTrojan(name string, c mihomo.Config) string {
	q := url.Values{}
	q.Set("security", "tls")
	addTransportQuery(q, c)
	addTLSQuery(q, c)
	if c.UDP != nil {
		q.Set("udp", boolValue(c.UDP))
	}
	addExtraQuery(q, c.Extra)
	u := newURL("trojan", hostPort(c), name)
	u.User = url.User(c.Password)
	u.RawQuery = q.Encode()
	return u.String()
}

func buildHysteria2(name string, c mihomo.Config) string {
	q := url.Values{}
	q.Set("security", "tls")
	if c.SNI != "" {
		q.Set("sni", c.SNI)
	}
	if len(c.ALPN) > 0 {
		q.Set("alpn", strings.Join(c.ALPN, ","))
	}
	if c.SkipCertVerify {
		q.Set("insecure", "1")
	}
	if c.Obfs != "" {
		q.Set("obfs", c.Obfs)
	}
	if c.ObfsPassword != "" {
		if q.Get("obfs") == "" {
			q.Set("obfs", "salamander")
		}
		q.Set("obfs-password", c.ObfsPassword)
	}
	if c.Up != "" {
		q.Set("up", c.Up)
	}
	if c.Down != "" {
		q.Set("down", c.Down)
	}
	if c.Ports != "" {
		// v2rayNG and the Hysteria2 URI convention use mport.
		q.Set("mport", c.Ports)
	}
	if c.HopInterval != "" {
		q.Set("hop-interval", c.HopInterval)
	}
	if c.Fingerprint != "" {
		if looksLikeCertFingerprint(c.Fingerprint) {
			q.Set("pinSHA256", c.Fingerprint)
		} else {
			q.Set("fp", c.Fingerprint)
		}
	}
	u := newURL("hysteria2", hostPort(c), name)
	u.User = url.User(c.Password)
	u.RawQuery = q.Encode()
	return u.String()
}

func buildSS(name string, c mihomo.Config) string {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(c.Cipher + ":" + c.Password))
	q := url.Values{}
	if c.Plugin != "" {
		q.Set("plugin", ssPlugin(c.Plugin, c.PluginOpts))
	}
	if c.UDP != nil {
		q.Set("udp", boolValue(c.UDP))
	}
	addExtraQuery(q, c.Extra)
	u := newURL("ss", hostPort(c), name)
	u.User = url.User(userinfo)
	u.RawQuery = q.Encode()
	return u.String()
}

func ssPlugin(name string, options map[string]any) string {
	parts := []string{name}
	switch name {
	case "obfs":
		parts[0] = "obfs-local"
		if mode := optionString(options, "mode"); mode != "" {
			parts = append(parts, "obfs="+mode)
		}
		if host := optionString(options, "host"); host != "" {
			parts = append(parts, "obfs-host="+host)
		}
	case "v2ray-plugin":
		if mode := optionString(options, "mode"); mode != "" {
			parts = append(parts, "mode="+mode)
		}
		if host := optionString(options, "host"); host != "" {
			parts = append(parts, "host="+host)
		}
		if path := optionString(options, "path"); path != "" {
			parts = append(parts, "path="+path)
		}
		if optionBool(options, "tls") {
			parts = append(parts, "tls")
		}
		if optionBool(options, "mux") {
			parts = append(parts, "mux")
		}
	default:
		keys := make([]string, 0, len(options))
		for key := range options {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			switch value := options[key].(type) {
			case bool:
				if value {
					parts = append(parts, key)
				}
			case string:
				if value != "" {
					parts = append(parts, key+"="+value)
				}
			}
		}
	}
	return strings.Join(parts, ";")
}

func buildUserPassProxy(name string, protocol mihomo.Protocol, c mihomo.Config) string {
	scheme := "socks5"
	if protocol == mihomo.ProtocolHTTP {
		if c.TLS {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	q := url.Values{}
	if protocol == mihomo.ProtocolSOCKS5 && c.TLS {
		q.Set("tls", "1")
	}
	addTLSQuery(q, c)
	if c.UDP != nil {
		q.Set("udp", boolValue(c.UDP))
	}
	addExtraQuery(q, c.Extra)
	u := newURL(scheme, hostPort(c), name)
	if c.Username != "" || c.Password != "" {
		u.User = url.UserPassword(c.Username, c.Password)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func optionString(options map[string]any, key string) string {
	value, _ := options[key].(string)
	return value
}

func optionBool(options map[string]any, key string) bool {
	value, _ := options[key].(bool)
	return value
}

// looksLikeCertFingerprint distinguishes a certificate pin from a uTLS
// client fingerprint. Hysteria2 links use pinSHA256 for the former and fp for
// the latter.
func looksLikeCertFingerprint(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) == 64 {
		if _, err := hex.DecodeString(value); err == nil {
			return true
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := encoding.DecodeString(value); err == nil && len(raw) == 32 {
			return true
		}
	}
	return false
}
