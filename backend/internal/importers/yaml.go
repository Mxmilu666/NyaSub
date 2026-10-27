package importers

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"nyasub/internal/mihomo"
)

func parseYAML(content string, result *Result) {
	dec := yaml.NewDecoder(strings.NewReader(content))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			result.Issues = append(result.Issues, Issue{Message: "YAML content is empty"})
			return
		}
		result.Issues = append(result.Issues, Issue{Source: "yaml", Message: "invalid YAML: " + err.Error()})
		return
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		result.Issues = append(result.Issues, Issue{Source: "yaml", Message: "multiple YAML documents are not supported"})
		return
	}
	if err := inspectNode(&doc, 0, new(int)); err != nil {
		result.Issues = append(result.Issues, Issue{Source: "yaml", Message: err.Error()})
		return
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	var seq *yaml.Node
	switch root.Kind {
	case yaml.SequenceNode:
		seq = root
	case yaml.MappingNode:
		if p := mappingValue(root, "proxies"); p != nil {
			if p.Kind != yaml.SequenceNode {
				result.Issues = append(result.Issues, Issue{Line: p.Line, Source: "yaml", Message: "proxies must be a YAML array"})
				return
			}
			seq = p
		} else if mappingValue(root, "type") != nil && mappingValue(root, "server") != nil {
			seq = &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{root}}
		} else {
			result.Issues = append(result.Issues, Issue{Source: "yaml", Message: "no proxies array found in YAML"})
			return
		}
	default:
		result.Issues = append(result.Issues, Issue{Source: "yaml", Message: "YAML root must be an object or array"})
		return
	}

	for _, proxyNode := range seq.Content {
		if len(result.Items) >= MaxItems {
			result.Issues = append(result.Issues, Issue{Line: proxyNode.Line, Source: "yaml", Message: fmt.Sprintf("node limit of %d reached", MaxItems)})
			return
		}
		item, err := parseProxyNode(proxyNode)
		if err != nil {
			result.Issues = append(result.Issues, Issue{Line: proxyNode.Line, Source: "yaml", Message: err.Error()})
			continue
		}
		item.Line = proxyNode.Line
		item.Source = "yaml"
		result.Items = append(result.Items, *item)
	}
}

func inspectNode(n *yaml.Node, depth int, count *int) error {
	*count++
	if *count > 50000 {
		return fmt.Errorf("YAML document is too complex")
	}
	if depth > 16 {
		return fmt.Errorf("YAML nesting is too deep")
	}
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases and anchors are not allowed")
	}
	if n.Tag != "" && strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return fmt.Errorf("custom YAML tags are not allowed")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return fmt.Errorf("YAML mapping keys must be scalars")
			}
			if seen[k.Value] {
				return fmt.Errorf("duplicate YAML key %q", k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := inspectNode(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

var commonProxyFields = map[string]bool{
	"name": true, "type": true, "server": true, "port": true,
	"tfo": true, "mptcp": true, "ip-version": true, "interface-name": true,
	"routing-mark": true, "smux": true, "udp": true,
}

var protocolProxyFields = map[mihomo.Protocol]map[string]bool{
	mihomo.ProtocolVLESS: {
		"uuid": true, "flow": true, "encryption": true, "network": true, "tls": true, "servername": true,
		"sni": true, "alpn": true, "skip-cert-verify": true, "client-fingerprint": true,
		"reality-opts": true, "ws-opts": true, "grpc-opts": true, "http-opts": true,
		"h2-opts": true, "packet-encoding": true,
	},
	mihomo.ProtocolVMess: {
		"uuid": true, "alterId": true, "cipher": true, "network": true, "tls": true,
		"servername": true, "sni": true, "alpn": true, "skip-cert-verify": true,
		"client-fingerprint": true, "ws-opts": true, "grpc-opts": true,
		"http-opts": true, "h2-opts": true, "packet-encoding": true,
	},
	mihomo.ProtocolTrojan: {
		"password": true, "network": true, "sni": true, "servername": true,
		"alpn": true, "skip-cert-verify": true, "client-fingerprint": true,
		"ws-opts": true, "grpc-opts": true,
	},
	mihomo.ProtocolSS: {
		"cipher": true, "password": true, "plugin": true, "plugin-opts": true,
		"udp-over-tcp": true, "udp-over-tcp-version": true,
	},
	mihomo.ProtocolHysteria2: {
		"password": true, "sni": true, "servername": true, "alpn": true,
		"skip-cert-verify": true, "fingerprint": true, "client-fingerprint": true, "obfs": true,
		"obfs-password": true, "up": true, "down": true, "ports": true, "hop-interval": true,
	},
	mihomo.ProtocolTUIC: {
		"uuid": true, "password": true, "sni": true, "servername": true, "alpn": true,
		"skip-cert-verify": true, "client-fingerprint": true, "disable-sni": true, "reduce-rtt": true,
		"congestion-controller": true, "udp-relay-mode": true, "udp-over-stream": true,
		"heartbeat-interval": true,
	},
	mihomo.ProtocolSOCKS5: {
		"username": true, "password": true, "tls": true, "skip-cert-verify": true,
		"sni": true, "servername": true, "alpn": true, "client-fingerprint": true,
	},
	mihomo.ProtocolHTTP: {
		"username": true, "password": true, "tls": true, "skip-cert-verify": true,
		"sni": true, "servername": true, "alpn": true, "client-fingerprint": true, "headers": true,
	},
	mihomo.ProtocolSSH: {
		"username": true, "password": true, "private-key": true, "private-key-passphrase": true,
		"host-key": true, "host-key-algorithms": true,
	},
}

func parseProxyNode(n *yaml.Node) (*Item, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("each proxy must be an object")
	}
	raw := map[string]any{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i].Value
		var value any
		if err := n.Content[i+1].Decode(&value); err != nil {
			return nil, fmt.Errorf("%s: %v", key, err)
		}
		raw[key] = value
	}
	name, _ := raw["name"].(string)
	typeName, _ := raw["type"].(string)
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("proxy name is required")
	}
	if typeName == "" {
		return nil, fmt.Errorf("proxy type is required")
	}
	protocol, ok := mihomo.ProtocolFromMihomoType(typeName)
	if !ok {
		return nil, fmt.Errorf("unsupported proxy type %q", typeName)
	}
	allowed := protocolProxyFields[protocol]
	extraAllowed := map[string]bool{
		"tfo": true, "mptcp": true, "ip-version": true, "interface-name": true,
		"routing-mark": true, "smux": true, "packet-encoding": true,
	}
	for key := range raw {
		if commonProxyFields[key] || allowed[key] {
			continue
		}
		if protocol == mihomo.ProtocolHTTP && key == "headers" {
			continue
		}
		if extraAllowed[key] {
			continue
		}
		return nil, fmt.Errorf("proxy %q uses unsupported field %q", name, key)
	}

	server, _ := raw["server"].(string)
	server = strings.TrimSpace(server)
	if server == "" {
		return nil, fmt.Errorf("proxy %q is missing server", name)
	}
	port, err := toInt(raw["port"])
	if err != nil {
		return nil, fmt.Errorf("proxy %q has invalid port", name)
	}
	c := mihomo.Config{Server: server, Port: port}
	getStr := func(key string) string {
		return yamlScalar(raw[key])
	}
	getBool := func(key string) bool {
		b, _ := raw[key].(bool)
		return b
	}
	getStrings := func(key string) []string {
		switch v := raw[key].(type) {
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
			return out
		case []string:
			return v
		case string:
			return splitComma(v)
		default:
			return nil
		}
	}
	switch protocol {
	case mihomo.ProtocolVLESS, mihomo.ProtocolVMess:
		c.UUID = getStr("uuid")
		c.Cipher = getStr("cipher")
		c.Network = strings.ToLower(getStr("network"))
		c.TLS = getBool("tls")
		c.SNI = firstNonEmpty(getStr("servername"), getStr("sni"))
		c.ALPN = getStrings("alpn")
		c.SkipCertVerify = getBool("skip-cert-verify")
		c.Fingerprint = getStr("client-fingerprint")
		c.Flow = getStr("flow")
		c.Encryption = getStr("encryption")
		if protocol == mihomo.ProtocolVMess {
			if v, ok := raw["alterId"]; ok {
				c.AlterID, err = toInt(v)
				if err != nil {
					return nil, fmt.Errorf("proxy %q has invalid alterId", name)
				}
			}
		}
		if r := raw["reality-opts"]; r != nil {
			m, ok := r.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("proxy %q has invalid reality-opts", name)
			}
			if err := checkNestedKeys(name, "reality-opts", m, "public-key", "short-id"); err != nil {
				return nil, err
			}
			reality := &mihomo.RealityOptions{}
			if s, ok := m["public-key"].(string); ok {
				reality.PublicKey = s
			}
			if s, ok := m["short-id"].(string); ok {
				reality.ShortID = s
			}
			c.Reality = reality
			c.TLS = true
		}
	case mihomo.ProtocolTrojan:
		c.Password = getStr("password")
		c.Network = strings.ToLower(getStr("network"))
		c.SNI = firstNonEmpty(getStr("sni"), getStr("servername"))
		c.ALPN = getStrings("alpn")
		c.SkipCertVerify = getBool("skip-cert-verify")
		c.Fingerprint = getStr("client-fingerprint")
		c.TLS = true
	case mihomo.ProtocolSSH:
		c.Username = getStr("username")
		c.Password = getStr("password")
		c.PrivateKey = getStr("private-key")
		c.PrivateKeyPassphrase = getStr("private-key-passphrase")
		c.HostKey = getStrings("host-key")
		c.HostKeyAlgorithms = getStrings("host-key-algorithms")
	case mihomo.ProtocolSS:
		c.Cipher = getStr("cipher")
		c.Password = getStr("password")
		c.UDPOverTCP = getBool("udp-over-tcp")
		if v, ok := raw["udp-over-tcp-version"]; ok {
			c.UDPOverTCPVersion, err = toInt(v)
			if err != nil {
				return nil, fmt.Errorf("proxy %q has invalid udp-over-tcp-version", name)
			}
		}
		c.Plugin = getStr("plugin")
		if po, ok := raw["plugin-opts"].(map[string]any); ok {
			c.PluginOpts = po
		}
	case mihomo.ProtocolHysteria2:
		c.Password = getStr("password")
		c.SNI = firstNonEmpty(getStr("sni"), getStr("servername"))
		c.ALPN = getStrings("alpn")
		c.SkipCertVerify = getBool("skip-cert-verify")
		certFingerprint := getStr("fingerprint")
		clientFingerprint := getStr("client-fingerprint")
		if certFingerprint != "" && clientFingerprint != "" && certFingerprint != clientFingerprint {
			return nil, fmt.Errorf("proxy %q specifies both fingerprint and client-fingerprint", name)
		}
		c.Fingerprint = firstNonEmpty(certFingerprint, clientFingerprint)
		c.Obfs = getStr("obfs")
		c.ObfsPassword = getStr("obfs-password")
		c.Up = getStr("up")
		c.Down = getStr("down")
		c.Ports = getStr("ports")
		c.HopInterval = getStr("hop-interval")
		c.TLS = true
	case mihomo.ProtocolTUIC:
		c.UUID = getStr("uuid")
		c.Password = getStr("password")
		c.SNI = firstNonEmpty(getStr("sni"), getStr("servername"))
		c.ALPN = getStrings("alpn")
		c.SkipCertVerify = getBool("skip-cert-verify")
		c.DisableSNI = getBool("disable-sni")
		c.Fingerprint = getStr("client-fingerprint")
		c.CongestionController = getStr("congestion-controller")
		c.UDPRelayMode = getStr("udp-relay-mode")
		if v, ok := raw["reduce-rtt"].(bool); ok {
			c.ReduceRTT = &v
		}
		c.TLS = true
	case mihomo.ProtocolSOCKS5, mihomo.ProtocolHTTP:
		c.Username = getStr("username")
		c.Password = getStr("password")
		c.TLS = getBool("tls")
		c.SkipCertVerify = getBool("skip-cert-verify")
		c.SNI = firstNonEmpty(getStr("sni"), getStr("servername"))
		c.ALPN = getStrings("alpn")
		c.Fingerprint = getStr("client-fingerprint")
		if protocol == mihomo.ProtocolHTTP {
			if h, ok := raw["headers"].(map[string]any); ok {
				c.Extra = map[string]any{"headers": h}
			}
		}
	}
	if v, ok := raw["udp"].(bool); ok {
		c.UDP = &v
	}
	if wsNode := raw["ws-opts"]; wsNode != nil {
		m, ok := wsNode.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proxy %q has invalid ws-opts", name)
		}
		if err := checkNestedKeys(name, "ws-opts", m, "path", "headers", "max-early-data", "early-data-header-name"); err != nil {
			return nil, err
		}
		ws := &mihomo.WSOptions{}
		if s, ok := m["path"].(string); ok {
			ws.Path = s
		}
		if headers, ok := m["headers"].(map[string]any); ok {
			ws.Headers = map[string]string{}
			for k, v := range headers {
				if s, ok := v.(string); ok {
					ws.Headers[k] = s
				}
			}
		}
		if n, ok := m["max-early-data"]; ok {
			ws.MaxEarlyData, _ = toInt(n)
		}
		if s, ok := m["early-data-header-name"].(string); ok {
			ws.EarlyDataHeaderName = s
		}
		c.WS = ws
	}
	if grpcNode := raw["grpc-opts"]; grpcNode != nil {
		m, ok := grpcNode.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proxy %q has invalid grpc-opts", name)
		}
		if err := checkNestedKeys(name, "grpc-opts", m, "grpc-service-name"); err != nil {
			return nil, err
		}
		grpc := &mihomo.GRPCOptions{}
		if s, ok := m["grpc-service-name"].(string); ok {
			grpc.ServiceName = s
		}
		c.GRPC = grpc
	}
	if httpNode := raw["http-opts"]; httpNode != nil {
		m, ok := httpNode.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proxy %q has invalid http-opts", name)
		}
		if err := checkNestedKeys(name, "http-opts", m, "method", "path", "headers"); err != nil {
			return nil, err
		}
		opts := &mihomo.HTTPOptions{}
		if s, ok := m["method"].(string); ok {
			opts.Method = s
		}
		switch p := m["path"].(type) {
		case string:
			opts.Path = []string{p}
		case []any:
			for _, item := range p {
				if s, ok := item.(string); ok {
					opts.Path = append(opts.Path, s)
				}
			}
		}
		if headers, ok := m["headers"].(map[string]any); ok {
			opts.Headers = map[string][]string{}
			for k, v := range headers {
				switch hv := v.(type) {
				case string:
					opts.Headers[k] = []string{hv}
				case []any:
					for _, item := range hv {
						if s, ok := item.(string); ok {
							opts.Headers[k] = append(opts.Headers[k], s)
						}
					}
				}
			}
		}
		c.HTTP = opts
	}
	if h2Node := raw["h2-opts"]; h2Node != nil {
		m, ok := h2Node.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proxy %q has invalid h2-opts", name)
		}
		if err := checkNestedKeys(name, "h2-opts", m, "host", "path"); err != nil {
			return nil, err
		}
		opts := &mihomo.H2Options{}
		switch h := m["host"].(type) {
		case string:
			opts.Host = splitComma(h)
		case []any:
			for _, item := range h {
				if s, ok := item.(string); ok {
					opts.Host = append(opts.Host, s)
				}
			}
		}
		if s, ok := m["path"].(string); ok {
			opts.Path = s
		}
		c.H2 = opts
	}

	if c.Extra == nil {
		c.Extra = map[string]any{}
	}
	for _, key := range []string{"tfo", "mptcp", "ip-version", "interface-name", "routing-mark", "smux", "packet-encoding", "udp-over-stream", "heartbeat-interval"} {
		if v, ok := raw[key]; ok {
			c.Extra[key] = v
		}
	}
	if len(c.Extra) == 0 {
		c.Extra = nil
	}
	if err := mihomo.ValidateConfig(protocol, c); err != nil {
		return nil, fmt.Errorf("proxy %q: %w", name, err)
	}
	return &Item{Name: name, Protocol: protocol, Config: c}, nil
}

func toInt(v any) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case uint64:
		return int(val), nil
	case float64:
		return int(val), nil
	case string:
		return strconv.Atoi(strings.TrimSpace(val))
	default:
		return 0, fmt.Errorf("not a number")
	}
}

func yamlScalar(v any) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	default:
		return ""
	}
}

func checkNestedKeys(proxyName, section string, m map[string]any, allowed ...string) error {
	allowedSet := map[string]bool{}
	for _, key := range allowed {
		allowedSet[key] = true
	}
	for key := range m {
		if !allowedSet[key] {
			return fmt.Errorf("proxy %q %s has unsupported field %q", proxyName, section, key)
		}
	}
	return nil
}
