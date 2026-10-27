package importers

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"nyasub/internal/mihomo"
)

type Item struct {
	Name     string          `json:"name"`
	Protocol mihomo.Protocol `json:"protocol"`
	Config   mihomo.Config   `json:"config"`
	Tags     []string        `json:"tags,omitempty"`
	Source   string          `json:"source"`
	Line     int             `json:"line"`
	Warnings []string        `json:"warnings,omitempty"`
}

type Issue struct {
	Line    int    `json:"line"`
	Source  string `json:"source"`
	Message string `json:"message"`
}

type Result struct {
	Items  []Item  `json:"items"`
	Issues []Issue `json:"issues"`
}

const (
	MaxContentBytes = 1 << 20
	MaxItems        = 500
)

// Parse parses a batch of share links or a Mihomo proxies document.
func Parse(content, format string) Result {
	result := Result{Items: []Item{}, Issues: []Issue{}}
	if len(content) > MaxContentBytes {
		result.Issues = append(result.Issues, Issue{Message: "import content exceeds 1 MiB"})
		return result
	}
	content = normalizeImportContent(content)
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		format = detectFormat(content)
	}
	switch format {
	case "uri":
		parseURIs(content, &result)
	case "yaml":
		parseYAML(content, &result)
	default:
		result.Issues = append(result.Issues, Issue{Message: "format must be auto, uri or yaml"})
	}
	if len(result.Items) > MaxItems {
		result.Issues = append(result.Issues, Issue{Message: fmt.Sprintf("at most %d nodes can be imported at once", MaxItems)})
		result.Items = result.Items[:MaxItems]
	}
	return result
}

func detectFormat(content string) string {
	first := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first = line
		break
	}
	if first == "" {
		return "uri"
	}
	lower := strings.ToLower(first)
	if strings.HasPrefix(lower, "proxies:") ||
		strings.HasPrefix(first, "{") || strings.HasPrefix(first, "[") ||
		strings.HasPrefix(first, "- ") ||
		(!strings.Contains(first, "://") && strings.Contains(first, ":") && !strings.HasPrefix(lower, "http")) {
		return "yaml"
	}
	return "uri"
}

func parseURIs(content string, result *Result) {
	for idx, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		lineNo := idx + 1
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(result.Items) >= MaxItems {
			result.Issues = append(result.Issues, Issue{Line: lineNo, Message: fmt.Sprintf("node limit of %d reached", MaxItems)})
			return
		}
		item, err := ParseURI(line)
		if err != nil {
			result.Issues = append(result.Issues, Issue{Line: lineNo, Source: redactURI(line), Message: err.Error()})
			continue
		}
		item.Line = lineNo
		item.Source = "uri"
		result.Items = append(result.Items, *item)
	}
}

// ParseURI parses a single share link.
func ParseURI(line string) (*Item, error) {
	scheme, _, ok := strings.Cut(line, "://")
	if !ok {
		return nil, fmt.Errorf("not a share link (missing ://)")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(line)
	case "vmess":
		return parseVMess(line)
	case "trojan":
		return parseTrojan(line)
	case "ss":
		return parseSS(line)
	case "hysteria2", "hy2":
		return parseHysteria2(line)
	case "tuic":
		return parseTUIC(line)
	case "socks5", "socks":
		return parseSocks5(line)
	case "http", "https":
		return parseHTTP(line)
	default:
		return nil, fmt.Errorf("unsupported protocol %q", scheme)
	}
}

type query map[string]string

func parseURL(line string) (*url.URL, query, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL: %v", err)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, nil, fmt.Errorf("missing host or port")
	}
	q, err := parseQuery(u.RawQuery)
	if err != nil {
		return nil, nil, err
	}
	return u, q, nil
}

func parseQuery(raw string) (query, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid query string")
	}
	q := query{}
	for k, v := range values {
		if len(v) == 0 {
			continue
		}
		q[strings.ToLower(k)] = v[len(v)-1]
	}
	return q, nil
}

func checkUnknown(q query, allowed ...string) error {
	allowedSet := map[string]bool{}
	for _, k := range allowed {
		allowedSet[strings.ToLower(k)] = true
	}
	for k := range q {
		if !allowedSet[k] {
			return fmt.Errorf("unsupported URI parameter %q", k)
		}
	}
	return nil
}

func queryName(q query, fallback string) string {
	if v := q["remark"]; v != "" {
		return decodeName(v)
	}
	return fallback
}

func decodeName(s string) string {
	if s == "" {
		return s
	}
	if decoded, err := url.PathUnescape(s); err == nil {
		s = decoded
	}
	return strings.TrimSpace(s)
}

func boolParam(q query, keys ...string) bool {
	for _, k := range keys {
		v := strings.ToLower(q[k])
		if v == "1" || v == "true" || v == "yes" {
			return true
		}
	}
	return false
}

func alpnParam(q query) []string {
	raw := q["alpn"]
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePort(u *url.URL) (int, error) {
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port")
	}
	return port, nil
}

func applyTLS(q query, c *mihomo.Config, allowReality bool) {
	security := strings.ToLower(q["security"])
	tlsParam := strings.ToLower(q["tls"])
	c.TLS = security == "tls" || security == "reality" || security == "xtls" || tlsParam == "1" || tlsParam == "true"
	c.SNI = firstNonEmpty(q["sni"], q["servername"], q["peer"])
	c.ALPN = alpnParam(q)
	c.SkipCertVerify = boolParam(q, "allowinsecure", "insecure", "skip-cert-verify")
	c.Fingerprint = firstNonEmpty(q["fp"], q["fingerprint"])
	if allowReality && (security == "reality" || q["pbk"] != "") {
		c.Reality = &mihomo.RealityOptions{PublicKey: q["pbk"], ShortID: q["sid"]}
		c.TLS = true
	}
}

func applyNetwork(q query, c *mihomo.Config) error {
	network := strings.ToLower(firstNonEmpty(q["type"], q["network"]))
	if network == "" {
		network = "tcp"
	}
	c.Network = network
	switch network {
	case "tcp":
		if header := strings.ToLower(q["headertype"]); header != "" && header != "none" {
			return fmt.Errorf("unsupported tcp header type %q (Mihomo has no equivalent)", header)
		}
	case "ws":
		c.WS = &mihomo.WSOptions{Path: firstNonEmpty(q["path"], "/")}
		if host := q["host"]; host != "" {
			c.WS.Headers = map[string]string{"Host": host}
		}
		if raw := q["ed"]; raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				c.WS.MaxEarlyData = n
			}
		}
		c.WS.EarlyDataHeaderName = q["eh"]
	case "grpc":
		c.GRPC = &mihomo.GRPCOptions{ServiceName: firstNonEmpty(q["servicename"], q["service_name"])}
		if mode := strings.ToLower(q["mode"]); mode != "" && mode != "gun" {
			return fmt.Errorf("unsupported grpc mode %q", mode)
		}
	case "h2":
		c.H2 = &mihomo.H2Options{Path: firstNonEmpty(q["path"], "/")}
		if host := q["host"]; host != "" {
			c.H2.Host = splitComma(host)
		}
	case "http":
		c.HTTP = &mihomo.HTTPOptions{Path: []string{firstNonEmpty(q["path"], "/")}}
		if host := q["host"]; host != "" {
			c.HTTP.Headers = map[string][]string{"Host": splitComma(host)}
		}
	default:
		return fmt.Errorf("unsupported transport %q", network)
	}
	return nil
}

func parseVLESS(line string) (*Item, error) {
	u, q, err := parseURL(line)
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vless link is missing a uuid")
	}
	port, err := parsePort(u)
	if err != nil {
		return nil, err
	}
	if err := checkUnknown(q,
		"type", "network", "security", "tls", "sni", "servername", "peer", "alpn", "fp", "fingerprint",
		"allowinsecure", "insecure", "skip-cert-verify", "flow", "path", "host", "servicename",
		"service_name", "pbk", "sid", "encryption", "headertype", "ed", "eh", "mode",
		"udp", "tfo", "mptcp", "packetencoding", "packet-encoding", "remark", "group", "ip-version",
	); err != nil {
		return nil, err
	}
	c := mihomo.Config{Server: u.Hostname(), Port: port, UUID: u.User.Username(), Flow: q["flow"]}
	if err := applyNetwork(q, &c); err != nil {
		return nil, err
	}
	applyTLS(q, &c, true)
	if c.Reality != nil {
		if c.Reality.PublicKey == "" {
			return nil, fmt.Errorf("reality link is missing pbk")
		}
	}
	applyCommonExtras(q, &c)
	c.Encryption = q["encryption"]
	name := queryName(q, "")
	if decoded, err := url.PathUnescape(u.Fragment); err == nil && strings.TrimSpace(decoded) != "" {
		name = strings.TrimSpace(decoded)
	}
	if name == "" {
		name = fmt.Sprintf("VLESS %s", c.Server)
	}
	if err := mihomo.ValidateConfig(mihomo.ProtocolVLESS, c); err != nil {
		return nil, err
	}
	return &Item{Name: name, Protocol: mihomo.ProtocolVLESS, Config: c, Tags: tagsFromQuery(q)}, nil
}

func parseTrojan(line string) (*Item, error) {
	u, q, err := parseURL(line)
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("trojan link is missing a password")
	}
	port, err := parsePort(u)
	if err != nil {
		return nil, err
	}
	if err := checkUnknown(q,
		"type", "network", "security", "tls", "sni", "servername", "peer", "alpn", "fp", "fingerprint",
		"allowinsecure", "insecure", "skip-cert-verify", "path", "host", "servicename", "service_name",
		"headertype", "ed", "eh", "mode", "udp", "tfo", "mptcp", "remark", "group", "ip-version",
	); err != nil {
		return nil, err
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	c := mihomo.Config{Server: u.Hostname(), Port: port, Password: password, TLS: true}
	if err := applyNetwork(q, &c); err != nil {
		return nil, err
	}
	applyTLS(q, &c, false)
	applyCommonExtras(q, &c)
	name := queryName(q, "")
	if decoded, err := url.PathUnescape(u.Fragment); err == nil && strings.TrimSpace(decoded) != "" {
		name = strings.TrimSpace(decoded)
	}
	if name == "" {
		name = fmt.Sprintf("Trojan %s", c.Server)
	}
	if err := mihomo.ValidateConfig(mihomo.ProtocolTrojan, c); err != nil {
		return nil, err
	}
	return &Item{Name: name, Protocol: mihomo.ProtocolTrojan, Config: c, Tags: tagsFromQuery(q)}, nil
}

func parseHysteria2(line string) (*Item, error) {
	u, q, err := parseURL(line)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("hysteria2 link is missing an auth password")
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	if password == "" {
		return nil, fmt.Errorf("hysteria2 link is missing an auth password")
	}
	port, err := parsePort(u)
	if err != nil {
		return nil, err
	}
	if err := checkUnknown(q,
		"security", "insecure", "allowinsecure", "sni", "servername", "peer", "alpn", "obfs", "obfs-password",
		"up", "down", "ports", "mport", "hop-interval", "fp", "fingerprint", "client-fingerprint", "pinSHA256", "remark", "group", "tfo", "mptcp",
	); err != nil {
		return nil, err
	}
	fingerprints := distinctNonEmpty(q["fp"], q["fingerprint"], q["client-fingerprint"], q["pinsha256"])
	if len(fingerprints) > 1 {
		return nil, fmt.Errorf("hysteria2 link specifies multiple different fingerprint values")
	}
	c := mihomo.Config{
		Server: u.Hostname(), Port: port, Password: password, TLS: true,
		SNI: firstNonEmpty(q["sni"], q["servername"], q["peer"]), ALPN: alpnParam(q),
		SkipCertVerify: boolParam(q, "insecure", "allowinsecure", "skip-cert-verify"),
		Fingerprint:    firstNonEmpty(q["fp"], q["fingerprint"], q["client-fingerprint"], q["pinsha256"]),
		Obfs:           q["obfs"], ObfsPassword: q["obfs-password"],
		Up: q["up"], Down: q["down"], Ports: firstNonEmpty(q["ports"], q["mport"]), HopInterval: q["hop-interval"],
	}
	applyCommonExtras(q, &c)
	name := queryName(q, "")
	if decoded, err := url.PathUnescape(u.Fragment); err == nil && strings.TrimSpace(decoded) != "" {
		name = strings.TrimSpace(decoded)
	}
	if name == "" {
		name = fmt.Sprintf("Hysteria2 %s", c.Server)
	}
	if err := mihomo.ValidateConfig(mihomo.ProtocolHysteria2, c); err != nil {
		return nil, err
	}
	return &Item{Name: name, Protocol: mihomo.ProtocolHysteria2, Config: c, Tags: tagsFromQuery(q)}, nil
}

func parseTUIC(line string) (*Item, error) {
	u, q, err := parseURL(line)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("tuic link is missing uuid and password")
	}
	password, _ := u.User.Password()
	id := u.User.Username()
	if id == "" || password == "" {
		return nil, fmt.Errorf("tuic link requires uuid:password@host")
	}
	port, err := parsePort(u)
	if err != nil {
		return nil, err
	}
	if err := checkUnknown(q,
		"congestion_control", "congestion-controller", "udp_relay_mode", "udp-relay-mode", "alpn",
		"sni", "servername", "peer", "allow_insecure", "allowinsecure", "insecure", "disable_sni",
		"disable-sni", "reduce_rtt", "reduce-rtt", "udp_over_stream", "udp-over-stream",
		"heartbeat_interval", "heartbeat-interval", "remark", "group", "tfo", "mptcp", "fp", "fingerprint",
		"client-fingerprint",
	); err != nil {
		return nil, err
	}
	c := mihomo.Config{
		Server: u.Hostname(), Port: port, UUID: id, Password: password, TLS: true,
		SNI: firstNonEmpty(q["sni"], q["servername"], q["peer"]), ALPN: alpnParam(q),
		SkipCertVerify:       boolParam(q, "allow_insecure", "allowinsecure", "insecure", "skip-cert-verify"),
		DisableSNI:           boolParam(q, "disable_sni", "disable-sni"),
		Fingerprint:          firstNonEmpty(q["fp"], q["fingerprint"], q["client-fingerprint"]),
		CongestionController: firstNonEmpty(q["congestion_control"], q["congestion-controller"]),
		UDPRelayMode:         firstNonEmpty(q["udp_relay_mode"], q["udp-relay-mode"]),
	}
	if v, ok := q["reduce_rtt"]; ok {
		b := v == "1" || strings.EqualFold(v, "true")
		c.ReduceRTT = &b
	} else if v, ok := q["reduce-rtt"]; ok {
		b := v == "1" || strings.EqualFold(v, "true")
		c.ReduceRTT = &b
	}
	applyCommonExtras(q, &c)
	if v := firstNonEmpty(q["udp_over_stream"], q["udp-over-stream"]); v != "" {
		c.Extra["udp-over-stream"] = v == "1" || strings.EqualFold(v, "true")
	}
	if v := firstNonEmpty(q["heartbeat_interval"], q["heartbeat-interval"]); v != "" {
		c.Extra["heartbeat-interval"] = v
	}
	name := queryName(q, "")
	if decoded, err := url.PathUnescape(u.Fragment); err == nil && strings.TrimSpace(decoded) != "" {
		name = strings.TrimSpace(decoded)
	}
	if name == "" {
		name = fmt.Sprintf("TUIC %s", c.Server)
	}
	if err := mihomo.ValidateConfig(mihomo.ProtocolTUIC, c); err != nil {
		return nil, err
	}
	return &Item{Name: name, Protocol: mihomo.ProtocolTUIC, Config: c, Tags: tagsFromQuery(q)}, nil
}

func parseSocks5(line string) (*Item, error) {
	return parseUserPassProxy(line, mihomo.ProtocolSOCKS5)
}

func parseHTTP(line string) (*Item, error) {
	return parseUserPassProxy(line, mihomo.ProtocolHTTP)
}

func parseUserPassProxy(line string, protocol mihomo.Protocol) (*Item, error) {
	u, q, err := parseURL(line)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(u)
	if err != nil {
		return nil, err
	}
	if err := checkUnknown(q, "udp", "tls", "skip-cert-verify", "allowinsecure", "insecure",
		"remark", "group", "tfo", "mptcp", "sni", "servername", "peer", "alpn", "fp", "fingerprint", "client-fingerprint"); err != nil {
		return nil, err
	}
	c := mihomo.Config{Server: u.Hostname(), Port: port}
	if u.User != nil {
		c.Username = u.User.Username()
		c.Password, _ = u.User.Password()
	}
	c.TLS = strings.EqualFold(u.Scheme, "https") || boolParam(q, "tls")
	if protocol == mihomo.ProtocolSOCKS5 && q["udp"] != "" {
		b := q["udp"] == "1" || strings.EqualFold(q["udp"], "true")
		c.UDP = &b
	}
	c.SNI = firstNonEmpty(q["sni"], q["servername"], q["peer"])
	c.ALPN = alpnParam(q)
	c.Fingerprint = firstNonEmpty(q["fp"], q["fingerprint"], q["client-fingerprint"])
	c.SkipCertVerify = boolParam(q, "skip-cert-verify", "allowinsecure", "insecure")
	applyCommonExtras(q, &c)
	name := queryName(q, "")
	if decoded, err := url.PathUnescape(u.Fragment); err == nil && strings.TrimSpace(decoded) != "" {
		name = strings.TrimSpace(decoded)
	}
	if name == "" {
		name = fmt.Sprintf("%s %s", strings.ToUpper(string(protocol)), c.Server)
	}
	if err := mihomo.ValidateConfig(protocol, c); err != nil {
		return nil, err
	}
	return &Item{Name: name, Protocol: protocol, Config: c, Tags: tagsFromQuery(q)}, nil
}

// applyCommonExtras maps Mihomo-supported fields that we deliberately keep in
// Extra rather than first-class struct fields.
func applyCommonExtras(q query, c *mihomo.Config) {
	if c.Extra == nil {
		c.Extra = map[string]any{}
	}
	if v := q["tfo"]; v != "" {
		c.Extra["tfo"] = v == "1" || strings.EqualFold(v, "true")
	}
	if v := q["mptcp"]; v != "" {
		c.Extra["mptcp"] = v == "1" || strings.EqualFold(v, "true")
	}
	if v := firstNonEmpty(q["packetencoding"], q["packet-encoding"]); v != "" {
		c.Extra["packet-encoding"] = v
	}
	if v := q["ip-version"]; v != "" {
		c.Extra["ip-version"] = v
	}
	if v := q["udp"]; v != "" && c.UDP == nil {
		b := v == "1" || strings.EqualFold(v, "true")
		c.UDP = &b
	}
	if len(c.Extra) == 0 {
		c.Extra = nil
	}
}

func tagsFromQuery(q query) []string {
	raw := q["group"]
	if raw == "" {
		return nil
	}
	var tags []string
	for _, part := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(part); t != "" && len([]rune(t)) <= 32 {
			tags = append(tags, t)
		}
	}
	return tags
}

func splitComma(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func decodeBase64Flexible(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimRight(raw, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(raw); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

func splitHostPort(raw string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(raw)
	if err != nil {
		return "", 0, fmt.Errorf("invalid host:port")
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return strings.Trim(host, "[]"), port, nil
}

func redactURI(line string) string {
	if scheme, rest, ok := strings.Cut(line, "://"); ok {
		if len(rest) > 24 {
			rest = rest[:8] + "…"
		}
		return scheme + "://" + rest
	}
	return line
}

func distinctNonEmpty(values ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
