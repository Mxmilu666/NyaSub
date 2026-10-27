package importers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"nyasub/internal/mihomo"
)

func parseSS(line string) (*Item, error) {
	// SIP002 has several historical shapes; parse manually to keep the
	// base64 userinfo intact.
	rest := line
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	name := ""
	if idx := strings.IndexByte(rest, '#'); idx >= 0 {
		name = decodeName(rest[idx+1:])
		rest = rest[:idx]
	}
	rawQuery := ""
	if idx := strings.IndexByte(rest, '?'); idx >= 0 {
		rawQuery = rest[idx+1:]
		rest = rest[:idx]
	}
	q, err := parseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	if err := checkUnknown(q, "plugin", "udp", "tfo", "mptcp", "remark", "group", "ip-version"); err != nil {
		return nil, err
	}

	userinfo := ""
	hostport := rest
	if idx := strings.LastIndexByte(rest, '@'); idx >= 0 {
		userinfo = rest[:idx]
		hostport = rest[idx+1:]
	} else {
		// Legacy ss://base64(method:password@host:port)
		decoded, err := decodeBase64Flexible(rest)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks link must contain @ or a base64 payload")
		}
		combined := string(decoded)
		idx := strings.LastIndexByte(combined, '@')
		if idx < 0 {
			return nil, fmt.Errorf("invalid shadowsocks payload")
		}
		userinfo, hostport = combined[:idx], combined[idx+1:]
	}

	method, password, err := decodeSSUserinfo(userinfo)
	if err != nil {
		return nil, err
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	c := mihomo.Config{Server: host, Port: port, Cipher: method, Password: password}
	if plugin := q["plugin"]; plugin != "" {
		c.Plugin, c.PluginOpts = parseSSPlugin(plugin)
	}
	applyCommonExtras(q, &c)
	if name == "" {
		name = queryName(q, "")
	}
	if name == "" {
		name = fmt.Sprintf("Shadowsocks %s", c.Server)
	}
	if err := mihomo.ValidateConfig(mihomo.ProtocolSS, c); err != nil {
		return nil, err
	}
	return &Item{Name: name, Protocol: mihomo.ProtocolSS, Config: c, Tags: tagsFromQuery(q)}, nil
}

func decodeSSUserinfo(raw string) (string, string, error) {
	decoded := raw
	if b, err := decodeBase64Flexible(raw); err == nil && strings.Contains(string(b), ":") {
		decoded = string(b)
	} else if unescaped, err := url.PathUnescape(raw); err == nil {
		decoded = unescaped
	}
	method, password, ok := strings.Cut(decoded, ":")
	if !ok || method == "" || password == "" {
		return "", "", fmt.Errorf("shadowsocks userinfo must be method:password")
	}
	return method, password, nil
}

func parseSSPlugin(raw string) (string, map[string]any) {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	parts := strings.Split(decoded, ";")
	if len(parts) == 0 {
		return "", nil
	}
	name := parts[0]
	opts := map[string]any{}
	switch name {
	case "obfs-local", "simple-obfs":
		for _, opt := range parts[1:] {
			k, v, hasValue := strings.Cut(opt, "=")
			switch k {
			case "obfs":
				opts["mode"] = v
			case "obfs-host":
				opts["host"] = v
			default:
				if hasValue {
					opts[k] = v
				}
			}
		}
		return "obfs", opts
	case "v2ray-plugin":
		mode := "websocket"
		for _, opt := range parts[1:] {
			k, v, hasValue := strings.Cut(opt, "=")
			switch k {
			case "mode":
				mode = v
			case "host":
				opts["host"] = v
			case "path":
				opts["path"] = v
			case "tls":
				opts["tls"] = true
			case "mux":
				opts["mux"] = true
			default:
				if hasValue {
					opts[k] = v
				}
			}
		}
		opts["mode"] = mode
		return "v2ray-plugin", opts
	default:
		for _, opt := range parts[1:] {
			k, v, hasValue := strings.Cut(opt, "=")
			if hasValue {
				opts[k] = v
			} else if k != "" {
				opts[k] = true
			}
		}
		if len(opts) == 0 {
			return name, nil
		}
		return name, opts
	}
}

func parseVMess(line string) (*Item, error) {
	payload := line
	if idx := strings.Index(payload, "://"); idx >= 0 {
		payload = payload[idx+3:]
	}
	nameFromFragment := ""
	if idx := strings.IndexByte(payload, '#'); idx >= 0 {
		nameFromFragment = decodeName(payload[idx+1:])
		payload = payload[:idx]
	}
	decoded, err := decodeBase64Flexible(payload)
	if err != nil {
		if unescaped, uerr := url.QueryUnescape(payload); uerr == nil {
			decoded, err = decodeBase64Flexible(unescaped)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("vmess payload is not valid base64 JSON")
	}
	var raw map[string]any
	if err := json.Unmarshal(decoded, &raw); err != nil {
		return nil, fmt.Errorf("vmess payload is not valid JSON")
	}
	fields := map[string]any{}
	for k, v := range raw {
		fields[strings.ToLower(k)] = v
	}
	allowed := map[string]bool{
		"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true,
		"scy": true, "net": true, "type": true, "host": true, "path": true,
		"tls": true, "sni": true, "alpn": true, "fp": true, "allowinsecure": true,
		"insecure": true, "security": true, "verify_cert": true, "tfo": true,
		"mptcp": true, "servername": true, "packetencoding": true, "packet-encoding": true,
		"ip-version": true, "remark": true, "group": true, "header": true,
		"servicename": true, "service_name": true, "mode": true,
	}
	for k := range fields {
		if !allowed[k] {
			return nil, fmt.Errorf("unsupported vmess field %q", k)
		}
	}
	server, _ := stringField(fields, "add")
	if server == "" {
		return nil, fmt.Errorf("vmess field add is required")
	}
	port, err := intField(fields, "port")
	if err != nil {
		return nil, fmt.Errorf("vmess port: %w", err)
	}
	id, _ := stringField(fields, "id")
	if id == "" {
		return nil, fmt.Errorf("vmess field id is required")
	}
	aid := 0
	if _, ok := fields["aid"]; ok {
		aid, err = intField(fields, "aid")
		if err != nil {
			return nil, fmt.Errorf("vmess aid: %w", err)
		}
	}
	c := mihomo.Config{
		Server: server, Port: port, UUID: id, AlterID: aid,
		Cipher:         firstNonEmpty(stringFieldVal(fields, "scy"), "auto"),
		TLS:            strings.EqualFold(stringFieldVal(fields, "tls"), "tls") || strings.EqualFold(stringFieldVal(fields, "security"), "tls"),
		SNI:            firstNonEmpty(stringFieldVal(fields, "sni"), stringFieldVal(fields, "servername")),
		ALPN:           alpnParam(query{"alpn": stringFieldVal(fields, "alpn")}),
		Fingerprint:    firstNonEmpty(stringFieldVal(fields, "fp")),
		SkipCertVerify: boolField(fields, "allowinsecure") || boolField(fields, "insecure"),
	}
	net := strings.ToLower(stringFieldVal(fields, "net"))
	headerType := strings.ToLower(stringFieldVal(fields, "type"))
	q := query{}
	if net != "" {
		q["type"] = net
	}
	if h := stringFieldVal(fields, "host"); h != "" {
		q["host"] = h
	}
	if p := stringFieldVal(fields, "path"); p != "" {
		q["path"] = p
	}
	if v := firstNonEmpty(stringFieldVal(fields, "servicename"), stringFieldVal(fields, "service_name")); v != "" {
		q["servicename"] = v
	}
	if v := stringFieldVal(fields, "mode"); v != "" {
		q["mode"] = v
	}
	if headerType != "" && headerType != "none" {
		q["headertype"] = headerType
	}
	if err := applyNetwork(q, &c); err != nil {
		return nil, err
	}
	applyCommonExtras(q, &c)
	if v := stringFieldVal(fields, "packetencoding"); v != "" {
		c.Extra["packet-encoding"] = v
	}
	if v := stringFieldVal(fields, "packet-encoding"); v != "" {
		c.Extra["packet-encoding"] = v
	}
	if len(c.Extra) == 0 {
		c.Extra = nil
	}
	name := firstNonEmpty(stringFieldVal(fields, "ps"), nameFromFragment, stringFieldVal(fields, "remark"))
	if name == "" {
		name = fmt.Sprintf("VMess %s", c.Server)
	}
	if v, ok := fields["group"]; ok {
		if s, _ := v.(string); s != "" {
			q["group"] = s
		}
	}
	if err := mihomo.ValidateConfig(mihomo.ProtocolVMess, c); err != nil {
		return nil, err
	}
	return &Item{Name: name, Protocol: mihomo.ProtocolVMess, Config: c, Tags: tagsFromQuery(q)}, nil
}

func stringField(fields map[string]any, key string) (string, bool) {
	v, ok := fields[key]
	if !ok || v == nil {
		return "", false
	}
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val), true
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64), true
	case json.Number:
		return val.String(), true
	case int:
		return strconv.Itoa(val), true
	case bool:
		return strconv.FormatBool(val), true
	default:
		return "", false
	}
}

func stringFieldVal(fields map[string]any, key string) string {
	s, _ := stringField(fields, key)
	return s
}

func intField(fields map[string]any, key string) (int, error) {
	s, ok := stringField(fields, key)
	if !ok || s == "" {
		return 0, fmt.Errorf("missing value")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("must be a number")
	}
	return n, nil
}

func boolField(fields map[string]any, key string) bool {
	v, ok := fields[key]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "1" || strings.EqualFold(val, "true")
	case float64:
		return val == 1
	default:
		return false
	}
}
