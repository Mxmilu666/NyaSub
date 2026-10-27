package mihomo

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

var ruleTypes = map[string]bool{
	"DOMAIN":             true,
	"DOMAIN-SUFFIX":      true,
	"DOMAIN-KEYWORD":     true,
	"GEOIP":              true,
	"GEOSITE":            true,
	"RULE-SET":           true,
	"IP-CIDR":            true,
	"IP-CIDR6":           true,
	"PROCESS-NAME":       true,
	"PROCESS-PATH":       true,
	"DST-PORT":           true,
	"SRC-PORT":           true,
	"NETWORK":            true,
	"IN-PORT":            true,
	"SRC-IP-CIDR":        true,
	"SRC-GEOIP":          true,
	"DOMAIN-REGEX":       true,
	"GEOSITE-REGEX":      true,
	"IP-ASN":             true,
	"PROCESS-NAME-REGEX": true,
}

var groupTypes = map[string]bool{
	"select": true, "url-test": true, "fallback": true, "load-balance": true,
}

var generalReserved = map[string]bool{
	"proxies": true, "proxy-groups": true, "rules": true, "dns": true,
	"proxy-providers": true, "rule-providers": true, "sub-rules": true,
	"listeners": true, "tunnel": true, "experimental": true,
}

type allocator struct {
	used map[string]bool
}

func newAllocator() *allocator {
	return &allocator{used: map[string]bool{}}
}

func (a *allocator) assign(base string) string {
	base = cleanExportName(base)
	if !a.used[base] {
		a.used[base] = true
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s (%d)", base, i)
		if !a.used[candidate] {
			a.used[candidate] = true
			return candidate
		}
	}
}

func cleanExportName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	name = strings.TrimSpace(b.String())
	if name == "" {
		name = "Unnamed"
	}
	runes := []rune(name)
	if len(runes) > 180 {
		name = string(runes[:180])
	}
	return name
}

// Generate renders a complete, deterministic Mihomo configuration.
func Generate(spec Spec) (*Result, error) {
	if len(spec.Nodes) == 0 {
		return nil, fmt.Errorf("profile has no nodes")
	}
	validationSpec := spec
	if validationSpec.UseACL4SSR {
		validationSpec.Groups = nil
		validationSpec.Rules = nil
		validationSpec.DefaultExitType = ""
		validationSpec.DefaultExitID = ""
		validationSpec.ForceDefaultExit = false
	}
	if err := validateSpec(validationSpec); err != nil {
		return nil, err
	}

	nodes := append([]Node(nil), spec.Nodes...)
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := strings.ToLower(nodes[i].Name), strings.ToLower(nodes[j].Name)
		if a != b {
			return a < b
		}
		return nodes[i].ID < nodes[j].ID
	})

	alloc := newAllocator()
	nodeNames := make(map[string]string, len(nodes))
	selectedNode := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		if _, ok := selectedNode[n.ID]; ok {
			continue
		}
		selectedNode[n.ID] = n
		nodeNames[n.ID] = alloc.assign(exportDisplayName(n.Name, n.Country))
	}

	type chainEntry struct {
		chain Chain
		base  string
	}
	var chainEntries []chainEntry
	seenChain := map[string]bool{}
	for _, c := range spec.Chains {
		if !c.Enabled || seenChain[c.ID] {
			continue
		}
		seenChain[c.ID] = true
		entryName, ok := nodeNames[c.Entry.ID]
		if !ok {
			return nil, fmt.Errorf("chain %q uses an entry node that is not enabled in this profile", c.Name)
		}
		exitLabel := exportDisplayName(c.Exit.Name, c.Exit.Country)
		if n, ok := nodeNames[c.Exit.ID]; ok {
			exitLabel = n
		}
		entryDisplay := stripLeadingFlags(entryName)
		exitDisplay := stripLeadingFlags(exitLabel)
		entryFlag := nodeFlag(c.Entry.Name, c.Entry.Country)
		exitFlag := nodeFlag(c.Exit.Name, c.Exit.Country)
		prefix := ""
		if entryFlag != "" && exitFlag != "" {
			prefix = entryFlag + " → " + exitFlag + " "
		}
		chainEntries = append(chainEntries, chainEntry{
			chain: c,
			base:  prefix + fmt.Sprintf("%s → %s", entryDisplay, exitDisplay),
		})
	}
	sort.SliceStable(chainEntries, func(i, j int) bool {
		if chainEntries[i].base != chainEntries[j].base {
			return chainEntries[i].base < chainEntries[j].base
		}
		return chainEntries[i].chain.ID < chainEntries[j].chain.ID
	})
	chainNames := make(map[string]string, len(chainEntries))
	for _, e := range chainEntries {
		chainNames[e.chain.ID] = alloc.assign(e.base)
	}

	// Render proxies: original enabled nodes first, then chain exit copies.
	type renderedProxy struct {
		name   string
		node   Node
		dialer string
	}
	var proxies []renderedProxy
	for _, n := range nodes {
		proxies = append(proxies, renderedProxy{name: nodeNames[n.ID], node: n})
	}
	for _, e := range chainEntries {
		proxies = append(proxies, renderedProxy{
			name:   chainNames[e.chain.ID],
			node:   e.chain.Exit,
			dialer: nodeNames[e.chain.Entry.ID],
		})
	}

	allProxyNames := make([]string, 0, len(proxies))
	for _, p := range proxies {
		allProxyNames = append(allProxyNames, p.name)
	}

	var resolvedGroups []Group
	var groupAllocated map[string]string
	ruleLines := []string{}
	ruleProviders := []RuleProvider{}
	matchTarget := ""

	if spec.UseACL4SSR {
		preset, err := loadACL4SSRPreset()
		if err != nil {
			return nil, err
		}
		acl4Proxies := make([]acl4Proxy, 0, len(proxies))
		for _, proxy := range proxies {
			var tags []string
			if proxy.dialer == "" {
				tags = proxy.node.Tags
			}
			acl4Proxies = append(acl4Proxies, acl4Proxy{Name: proxy.name, Tags: tags})
		}
		resolvedGroups, groupAllocated, err = resolveACL4Groups(preset, alloc, acl4Proxies)
		if err != nil {
			return nil, err
		}
		ruleLines, ruleProviders, matchTarget, err = resolveACL4Rules(preset, groupAllocated)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		resolvedGroups, groupAllocated, err = resolveGroups(spec.Groups, alloc, nodeNames, chainNames)
		if err != nil {
			return nil, err
		}

		defaultName, err := resolveDefaultExit(spec, nodeNames, chainNames)
		if err != nil {
			return nil, err
		}

		if len(resolvedGroups) == 0 {
			groupName := alloc.assign("Proxy")
			groupAllocated["__auto__"] = groupName
			resolvedGroups = append(resolvedGroups, Group{
				Name: groupName, Type: "select", Proxies: orderWithDefault(allProxyNames, defaultName),
			})
		}

		switch {
		case spec.ForceDefaultExit:
			if defaultName == "" {
				return nil, fmt.Errorf("force default exit requires a default exit")
			}
			matchTarget = defaultName
		case defaultName != "":
			found := -1
			for i, g := range resolvedGroups {
				if g.Type != "select" {
					continue
				}
				for _, p := range g.Proxies {
					if p == defaultName {
						found = i
						break
					}
				}
				if found >= 0 {
					break
				}
			}
			if found >= 0 {
				resolvedGroups[found].Proxies = orderWithDefault(resolvedGroups[found].Proxies, defaultName)
				matchTarget = resolvedGroups[found].Name
			} else {
				groupName := alloc.assign("Default Exit")
				groupAllocated["__default__"] = groupName
				order := orderWithDefault(allProxyNames, defaultName)
				resolvedGroups = append([]Group{{Name: groupName, Type: "select", Proxies: order}}, resolvedGroups...)
				matchTarget = groupName
			}
		default:
			matchTarget = resolvedGroups[0].Name
		}

		ruleLines, err = renderRules(spec.Rules, nodeNames, chainNames, groupAllocated)
		if err != nil {
			return nil, err
		}
		ruleLines = append(ruleLines, "MATCH,"+matchTarget)
	}

	configMap, err := buildConfigMap(spec.General, spec.DNS, spec.ForceDefaultExit)
	if err != nil {
		return nil, err
	}

	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, key := range sortedKeys(configMap) {
		root.Content = append(root.Content, strNode(key), encodeAny(configMap[key]))
	}

	proxySeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, p := range proxies {
		n, err := renderProxy(p.name, p.node.Protocol, p.node.Config, p.dialer)
		if err != nil {
			return nil, fmt.Errorf("node %q: %w", p.name, err)
		}
		proxySeq.Content = append(proxySeq.Content, n)
	}
	root.Content = append(root.Content, strNode("proxies"), proxySeq)

	groupSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, g := range resolvedGroups {
		groupSeq.Content = append(groupSeq.Content, renderGroup(g))
	}
	root.Content = append(root.Content, strNode("proxy-groups"), groupSeq)

	if len(ruleProviders) > 0 {
		root.Content = append(root.Content, strNode("rule-providers"), encodeAny(ruleProviderMap(ruleProviders)))
	}

	ruleSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, r := range ruleLines {
		ruleSeq.Content = append(ruleSeq.Content, strNode(r))
	}
	root.Content = append(root.Content, strNode("rules"), ruleSeq)

	if len(spec.DNS) > 0 {
		root.Content = append(root.Content, strNode("dns"), encodeAny(spec.DNS))
	}

	out, err := marshalNode(root)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(out)
	return &Result{
		YAML:       out,
		ETag:       `"` + hex.EncodeToString(sum[:]) + `"`,
		NodeNames:  nodeNames,
		ChainNames: chainNames,
		GroupNames: groupAllocated,
		Match:      matchTarget,
	}, nil
}

func orderWithDefault(names []string, defaultName string) []string {
	out := append([]string(nil), names...)
	if defaultName == "" {
		return out
	}
	idx := -1
	for i, n := range out {
		if n == defaultName {
			idx = i
			break
		}
	}
	if idx > 0 {
		copy(out[1:idx+1], out[0:idx])
		out[0] = defaultName
	}
	return out
}

func validateSpec(spec Spec) error {
	seen := map[string]bool{}
	for _, n := range spec.Nodes {
		if n.ID == "" || seen[n.ID] {
			return fmt.Errorf("duplicate or empty node id")
		}
		seen[n.ID] = true
		if err := ValidateName(n.Name); err != nil {
			return fmt.Errorf("node name: %w", err)
		}
		if !ProtocolValid(n.Protocol) {
			return fmt.Errorf("node %q has unsupported protocol", n.Name)
		}
		if err := ValidateConfig(n.Protocol, n.Config); err != nil {
			return fmt.Errorf("node %q: %w", n.Name, err)
		}
	}
	chainIDs := map[string]bool{}
	for _, c := range spec.Chains {
		if c.ID == "" || chainIDs[c.ID] {
			return fmt.Errorf("duplicate or empty chain id")
		}
		chainIDs[c.ID] = true
		if c.Entry.ID == c.Exit.ID {
			return fmt.Errorf("chain %q cannot use the same entry and exit node", c.Name)
		}
		if err := ValidateConfig(c.Exit.Protocol, c.Exit.Config); err != nil {
			return fmt.Errorf("chain %q exit node: %w", c.Name, err)
		}
		if !c.Enabled {
			continue
		}
		if !seen[c.Entry.ID] {
			return fmt.Errorf("chain %q entry node is not enabled", c.Name)
		}
	}
	groupNames := map[string]bool{}
	for _, g := range spec.Groups {
		if err := ValidateName(g.Name); err != nil {
			return fmt.Errorf("group name: %w", err)
		}
		if groupNames[g.Name] {
			return fmt.Errorf("duplicate group name %q", g.Name)
		}
		groupNames[g.Name] = true
		if !groupTypes[g.Type] {
			return fmt.Errorf("group %q has unsupported type %q", g.Name, g.Type)
		}
		if len(g.Proxies) == 0 {
			return fmt.Errorf("group %q has no proxies", g.Name)
		}
		if g.Type != "select" && g.URL == "" {
			return fmt.Errorf("group %q requires a test URL", g.Name)
		}
		if g.Interval < 0 || g.Interval > 86400 || g.Tolerance < 0 || g.Tolerance > 10000 {
			return fmt.Errorf("group %q has invalid test settings", g.Name)
		}
		if g.Strategy != "" && g.Strategy != "round-robin" && g.Strategy != "consistent-hashing" && g.Strategy != "sticky-sessions" {
			return fmt.Errorf("group %q has unsupported strategy %q", g.Name, g.Strategy)
		}
	}
	for _, r := range spec.Rules {
		t := strings.ToUpper(strings.TrimSpace(r.Type))
		if t == "MATCH" {
			return fmt.Errorf("MATCH is generated automatically and cannot be added")
		}
		if !ruleTypes[t] {
			return fmt.Errorf("unsupported rule type %q", r.Type)
		}
		if r.Payload == "" || len(r.Payload) > 512 || strings.ContainsAny(r.Payload, ",\r\n") {
			return fmt.Errorf("rule payload is invalid")
		}
		if r.Target == "" {
			return fmt.Errorf("rule target is required")
		}
	}
	for key := range spec.General {
		if generalReserved[key] {
			return fmt.Errorf("general setting %q is reserved", key)
		}
		if strings.ContainsAny(key, ":\r\n") {
			return fmt.Errorf("invalid general setting key")
		}
	}
	return nil
}

func resolveGroups(groups []Group, alloc *allocator, nodeNames map[string]string, chainNames map[string]string) ([]Group, map[string]string, error) {
	allocated := map[string]string{}
	for i := range groups {
		g := groups[i]
		allocated[g.Name] = alloc.assign(g.Name)
	}
	for i := range groups {
		for _, ref := range groups[i].Proxies {
			if strings.HasPrefix(ref, "group:") {
				target := strings.TrimPrefix(ref, "group:")
				if target == groups[i].Name {
					return nil, nil, fmt.Errorf("group %q cannot reference itself", groups[i].Name)
				}
				if _, ok := allocated[target]; !ok {
					return nil, nil, fmt.Errorf("group %q references unknown group %q", groups[i].Name, target)
				}
			}
		}
	}
	// Detect group-reference cycles.
	state := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("policy groups contain a reference cycle at %q", name)
		case 2:
			return nil
		}
		state[name] = 1
		for _, g := range groups {
			if g.Name != name {
				continue
			}
			for _, ref := range g.Proxies {
				if strings.HasPrefix(ref, "group:") {
					if err := visit(strings.TrimPrefix(ref, "group:")); err != nil {
						return err
					}
				}
			}
		}
		state[name] = 2
		return nil
	}
	for _, g := range groups {
		if err := visit(g.Name); err != nil {
			return nil, nil, err
		}
	}

	resolved := make([]Group, 0, len(groups))
	for _, g := range groups {
		out := g
		out.Name = allocated[g.Name]
		out.Proxies = nil
		for _, ref := range g.Proxies {
			name, err := resolveRef(ref, nodeNames, chainNames, allocated)
			if err != nil {
				return nil, nil, fmt.Errorf("group %q: %w", g.Name, err)
			}
			out.Proxies = append(out.Proxies, name)
		}
		resolved = append(resolved, out)
	}
	return resolved, allocated, nil
}

func resolveRef(ref string, nodeNames, chainNames, groups map[string]string) (string, error) {
	switch {
	case ref == "DIRECT" || ref == "REJECT":
		return ref, nil
	case strings.HasPrefix(ref, "node:"):
		id := strings.TrimPrefix(ref, "node:")
		name, ok := nodeNames[id]
		if !ok {
			return "", fmt.Errorf("referenced node is not enabled in this profile")
		}
		return name, nil
	case strings.HasPrefix(ref, "chain:"):
		id := strings.TrimPrefix(ref, "chain:")
		name, ok := chainNames[id]
		if !ok {
			return "", fmt.Errorf("referenced chain is not enabled in this profile")
		}
		return name, nil
	case strings.HasPrefix(ref, "group:"):
		name := strings.TrimPrefix(ref, "group:")
		allocated, ok := groups[name]
		if !ok {
			return "", fmt.Errorf("referenced group %q does not exist", name)
		}
		return allocated, nil
	default:
		return "", fmt.Errorf("unsupported proxy reference %q", ref)
	}
}

func resolveDefaultExit(spec Spec, nodeNames, chainNames map[string]string) (string, error) {
	switch spec.DefaultExitType {
	case "":
		if spec.DefaultExitID != "" {
			return "", fmt.Errorf("default exit id requires a default exit type")
		}
		return "", nil
	case "node":
		name, ok := nodeNames[spec.DefaultExitID]
		if !ok {
			return "", fmt.Errorf("default exit node is not enabled in this profile")
		}
		return name, nil
	case "chain":
		name, ok := chainNames[spec.DefaultExitID]
		if !ok {
			return "", fmt.Errorf("default exit chain is not enabled in this profile")
		}
		return name, nil
	default:
		return "", fmt.Errorf("default exit type must be node or chain")
	}
}

func renderRules(rules []Rule, nodeNames, chainNames, groups map[string]string) ([]string, error) {
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		target, err := resolveRef(r.Target, nodeNames, chainNames, groups)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", strings.ToUpper(r.Type), err)
		}
		line := strings.ToUpper(r.Type) + "," + r.Payload + "," + target
		if r.NoResolve {
			line += ",no-resolve"
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func buildConfigMap(general, dns map[string]any, forceRuleMode bool) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range general {
		out[k] = v
	}
	if _, ok := out["mode"]; !ok {
		out["mode"] = "rule"
	}
	if forceRuleMode {
		out["mode"] = "rule"
	}
	if _, ok := out["log-level"]; !ok {
		out["log-level"] = "info"
	}
	if _, ok := out["ipv6"]; !ok {
		out["ipv6"] = true
	}
	if _, ok := out["unified-delay"]; !ok {
		out["unified-delay"] = true
	}
	if _, ok := out["tcp-concurrent"]; !ok {
		out["tcp-concurrent"] = true
	}
	return out, nil
}

func renderProxy(name string, protocol Protocol, c Config, dialer string) (*yaml.Node, error) {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	add := func(k string, v any) {
		n.Content = append(n.Content, strNode(k), encodeAny(v))
	}
	add("name", name)
	add("type", protocol.MihomoType())
	add("server", c.Server)
	add("port", c.Port)

	set := func(k string, v any) { add(k, v) }
	ifS := func(k, v string) {
		if v != "" {
			set(k, v)
		}
	}
	ifB := func(k string, v bool) {
		if v {
			set(k, v)
		}
	}

	switch protocol {
	case ProtocolVLESS:
		set("uuid", c.UUID)
		ifS("flow", c.Flow)
		ifS("encryption", c.Encryption)
		ifS("network", c.Network)
		ifB("tls", c.TLS)
		ifS("servername", c.SNI)
		if len(c.ALPN) > 0 {
			set("alpn", c.ALPN)
		}
		ifB("skip-cert-verify", c.SkipCertVerify)
		ifS("client-fingerprint", c.Fingerprint)
		if c.Reality != nil {
			r := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			r.Content = append(r.Content, strNode("public-key"), strNode(c.Reality.PublicKey))
			if c.Reality.ShortID != "" {
				r.Content = append(r.Content, strNode("short-id"), strNode(c.Reality.ShortID))
			}
			set("reality-opts", r)
		}
		appendTransport(set, c)
		if c.UDP != nil {
			set("udp", *c.UDP)
		}
	case ProtocolVMess:
		set("uuid", c.UUID)
		set("alterId", c.AlterID)
		ifS("cipher", c.Cipher)
		ifS("network", c.Network)
		ifB("tls", c.TLS)
		ifS("servername", c.SNI)
		if len(c.ALPN) > 0 {
			set("alpn", c.ALPN)
		}
		ifB("skip-cert-verify", c.SkipCertVerify)
		ifS("client-fingerprint", c.Fingerprint)
		appendTransport(set, c)
		if c.UDP != nil {
			set("udp", *c.UDP)
		}
	case ProtocolTrojan:
		set("password", c.Password)
		ifS("network", c.Network)
		ifS("sni", c.SNI)
		if len(c.ALPN) > 0 {
			set("alpn", c.ALPN)
		}
		ifB("skip-cert-verify", c.SkipCertVerify)
		ifS("client-fingerprint", c.Fingerprint)
		appendTransport(set, c)
		if c.UDP != nil {
			set("udp", *c.UDP)
		}
	case ProtocolSS:
		set("cipher", c.Cipher)
		set("password", c.Password)
		if c.UDP != nil {
			set("udp", *c.UDP)
		}
		if c.UDPOverTCP {
			set("udp-over-tcp", true)
			if c.UDPOverTCPVersion != 0 {
				set("udp-over-tcp-version", c.UDPOverTCPVersion)
			}
		}
		ifS("plugin", c.Plugin)
		if len(c.PluginOpts) > 0 {
			set("plugin-opts", c.PluginOpts)
		}
	case ProtocolHysteria2:
		set("password", c.Password)
		ifS("sni", c.SNI)
		if len(c.ALPN) > 0 {
			set("alpn", c.ALPN)
		}
		ifB("skip-cert-verify", c.SkipCertVerify)
		if c.Fingerprint != "" {
			if looksLikeCertFingerprint(c.Fingerprint) {
				set("fingerprint", c.Fingerprint)
			} else {
				set("client-fingerprint", c.Fingerprint)
			}
		}
		ifS("obfs", c.Obfs)
		ifS("obfs-password", c.ObfsPassword)
		ifS("up", c.Up)
		ifS("down", c.Down)
		ifS("ports", c.Ports)
		ifS("hop-interval", c.HopInterval)
	case ProtocolTUIC:
		set("uuid", c.UUID)
		set("password", c.Password)
		ifS("sni", c.SNI)
		if len(c.ALPN) > 0 {
			set("alpn", c.ALPN)
		}
		ifB("skip-cert-verify", c.SkipCertVerify)
		ifS("client-fingerprint", c.Fingerprint)
		ifB("disable-sni", c.DisableSNI)
		if c.ReduceRTT != nil {
			set("reduce-rtt", *c.ReduceRTT)
		}
		ifS("congestion-controller", c.CongestionController)
		ifS("udp-relay-mode", c.UDPRelayMode)
	case ProtocolSOCKS5:
		ifS("username", c.Username)
		ifS("password", c.Password)
		ifB("tls", c.TLS)
		ifS("sni", c.SNI)
		if len(c.ALPN) > 0 {
			set("alpn", c.ALPN)
		}
		ifS("client-fingerprint", c.Fingerprint)
		ifB("skip-cert-verify", c.SkipCertVerify)
		if c.UDP != nil {
			set("udp", *c.UDP)
		}
	case ProtocolHTTP:
		ifS("username", c.Username)
		ifS("password", c.Password)
		ifB("tls", c.TLS)
		ifS("sni", c.SNI)
		if len(c.ALPN) > 0 {
			set("alpn", c.ALPN)
		}
		ifS("client-fingerprint", c.Fingerprint)
		ifB("skip-cert-verify", c.SkipCertVerify)
	case ProtocolSSH:
		ifS("username", c.Username)
		ifS("password", c.Password)
		ifS("private-key", c.PrivateKey)
		ifS("private-key-passphrase", c.PrivateKeyPassphrase)
		if len(c.HostKey) > 0 {
			set("host-key", c.HostKey)
		}
		if len(c.HostKeyAlgorithms) > 0 {
			set("host-key-algorithms", c.HostKeyAlgorithms)
		}
	}

	for _, k := range sortedAnyKeys(c.Extra) {
		set(k, c.Extra[k])
	}
	if dialer != "" {
		set("dialer-proxy", dialer)
	}
	return n, nil
}

func appendTransport(set func(string, any), c Config) {
	if c.WS != nil {
		ws := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		path := c.WS.Path
		if path == "" {
			path = "/"
		}
		ws.Content = append(ws.Content, strNode("path"), strNode(path))
		if len(c.WS.Headers) > 0 {
			h := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			for _, k := range sortedKeys(c.WS.Headers) {
				h.Content = append(h.Content, strNode(k), strNode(c.WS.Headers[k]))
			}
			ws.Content = append(ws.Content, strNode("headers"), h)
		}
		if c.WS.MaxEarlyData > 0 {
			ws.Content = append(ws.Content, strNode("max-early-data"), encodeAny(c.WS.MaxEarlyData))
		}
		if c.WS.EarlyDataHeaderName != "" {
			ws.Content = append(ws.Content, strNode("early-data-header-name"), strNode(c.WS.EarlyDataHeaderName))
		}
		set("ws-opts", ws)
	}
	if c.GRPC != nil {
		g := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		g.Content = append(g.Content, strNode("grpc-service-name"), strNode(c.GRPC.ServiceName))
		set("grpc-opts", g)
	}
	if c.HTTP != nil {
		h := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if c.HTTP.Method != "" {
			h.Content = append(h.Content, strNode("method"), strNode(c.HTTP.Method))
		}
		if len(c.HTTP.Path) > 0 {
			h.Content = append(h.Content, strNode("path"), encodeAny(c.HTTP.Path))
		}
		if len(c.HTTP.Headers) > 0 {
			headers := map[string]any{}
			for k, v := range c.HTTP.Headers {
				headers[k] = v
			}
			h.Content = append(h.Content, strNode("headers"), encodeAny(headers))
		}
		set("http-opts", h)
	}
	if c.H2 != nil {
		h := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if len(c.H2.Host) > 0 {
			h.Content = append(h.Content, strNode("host"), encodeAny(c.H2.Host))
		}
		if c.H2.Path != "" {
			h.Content = append(h.Content, strNode("path"), strNode(c.H2.Path))
		}
		set("h2-opts", h)
	}
}

func renderGroup(g Group) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	n.Content = append(n.Content, strNode("name"), strNode(g.Name))
	n.Content = append(n.Content, strNode("type"), strNode(g.Type))
	n.Content = append(n.Content, strNode("proxies"), encodeAny(g.Proxies))
	if g.Type != "select" {
		url := g.URL
		if url == "" {
			url = "https://www.gstatic.com/generate_204"
		}
		interval := g.Interval
		if interval == 0 {
			interval = 300
		}
		n.Content = append(n.Content, strNode("url"), strNode(url))
		n.Content = append(n.Content, strNode("interval"), encodeAny(interval))
		if g.Tolerance > 0 {
			n.Content = append(n.Content, strNode("tolerance"), encodeAny(g.Tolerance))
		}
		if g.Lazy {
			n.Content = append(n.Content, strNode("lazy"), encodeAny(true))
		}
		if g.Type == "load-balance" && g.Strategy != "" {
			n.Content = append(n.Content, strNode("strategy"), strNode(g.Strategy))
		}
	}
	return n
}

func strNode(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

func encodeAny(v any) *yaml.Node {
	switch val := v.(type) {
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
	case map[string]any:
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, k := range sortedKeys(val) {
			n.Content = append(n.Content, strNode(k), encodeAny(val[k]))
		}
		return n
	case map[string]string:
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, k := range sortedKeys(val) {
			n.Content = append(n.Content, strNode(k), strNode(val[k]))
		}
		return n
	case []string:
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range val {
			n.Content = append(n.Content, strNode(item))
		}
		return n
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range val {
			n.Content = append(n.Content, encodeAny(item))
		}
		return n
	case int, int64, uint64, float64, bool:
		var n yaml.Node
		if err := n.Encode(val); err != nil {
			return strNode(fmt.Sprint(val))
		}
		return &n
	default:
		var n yaml.Node
		if err := n.Encode(val); err != nil {
			return strNode(fmt.Sprint(val))
		}
		return &n
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedAnyKeys(m map[string]any) []string {
	return sortedKeys(m)
}

func marshalNode(root *yaml.Node) ([]byte, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("encode YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("finalize YAML: %w", err)
	}
	return []byte(b.String()), nil
}

// ExportProxiesYAML renders a standalone `proxies:` document for backup/export.
func ExportProxiesYAML(nodes []Node) ([]byte, error) {
	sorted := append([]Node(nil), nodes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := strings.ToLower(sorted[i].Name), strings.ToLower(sorted[j].Name)
		if a != b {
			return a < b
		}
		return sorted[i].ID < sorted[j].ID
	})
	alloc := newAllocator()
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, n := range sorted {
		if !ProtocolValid(n.Protocol) {
			return nil, fmt.Errorf("node %q has unsupported protocol", n.Name)
		}
		if err := ValidateConfig(n.Protocol, n.Config); err != nil {
			return nil, fmt.Errorf("node %q: %w", n.Name, err)
		}
		p, err := renderProxy(alloc.assign(exportDisplayName(n.Name, n.Country)), n.Protocol, n.Config, "")
		if err != nil {
			return nil, err
		}
		seq.Content = append(seq.Content, p)
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	root.Content = append(root.Content, strNode("proxies"), seq)
	return marshalNode(root)
}

func looksLikeCertFingerprint(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) == 64 {
		if _, err := hex.DecodeString(value); err == nil {
			return true
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(value); err == nil && len(raw) == 32 {
			return true
		}
	}
	return false
}
