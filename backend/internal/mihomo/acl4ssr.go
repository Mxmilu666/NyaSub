package mihomo

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed acl4ssr_online.ini
var acl4ssrOnlineINI string

// RuleProvider is rendered into Mihomo's rule-providers section.
type RuleProvider struct {
	Name     string
	Type     string
	Behavior string
	URL      string
	Path     string
	Interval int
}

type acl4GroupTemplate struct {
	Name      string
	Type      string
	URL       string
	Interval  int
	Tolerance int
	Selectors []string
}

type acl4RuleTemplate struct {
	Target  string
	URL     string
	Type    string
	Payload string
	Final   bool
}

type acl4Preset struct {
	Groups []acl4GroupTemplate
	Rules  []acl4RuleTemplate
}

var (
	acl4Once  sync.Once
	acl4Value *acl4Preset
	acl4Err   error
)

func loadACL4SSRPreset() (*acl4Preset, error) {
	acl4Once.Do(func() {
		acl4Value, acl4Err = parseACL4SSR(acl4ssrOnlineINI)
	})
	return acl4Value, acl4Err
}

func parseACL4SSR(raw string) (*acl4Preset, error) {
	preset := &acl4Preset{}
	groups := map[string]bool{}
	for lineNo, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "ruleset":
			rule, err := parseACL4Rule(value)
			if err != nil {
				return nil, fmt.Errorf("ACL4SSR line %d: %w", lineNo+1, err)
			}
			preset.Rules = append(preset.Rules, rule)
		case "custom_proxy_group":
			group, err := parseACL4Group(value)
			if err != nil {
				return nil, fmt.Errorf("ACL4SSR line %d: %w", lineNo+1, err)
			}
			if groups[group.Name] {
				return nil, fmt.Errorf("ACL4SSR has duplicate proxy group %q", group.Name)
			}
			groups[group.Name] = true
			preset.Groups = append(preset.Groups, group)
		}
	}
	if len(preset.Groups) == 0 || len(preset.Rules) == 0 {
		return nil, fmt.Errorf("ACL4SSR config is missing groups or rules")
	}
	return preset, nil
}

func parseACL4Rule(value string) (acl4RuleTemplate, error) {
	target, rest, ok := strings.Cut(value, ",")
	target = strings.TrimSpace(target)
	rest = strings.TrimSpace(rest)
	if !ok || target == "" || rest == "" {
		return acl4RuleTemplate{}, fmt.Errorf("invalid ruleset entry")
	}
	if strings.HasPrefix(rest, "[]") {
		directive := strings.TrimSpace(strings.TrimPrefix(rest, "[]"))
		if directive == "FINAL" || directive == "MATCH" {
			return acl4RuleTemplate{Target: target, Final: true}, nil
		}
		typeName, payload, ok := strings.Cut(directive, ",")
		if !ok || strings.TrimSpace(payload) == "" {
			return acl4RuleTemplate{}, fmt.Errorf("invalid direct ruleset %q", directive)
		}
		return acl4RuleTemplate{
			Target: target, Type: strings.ToUpper(strings.TrimSpace(typeName)),
			Payload: strings.TrimSpace(payload),
		}, nil
	}
	if !strings.HasPrefix(rest, "http://") && !strings.HasPrefix(rest, "https://") {
		return acl4RuleTemplate{}, fmt.Errorf("unsupported ruleset source %q", rest)
	}
	return acl4RuleTemplate{Target: target, URL: rest}, nil
}

func parseACL4Group(value string) (acl4GroupTemplate, error) {
	fields := strings.Split(value, "`")
	if len(fields) < 3 {
		return acl4GroupTemplate{}, fmt.Errorf("invalid custom_proxy_group entry")
	}
	group := acl4GroupTemplate{
		Name: strings.TrimSpace(fields[0]),
		Type: strings.TrimSpace(fields[1]),
	}
	if group.Name == "" {
		return acl4GroupTemplate{}, fmt.Errorf("proxy group name is empty")
	}
	for _, rawField := range fields[2:] {
		field := strings.TrimSpace(rawField)
		if field == "" {
			continue
		}
		if strings.HasPrefix(field, "[]") {
			ref := strings.TrimSpace(field[2:])
			if ref == "" {
				continue
			}
			if ref == "DIRECT" || ref == "REJECT" {
				group.Selectors = append(group.Selectors, ref)
			} else {
				group.Selectors = append(group.Selectors, "group:"+ref)
			}
			continue
		}
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			group.URL = field
			continue
		}
		if group.Type != "select" && group.URL != "" {
			parseACL4GroupTuning(field, &group)
			continue
		}
		group.Selectors = append(group.Selectors, "pattern:"+field)
	}
	if len(group.Selectors) == 0 {
		return acl4GroupTemplate{}, fmt.Errorf("proxy group %q has no members", group.Name)
	}
	if group.Type != "select" && group.URL == "" {
		return acl4GroupTemplate{}, fmt.Errorf("proxy group %q requires a test URL", group.Name)
	}
	return group, nil
}

func parseACL4GroupTuning(value string, group *acl4GroupTemplate) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return
	}
	if n, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && n >= 0 {
		group.Interval = n
	}
	if len(parts) > 1 {
		last := strings.TrimSpace(parts[len(parts)-1])
		if n, err := strconv.Atoi(last); err == nil && n >= 0 {
			group.Tolerance = n
		}
	}
}

type acl4Proxy struct {
	Name string
	Tags []string
}

func hasTag(tags []string, tag string) bool {
	for _, value := range tags {
		if strings.EqualFold(strings.TrimSpace(value), tag) {
			return true
		}
	}
	return false
}

func resolveACL4Groups(preset *acl4Preset, alloc *allocator, proxies []acl4Proxy) ([]Group, map[string]string, error) {
	allocated := make(map[string]string, len(preset.Groups))
	for _, template := range preset.Groups {
		allocated[template.Name] = alloc.assign(template.Name)
	}
	for _, group := range preset.Groups {
		for _, selector := range group.Selectors {
			if !strings.HasPrefix(selector, "group:") {
				continue
			}
			target := strings.TrimPrefix(selector, "group:")
			if _, ok := allocated[target]; !ok {
				return nil, nil, fmt.Errorf("ACL4SSR group %q references unknown group %q", group.Name, target)
			}
		}
	}
	state := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("ACL4SSR proxy groups contain a reference cycle at %q", name)
		case 2:
			return nil
		}
		state[name] = 1
		for _, group := range preset.Groups {
			if group.Name != name {
				continue
			}
			for _, selector := range group.Selectors {
				if strings.HasPrefix(selector, "group:") {
					if err := visit(strings.TrimPrefix(selector, "group:")); err != nil {
						return err
					}
				}
			}
		}
		state[name] = 2
		return nil
	}
	for _, group := range preset.Groups {
		if err := visit(group.Name); err != nil {
			return nil, nil, err
		}
	}

	out := make([]Group, 0, len(preset.Groups))
	for _, template := range preset.Groups {
		if !groupTypes[template.Type] {
			return nil, nil, fmt.Errorf("ACL4SSR group %q has unsupported type %q", template.Name, template.Type)
		}
		group := Group{
			Name: allocated[template.Name], Type: template.Type, URL: template.URL,
			Interval: template.Interval, Tolerance: template.Tolerance,
		}
		seen := map[string]bool{}
		add := func(name string) {
			if name != "" && !seen[name] {
				seen[name] = true
				group.Proxies = append(group.Proxies, name)
			}
		}
		for _, selector := range template.Selectors {
			switch {
			case selector == "DIRECT" || selector == "REJECT":
				add(selector)
			case strings.HasPrefix(selector, "group:"):
				add(allocated[strings.TrimPrefix(selector, "group:")])
			case strings.HasPrefix(selector, "pattern:"):
				pattern := strings.TrimPrefix(selector, "pattern:")
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, nil, fmt.Errorf("ACL4SSR group %q has invalid member pattern: %w", template.Name, err)
				}
				skipLanding := template.Name == "🚀 节点选择" || template.Name == "♻️ 自动选择"
				for _, proxy := range proxies {
					if skipLanding && hasTag(proxy.Tags, "落地机") {
						continue
					}
					if re.MatchString(proxy.Name) {
						add(proxy.Name)
					}
				}
			default:
				return nil, nil, fmt.Errorf("ACL4SSR group %q has invalid member", template.Name)
			}
		}
		if len(group.Proxies) == 0 {
			group.Proxies = []string{"DIRECT"}
		}
		if group.Type != "select" && group.URL == "" {
			return nil, nil, fmt.Errorf("ACL4SSR group %q has no test URL", template.Name)
		}
		out = append(out, group)
	}
	return out, allocated, nil
}

func resolveACL4Rules(preset *acl4Preset, groups map[string]string) ([]string, []RuleProvider, string, error) {
	lines := make([]string, 0, len(preset.Rules))
	providers := make([]RuleProvider, 0, len(preset.Rules))
	providerCount := 0
	matchTarget := ""
	for _, rule := range preset.Rules {
		target, ok := groups[rule.Target]
		if !ok {
			return nil, nil, "", fmt.Errorf("ACL4SSR rule references unknown group %q", rule.Target)
		}
		switch {
		case rule.Final:
			lines = append(lines, "MATCH,"+target)
			matchTarget = target
		case rule.URL != "":
			providerCount++
			name := fmt.Sprintf("acl4ssr-%02d", providerCount)
			providers = append(providers, RuleProvider{
				Name: name, Type: "http", Behavior: "classical", URL: rule.URL,
				Path: "./rules/acl4ssr/" + name + ".yaml", Interval: 86400,
			})
			lines = append(lines, "RULE-SET,"+name+","+target)
		default:
			lines = append(lines, rule.Type+","+rule.Payload+","+target)
		}
	}
	if matchTarget == "" {
		return nil, nil, "", fmt.Errorf("ACL4SSR preset has no FINAL rule")
	}
	return lines, providers, matchTarget, nil
}

func ruleProviderMap(providers []RuleProvider) map[string]any {
	out := make(map[string]any, len(providers))
	for _, provider := range providers {
		out[provider.Name] = map[string]any{
			"type": provider.Type, "behavior": provider.Behavior, "url": provider.URL,
			"path": provider.Path, "interval": provider.Interval,
		}
	}
	return out
}
