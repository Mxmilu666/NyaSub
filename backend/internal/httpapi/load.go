package httpapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"nyasub/internal/mihomo"
	"nyasub/internal/store"
)

func newUUID() string { return uuid.NewString() }

func decodeConfig(raw string) (mihomo.Config, error) {
	var c mihomo.Config
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid stored node config: %w", err)
	}
	return c, nil
}

func nodeToMihomo(n store.Node) (mihomo.Node, error) {
	c, err := decodeConfig(n.Config)
	if err != nil {
		return mihomo.Node{}, err
	}
	return mihomo.Node{
		ID: n.ID, Name: n.Name, Country: n.Country, Protocol: mihomo.Protocol(n.Protocol), Config: c, Tags: tagValues(n.Tags),
	}, nil
}

func tagValues(tags []store.NodeTag) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, t.Tag)
	}
	sort.Strings(out)
	return out
}

func nodeResponse(n store.Node) (gin.H, error) {
	c, err := decodeConfig(n.Config)
	if err != nil {
		return nil, err
	}
	return gin.H{
		"id":         n.ID,
		"name":       n.Name,
		"country":    n.Country,
		"protocol":   n.Protocol,
		"tags":       tagValues(n.Tags),
		"config":     c,
		"created_at": n.CreatedAt,
		"updated_at": n.UpdatedAt,
	}, nil
}

type profileBundle struct {
	Profile  store.Profile
	Nodes    []store.Node
	Chains   []store.Chain
	NodeIDs  []string
	ChainIDs []string
	Spec     mihomo.Spec
}

func loadProfileBundle(db *gorm.DB, profile store.Profile) (*profileBundle, error) {
	var links []store.ProfileNode
	if err := db.Where("profile_id = ?", profile.ID).Find(&links).Error; err != nil {
		return nil, err
	}
	nodeIDs := make([]string, 0, len(links))
	for _, l := range links {
		nodeIDs = append(nodeIDs, l.NodeID)
	}
	var nodes []store.Node
	if len(nodeIDs) > 0 {
		if err := db.Preload("Tags").Where("id IN ?", nodeIDs).Find(&nodes).Error; err != nil {
			return nil, err
		}
	}
	if len(nodes) != len(nodeIDs) {
		return nil, fmt.Errorf("profile references nodes that no longer exist")
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Name != nodes[j].Name {
			return strings.ToLower(nodes[i].Name) < strings.ToLower(nodes[j].Name)
		}
		return nodes[i].ID < nodes[j].ID
	})

	var chainLinks []store.ProfileChain
	if err := db.Where("profile_id = ?", profile.ID).Find(&chainLinks).Error; err != nil {
		return nil, err
	}
	chainIDs := make([]string, 0, len(chainLinks))
	for _, l := range chainLinks {
		chainIDs = append(chainIDs, l.ChainID)
	}
	var chains []store.Chain
	if len(chainIDs) > 0 {
		if err := db.Preload("EntryNode").Preload("ExitNode").Where("id IN ?", chainIDs).Find(&chains).Error; err != nil {
			return nil, err
		}
	}
	if len(chains) != len(chainIDs) {
		return nil, fmt.Errorf("profile references chains that no longer exist")
	}
	return buildBundle(profile, nodes, chains)
}

func buildBundle(profile store.Profile, nodes []store.Node, chains []store.Chain) (*profileBundle, error) {
	spec := mihomo.Spec{
		DefaultExitType:  profile.DefaultExitType,
		DefaultExitID:    profile.DefaultExitID,
		ForceDefaultExit: profile.ForceDefaultExit,
		UseACL4SSR:       profile.Template == "acl4ssr",
	}
	for _, n := range nodes {
		mn, err := nodeToMihomo(n)
		if err != nil {
			return nil, err
		}
		spec.Nodes = append(spec.Nodes, mn)
	}
	for _, c := range chains {
		entry, err := nodeToMihomo(c.EntryNode)
		if err != nil {
			return nil, fmt.Errorf("chain %q entry: %w", c.Name, err)
		}
		exit, err := nodeToMihomo(c.ExitNode)
		if err != nil {
			return nil, fmt.Errorf("chain %q exit: %w", c.Name, err)
		}
		spec.Chains = append(spec.Chains, mihomo.Chain{
			ID: c.ID, Name: c.Name, Entry: entry, Exit: exit, Enabled: c.Enabled,
		})
	}
	if strings.TrimSpace(profile.GroupsJSON) != "" {
		if err := json.Unmarshal([]byte(profile.GroupsJSON), &spec.Groups); err != nil {
			return nil, fmt.Errorf("invalid stored groups: %w", err)
		}
	}
	if strings.TrimSpace(profile.RulesJSON) != "" {
		if err := json.Unmarshal([]byte(profile.RulesJSON), &spec.Rules); err != nil {
			return nil, fmt.Errorf("invalid stored rules: %w", err)
		}
	}
	if strings.TrimSpace(profile.DNSJSON) != "" {
		if err := json.Unmarshal([]byte(profile.DNSJSON), &spec.DNS); err != nil {
			return nil, fmt.Errorf("invalid stored DNS config: %w", err)
		}
	}
	if strings.TrimSpace(profile.GeneralJSON) != "" {
		if err := json.Unmarshal([]byte(profile.GeneralJSON), &spec.General); err != nil {
			return nil, fmt.Errorf("invalid stored general config: %w", err)
		}
	}
	return &profileBundle{
		Profile: profile, Nodes: nodes, Chains: chains,
		NodeIDs: nodeIDsOf(nodes), ChainIDs: chainIDsOf(chains), Spec: spec,
	}, nil
}

func nodeIDsOf(nodes []store.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

func chainIDsOf(chains []store.Chain) []string {
	out := make([]string, 0, len(chains))
	for _, c := range chains {
		out = append(out, c.ID)
	}
	return out
}

func loadProfileByID(db *gorm.DB, id string) (*profileBundle, error) {
	var profile store.Profile
	if err := db.Where("id = ?", id).First(&profile).Error; err != nil {
		return nil, err
	}
	return loadProfileBundle(db, profile)
}

func decodeConfigJSON(raw json.RawMessage) (mihomo.Config, error) {
	var c mihomo.Config
	if len(raw) == 0 {
		return c, fmt.Errorf("config is required")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return c, fmt.Errorf("invalid config: trailing data")
	}
	return c, nil
}
