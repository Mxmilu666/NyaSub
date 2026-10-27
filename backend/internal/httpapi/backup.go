package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"nyasub/internal/mihomo"
	"nyasub/internal/security"
	"nyasub/internal/store"
)

const backupFormat = 1

type backupUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type backupSession struct {
	ID         string    `json:"id"`
	TokenHash  string    `json:"token_hash"`
	UserID     string    `json:"user_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	CreatedAt  time.Time `json:"created_at"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
}

type backupNode struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Country   string    `json:"country,omitempty"`
	Protocol  string    `json:"protocol"`
	Config    string    `json:"config"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type backupNodeTag struct {
	NodeID string `json:"node_id"`
	Tag    string `json:"tag"`
}

type backupChain struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	EntryNodeID string    `json:"entry_node_id"`
	ExitNodeID  string    `json:"exit_node_id"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type backupProfile struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Template         string    `json:"template,omitempty"`
	DefaultExitType  string    `json:"default_exit_type"`
	DefaultExitID    string    `json:"default_exit_id"`
	ForceDefaultExit bool      `json:"force_default_exit"`
	GroupsJSON       string    `json:"groups_json"`
	RulesJSON        string    `json:"rules_json"`
	DNSJSON          string    `json:"dns_json"`
	GeneralJSON      string    `json:"general_json"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type backupProfileNode struct {
	ProfileID string `json:"profile_id"`
	NodeID    string `json:"node_id"`
}

type backupProfileChain struct {
	ProfileID string `json:"profile_id"`
	ChainID   string `json:"chain_id"`
}

type backupToken struct {
	ID         string     `json:"id"`
	ProfileID  string     `json:"profile_id"`
	TokenHash  string     `json:"token_hash"`
	Token      string     `json:"token,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

type backupSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type backupData struct {
	Users              []backupUser         `json:"users"`
	Sessions           []backupSession      `json:"sessions"`
	Nodes              []backupNode         `json:"nodes"`
	NodeTags           []backupNodeTag      `json:"node_tags"`
	Chains             []backupChain        `json:"chains"`
	Profiles           []backupProfile      `json:"profiles"`
	ProfileNodes       []backupProfileNode  `json:"profile_nodes"`
	ProfileChains      []backupProfileChain `json:"profile_chains"`
	SubscriptionTokens []backupToken        `json:"subscription_tokens"`
	AppSettings        []backupSetting      `json:"app_settings"`
}

type backupFile struct {
	Format     int        `json:"format"`
	App        string     `json:"app"`
	Version    string     `json:"version"`
	ExportedAt time.Time  `json:"exported_at"`
	Data       backupData `json:"data"`
}

func (a *App) downloadBackup(c *gin.Context) {
	ctx := c.Request.Context()
	db := a.db.WithContext(ctx)
	var users []store.User
	var sessions []store.Session
	var nodes []store.Node
	var tags []store.NodeTag
	var chains []store.Chain
	var profiles []store.Profile
	var profileNodes []store.ProfileNode
	var profileChains []store.ProfileChain
	var tokens []store.SubscriptionToken
	var settings []store.AppSetting
	queries := []any{&users, &sessions, &nodes, &tags, &chains, &profiles, &profileNodes, &profileChains, &tokens, &settings}
	for _, dst := range queries {
		if err := db.Find(dst).Error; err != nil {
			a.log.Error("backup query", "error", err)
			writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
	}
	backup := backupFile{
		Format: backupFormat, App: "nyasub", Version: a.version, ExportedAt: time.Now().UTC(),
	}
	for _, u := range users {
		backup.Data.Users = append(backup.Data.Users, backupUser{u.ID, u.Username, u.PasswordHash, u.CreatedAt, u.UpdatedAt})
	}
	for _, s := range sessions {
		backup.Data.Sessions = append(backup.Data.Sessions, backupSession{s.ID, s.TokenHash, s.UserID, s.ExpiresAt, s.LastSeenAt, s.CreatedAt, s.IP, s.UserAgent})
	}
	for _, n := range nodes {
		backup.Data.Nodes = append(backup.Data.Nodes, backupNode{ID: n.ID, Name: n.Name, Country: n.Country, Protocol: n.Protocol, Config: n.Config, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt})
	}
	for _, t := range tags {
		backup.Data.NodeTags = append(backup.Data.NodeTags, backupNodeTag{t.NodeID, t.Tag})
	}
	for _, ch := range chains {
		backup.Data.Chains = append(backup.Data.Chains, backupChain{ch.ID, ch.Name, ch.EntryNodeID, ch.ExitNodeID, ch.Enabled, ch.CreatedAt, ch.UpdatedAt})
	}
	for _, p := range profiles {
		backup.Data.Profiles = append(backup.Data.Profiles, backupProfile{
			ID: p.ID, Name: p.Name, Description: p.Description, Template: p.Template,
			DefaultExitType: p.DefaultExitType, DefaultExitID: p.DefaultExitID,
			ForceDefaultExit: p.ForceDefaultExit, GroupsJSON: p.GroupsJSON, RulesJSON: p.RulesJSON,
			DNSJSON: p.DNSJSON, GeneralJSON: p.GeneralJSON, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		})
	}
	for _, pn := range profileNodes {
		backup.Data.ProfileNodes = append(backup.Data.ProfileNodes, backupProfileNode{pn.ProfileID, pn.NodeID})
	}
	for _, pc := range profileChains {
		backup.Data.ProfileChains = append(backup.Data.ProfileChains, backupProfileChain{pc.ProfileID, pc.ChainID})
	}
	for _, t := range tokens {
		backup.Data.SubscriptionTokens = append(backup.Data.SubscriptionTokens, backupToken{
			ID: t.ID, ProfileID: t.ProfileID, TokenHash: t.TokenHash, Token: t.Token,
			CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
		})
	}
	for _, s := range settings {
		backup.Data.AppSettings = append(backup.Data.AppSettings, backupSetting{s.Key, s.Value})
	}
	raw, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="nyasub-backup-%s.json"`, time.Now().UTC().Format("20060102-150405")))
	c.Header("X-Backup-Sensitive", "true")
	c.Data(http.StatusOK, "application/json; charset=utf-8", raw)
}

func isHexHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// validateBackup checks the entire snapshot before anything is deleted.
func validateBackup(b *backupFile) error {
	if b.Format != backupFormat {
		return fmt.Errorf("unsupported backup format %d", b.Format)
	}
	if len(b.Data.Users) == 0 {
		return fmt.Errorf("backup contains no administrator account")
	}
	users := map[string]backupUser{}
	usernames := map[string]bool{}
	for _, u := range b.Data.Users {
		if u.ID == "" || users[u.ID].ID != "" {
			return fmt.Errorf("backup contains duplicate or empty user id")
		}
		if !usernameRe.MatchString(u.Username) || usernames[strings.ToLower(u.Username)] {
			return fmt.Errorf("backup contains an invalid or duplicate username")
		}
		if !strings.HasPrefix(u.PasswordHash, "$argon2id$") || len(u.PasswordHash) > 512 {
			return fmt.Errorf("backup contains an invalid password hash")
		}
		users[u.ID] = u
		usernames[strings.ToLower(u.Username)] = true
	}
	nodes := map[string]backupNode{}
	settings := map[string]string{}
	for _, s := range b.Data.AppSettings {
		if s.Key == "" || len(s.Key) > 64 {
			return fmt.Errorf("backup contains an invalid app setting")
		}
		if _, ok := settings[s.Key]; ok {
			return fmt.Errorf("backup contains duplicate app settings")
		}
		settings[s.Key] = s.Value
	}
	if _, ok := settings["initialized"]; !ok && len(b.Data.Users) > 0 {
		b.Data.AppSettings = append(b.Data.AppSettings, backupSetting{Key: "initialized", Value: "1"})
	}
	for i := range b.Data.Nodes {
		n := &b.Data.Nodes[i]
		if n.ID == "" || nodes[n.ID].ID != "" {
			return fmt.Errorf("backup contains duplicate or empty node id")
		}
		if err := mihomo.ValidateName(n.Name); err != nil {
			return fmt.Errorf("backup contains an invalid node name")
		}
		country, err := mihomo.NormalizeCountry(n.Country)
		if err != nil {
			return fmt.Errorf("backup contains an invalid node country")
		}
		n.Country = country
		protocol := mihomo.Protocol(n.Protocol)
		if !mihomo.ProtocolValid(protocol) {
			return fmt.Errorf("backup contains an unsupported node protocol")
		}
		if len(n.Config) > 128*1024 {
			return fmt.Errorf("backup contains an oversized node config")
		}
		cfg, err := decodeConfig(n.Config)
		if err != nil {
			return fmt.Errorf("backup contains an invalid node config")
		}
		if err := mihomo.ValidateConfig(protocol, cfg); err != nil {
			return err
		}
		nodes[n.ID] = *n
	}
	tagsSeen := map[string]bool{}
	for _, t := range b.Data.NodeTags {
		if _, ok := nodes[t.NodeID]; !ok {
			return fmt.Errorf("backup contains a tag for a missing node")
		}
		if t.Tag == "" || len([]rune(t.Tag)) > 32 || strings.ContainsAny(t.Tag, "\r\n") {
			return fmt.Errorf("backup contains an invalid tag")
		}
		key := t.NodeID + "\x00" + t.Tag
		if tagsSeen[key] {
			return fmt.Errorf("backup contains duplicate tags")
		}
		tagsSeen[key] = true
	}
	chains := map[string]backupChain{}
	for _, ch := range b.Data.Chains {
		if ch.ID == "" || chains[ch.ID].ID != "" {
			return fmt.Errorf("backup contains duplicate or empty chain id")
		}
		if err := mihomo.ValidateName(ch.Name); err != nil {
			return fmt.Errorf("backup contains an invalid chain name")
		}
		if _, ok := nodes[ch.EntryNodeID]; !ok {
			return fmt.Errorf("backup contains a chain with a missing entry node")
		}
		if _, ok := nodes[ch.ExitNodeID]; !ok {
			return fmt.Errorf("backup contains a chain with a missing exit node")
		}
		if ch.EntryNodeID == ch.ExitNodeID {
			return fmt.Errorf("backup contains a chain with identical entry and exit nodes")
		}
		chains[ch.ID] = ch
	}
	chainModels := make([]store.Chain, 0, len(b.Data.Chains))
	for _, ch := range b.Data.Chains {
		cModel := store.Chain{ID: ch.ID, EntryNodeID: ch.EntryNodeID, ExitNodeID: ch.ExitNodeID}
		chainModels = append(chainModels, cModel)
	}
	if err := detectChainCycle(chainModels); err != nil {
		return fmt.Errorf("backup contains a chain cycle")
	}
	profiles := map[string]backupProfile{}
	for _, p := range b.Data.Profiles {
		if p.ID == "" || profiles[p.ID].ID != "" {
			return fmt.Errorf("backup contains duplicate or empty profile id")
		}
		if err := mihomo.ValidateName(p.Name); err != nil {
			return fmt.Errorf("backup contains an invalid profile name")
		}
		if len(p.Description) > 1000 {
			return fmt.Errorf("backup contains an oversized profile description")
		}
		if p.Template != "" && p.Template != "acl4ssr" {
			return fmt.Errorf("backup contains an invalid profile template")
		}
		if p.DefaultExitType != "" && p.DefaultExitType != "node" && p.DefaultExitType != "chain" {
			return fmt.Errorf("backup contains an invalid default exit type")
		}
		for _, raw := range []string{p.GroupsJSON, p.RulesJSON, p.DNSJSON, p.GeneralJSON} {
			if len(raw) > 512*1024 {
				return fmt.Errorf("backup contains an oversized profile configuration")
			}
		}
		if strings.TrimSpace(p.GroupsJSON) != "" {
			var groups []mihomo.Group
			if err := json.Unmarshal([]byte(p.GroupsJSON), &groups); err != nil {
				return fmt.Errorf("backup contains invalid profile groups")
			}
		}
		if strings.TrimSpace(p.RulesJSON) != "" {
			var rules []mihomo.Rule
			if err := json.Unmarshal([]byte(p.RulesJSON), &rules); err != nil {
				return fmt.Errorf("backup contains invalid profile rules")
			}
		}
		if strings.TrimSpace(p.DNSJSON) != "" {
			var dns map[string]any
			if err := json.Unmarshal([]byte(p.DNSJSON), &dns); err != nil {
				return fmt.Errorf("backup contains invalid DNS config")
			}
		}
		if strings.TrimSpace(p.GeneralJSON) != "" {
			var general map[string]any
			if err := json.Unmarshal([]byte(p.GeneralJSON), &general); err != nil {
				return fmt.Errorf("backup contains invalid general config")
			}
		}
		profiles[p.ID] = p
	}
	profileNodes := map[string][]string{}
	for _, pn := range b.Data.ProfileNodes {
		if _, ok := profiles[pn.ProfileID]; !ok {
			return fmt.Errorf("backup contains a profile-node link for a missing profile")
		}
		if _, ok := nodes[pn.NodeID]; !ok {
			return fmt.Errorf("backup contains a profile-node link for a missing node")
		}
		if profileNodes[pn.ProfileID] == nil {
			profileNodes[pn.ProfileID] = []string{}
		}
		if containsString(profileNodes[pn.ProfileID], pn.NodeID) {
			return fmt.Errorf("backup contains duplicate profile-node links")
		}
		profileNodes[pn.ProfileID] = append(profileNodes[pn.ProfileID], pn.NodeID)
	}
	profileChains := map[string][]string{}
	for _, pc := range b.Data.ProfileChains {
		if _, ok := profiles[pc.ProfileID]; !ok {
			return fmt.Errorf("backup contains a profile-chain link for a missing profile")
		}
		if _, ok := chains[pc.ChainID]; !ok {
			return fmt.Errorf("backup contains a profile-chain link for a missing chain")
		}
		if containsString(profileChains[pc.ProfileID], pc.ChainID) {
			return fmt.Errorf("backup contains duplicate profile-chain links")
		}
		profileChains[pc.ProfileID] = append(profileChains[pc.ProfileID], pc.ChainID)
	}
	tokenIDs := map[string]bool{}
	for _, t := range b.Data.SubscriptionTokens {
		if t.ID == "" || tokenIDs[t.ID] {
			return fmt.Errorf("backup contains duplicate or empty token id")
		}
		if _, ok := profiles[t.ProfileID]; !ok {
			return fmt.Errorf("backup contains a token for a missing profile")
		}
		if !isHexHash(t.TokenHash) {
			return fmt.Errorf("backup contains an invalid subscription token hash")
		}
		if t.Token != "" {
			if len(t.Token) < 16 || len(t.Token) > 200 || security.HashToken(t.Token) != t.TokenHash {
				return fmt.Errorf("backup contains an invalid subscription token")
			}
		}
		tokenIDs[t.ID] = true
	}
	sessionIDs := map[string]bool{}
	for _, s := range b.Data.Sessions {
		if s.ID == "" || sessionIDs[s.ID] {
			return fmt.Errorf("backup contains duplicate or empty session id")
		}
		if _, ok := users[s.UserID]; !ok {
			return fmt.Errorf("backup contains a session for a missing user")
		}
		if !isHexHash(s.TokenHash) {
			return fmt.Errorf("backup contains an invalid session hash")
		}
		sessionIDs[s.ID] = true
	}

	// Full generation dry-run for every profile.
	nodeModels := make(map[string]store.Node, len(nodes))
	for id, n := range nodes {
		nodeModels[id] = store.Node{ID: n.ID, Name: n.Name, Country: n.Country, Protocol: n.Protocol, Config: n.Config}
	}
	chainModelsByID := map[string]store.Chain{}
	for _, ch := range b.Data.Chains {
		entry := nodeModels[ch.EntryNodeID]
		exit := nodeModels[ch.ExitNodeID]
		chainModelsByID[ch.ID] = store.Chain{
			ID: ch.ID, Name: ch.Name, EntryNodeID: ch.EntryNodeID, ExitNodeID: ch.ExitNodeID,
			Enabled: ch.Enabled, EntryNode: entry, ExitNode: exit,
		}
	}
	for _, p := range b.Data.Profiles {
		var nodesForProfile []store.Node
		for _, id := range profileNodes[p.ID] {
			nodesForProfile = append(nodesForProfile, nodeModels[id])
		}
		var chainsForProfile []store.Chain
		for _, id := range profileChains[p.ID] {
			chainsForProfile = append(chainsForProfile, chainModelsByID[id])
		}
		model := store.Profile{
			ID: p.ID, Name: p.Name, Description: p.Description, Template: p.Template,
			DefaultExitType: p.DefaultExitType, DefaultExitID: p.DefaultExitID,
			ForceDefaultExit: p.ForceDefaultExit,
			GroupsJSON:       p.GroupsJSON, RulesJSON: p.RulesJSON, DNSJSON: p.DNSJSON, GeneralJSON: p.GeneralJSON,
		}
		bundle, err := buildBundle(model, nodesForProfile, chainsForProfile)
		if err != nil {
			return fmt.Errorf("profile %q is invalid: %w", p.Name, err)
		}
		if _, err := mihomo.Generate(bundle.Spec); err != nil {
			return fmt.Errorf("profile %q cannot be generated: %w", p.Name, err)
		}
	}
	return nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func (a *App) restoreBackup(c *gin.Context) {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	var backup backupFile
	if err := dec.Decode(&backup); err != nil {
		if err == io.EOF {
			writeError(c, http.StatusBadRequest, "invalid_backup", "backup body is required")
			return
		}
		writeError(c, http.StatusBadRequest, "invalid_backup", "invalid backup JSON")
		return
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		writeError(c, http.StatusBadRequest, "invalid_backup", "backup must contain exactly one JSON document")
		return
	}
	if err := validateBackup(&backup); err != nil {
		writeError(c, http.StatusUnprocessableEntity, "invalid_backup", err.Error())
		return
	}

	users := make([]store.User, 0, len(backup.Data.Users))
	for _, u := range backup.Data.Users {
		users = append(users, store.User{ID: u.ID, Username: u.Username, PasswordHash: u.PasswordHash, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt})
	}
	sessions := make([]store.Session, 0, len(backup.Data.Sessions))
	for _, s := range backup.Data.Sessions {
		sessions = append(sessions, store.Session{
			ID: s.ID, TokenHash: s.TokenHash, UserID: s.UserID, ExpiresAt: s.ExpiresAt,
			LastSeenAt: s.LastSeenAt, CreatedAt: s.CreatedAt, IP: s.IP, UserAgent: s.UserAgent,
		})
	}
	nodes := make([]store.Node, 0, len(backup.Data.Nodes))
	for _, n := range backup.Data.Nodes {
		nodes = append(nodes, store.Node{ID: n.ID, Name: n.Name, Country: n.Country, Protocol: n.Protocol, Config: n.Config, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt})
	}
	tags := make([]store.NodeTag, 0, len(backup.Data.NodeTags))
	for _, t := range backup.Data.NodeTags {
		tags = append(tags, store.NodeTag{NodeID: t.NodeID, Tag: t.Tag})
	}
	chains := make([]store.Chain, 0, len(backup.Data.Chains))
	for _, ch := range backup.Data.Chains {
		chains = append(chains, store.Chain{
			ID: ch.ID, Name: ch.Name, EntryNodeID: ch.EntryNodeID, ExitNodeID: ch.ExitNodeID,
			Enabled: ch.Enabled, CreatedAt: ch.CreatedAt, UpdatedAt: ch.UpdatedAt,
		})
	}
	profiles := make([]store.Profile, 0, len(backup.Data.Profiles))
	for _, p := range backup.Data.Profiles {
		profiles = append(profiles, store.Profile{
			ID: p.ID, Name: p.Name, Description: p.Description, Template: p.Template,
			DefaultExitType: p.DefaultExitType, DefaultExitID: p.DefaultExitID,
			ForceDefaultExit: p.ForceDefaultExit,
			GroupsJSON:       defaultJSON(p.GroupsJSON, "[]"), RulesJSON: defaultJSON(p.RulesJSON, "[]"),
			DNSJSON: defaultJSON(p.DNSJSON, "{}"), GeneralJSON: defaultJSON(p.GeneralJSON, "{}"),
			CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		})
	}
	profileNodes := make([]store.ProfileNode, 0, len(backup.Data.ProfileNodes))
	for _, pn := range backup.Data.ProfileNodes {
		profileNodes = append(profileNodes, store.ProfileNode{ProfileID: pn.ProfileID, NodeID: pn.NodeID})
	}
	profileChains := make([]store.ProfileChain, 0, len(backup.Data.ProfileChains))
	for _, pc := range backup.Data.ProfileChains {
		profileChains = append(profileChains, store.ProfileChain{ProfileID: pc.ProfileID, ChainID: pc.ChainID})
	}
	tokens := make([]store.SubscriptionToken, 0, len(backup.Data.SubscriptionTokens))
	for _, t := range backup.Data.SubscriptionTokens {
		tokens = append(tokens, store.SubscriptionToken{
			ID: t.ID, ProfileID: t.ProfileID, TokenHash: t.TokenHash, Token: t.Token,
			CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
		})
	}
	settings := make([]store.AppSetting, 0, len(backup.Data.AppSettings))
	for _, s := range backup.Data.AppSettings {
		settings = append(settings, store.AppSetting{Key: s.Key, Value: s.Value})
	}

	err := a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		for _, table := range []string{"sessions", "subscription_tokens", "profile_chains", "profile_nodes", "profiles", "chains", "node_tags", "nodes", "users", "app_settings"} {
			if err := tx.Exec("DELETE FROM " + table).Error; err != nil {
				return err
			}
		}
		if err := tx.Omit(clause.Associations).CreateInBatches(&users, 100).Error; err != nil {
			return err
		}
		if len(nodes) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&nodes, 100).Error; err != nil {
				return err
			}
		}
		if len(tags) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&tags, 200).Error; err != nil {
				return err
			}
		}
		if len(chains) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&chains, 100).Error; err != nil {
				return err
			}
		}
		if len(profiles) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&profiles, 100).Error; err != nil {
				return err
			}
		}
		if len(profileNodes) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&profileNodes, 200).Error; err != nil {
				return err
			}
		}
		if len(profileChains) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&profileChains, 200).Error; err != nil {
				return err
			}
		}
		if len(tokens) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&tokens, 200).Error; err != nil {
				return err
			}
		}
		if len(sessions) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&sessions, 100).Error; err != nil {
				return err
			}
		}
		if len(settings) > 0 {
			if err := tx.Omit(clause.Associations).CreateInBatches(&settings, 100).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		a.log.Error("restore backup", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to restore backup")
		return
	}
	a.clearSessionCookie(c)
	c.JSON(http.StatusOK, gin.H{"restored": true, "relogin_required": true})
}

func defaultJSON(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
