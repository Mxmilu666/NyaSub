package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"nyasub/internal/mihomo"
	"nyasub/internal/security"
	"nyasub/internal/store"
)

type profileInput struct {
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	Template         string         `json:"template"`
	NodeIDs          []string       `json:"node_ids"`
	ChainIDs         []string       `json:"chain_ids"`
	DefaultExitType  string         `json:"default_exit_type"`
	DefaultExitID    string         `json:"default_exit_id"`
	ForceDefaultExit bool           `json:"force_default_exit"`
	Groups           []mihomo.Group `json:"groups"`
	Rules            []mihomo.Rule  `json:"rules"`
	DNS              map[string]any `json:"dns"`
	General          map[string]any `json:"general"`
}

type tokenInfo struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	Active     bool       `json:"active"`
	URL        string     `json:"url,omitempty"`
	XrayURL    string     `json:"xray_url,omitempty"`
}

func (a *App) tokenInfo(t store.SubscriptionToken) tokenInfo {
	info := tokenInfo{
		ID: t.ID, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
		Active: t.RevokedAt == nil,
	}
	if t.Token != "" && t.RevokedAt == nil {
		if subscriptionURL, err := url.JoinPath(a.cfg.BaseURL, "s", t.Token); err == nil {
			info.URL = subscriptionURL
			info.XrayURL = subscriptionURL + "?format=xray"
		}
	}
	return info
}

func (a *App) tokenInfos(tokens []store.SubscriptionToken) []tokenInfo {
	out := make([]tokenInfo, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, a.tokenInfo(t))
	}
	return out
}

func (a *App) listProfiles(c *gin.Context) {
	var profiles []store.Profile
	if err := a.db.WithContext(c.Request.Context()).Order("updated_at DESC").Find(&profiles).Error; err != nil {
		a.log.Error("list profiles", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	out := make([]gin.H, 0, len(profiles))
	for _, p := range profiles {
		var nodeCount, chainCount int64
		_ = a.db.WithContext(c.Request.Context()).Model(&store.ProfileNode{}).Where("profile_id = ?", p.ID).Count(&nodeCount).Error
		_ = a.db.WithContext(c.Request.Context()).Model(&store.ProfileChain{}).Where("profile_id = ?", p.ID).Count(&chainCount).Error
		var token store.SubscriptionToken
		var tokenDTO any
		err := a.db.WithContext(c.Request.Context()).Where("profile_id = ? AND revoked_at IS NULL", p.ID).Order("created_at DESC").First(&token).Error
		if err == nil {
			tokenDTO = a.tokenInfo(token)
		}
		out = append(out, gin.H{
			"id": p.ID, "name": p.Name, "description": p.Description,
			"node_count": nodeCount, "chain_count": chainCount,
			"template":          p.Template,
			"default_exit_type": p.DefaultExitType, "default_exit_id": p.DefaultExitID,
			"force_default_exit": p.ForceDefaultExit,
			"created_at":         p.CreatedAt, "updated_at": p.UpdatedAt,
			"token": tokenDTO,
		})
	}
	c.JSON(http.StatusOK, gin.H{"profiles": out})
}

func dedupeIDs(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (a *App) buildProfileBundle(c *gin.Context, input profileInput, profile store.Profile) (*profileBundle, error) {
	if err := mihomo.ValidateName(input.Name); err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}
	if len([]rune(input.Description)) > 1000 {
		return nil, fmt.Errorf("description must be at most 1000 characters")
	}
	if len(input.NodeIDs) > 1000 || len(input.ChainIDs) > 1000 || len(input.Groups) > 100 || len(input.Rules) > 500 {
		return nil, fmt.Errorf("profile contains too many entries")
	}
	nodeIDs := dedupeIDs(input.NodeIDs)
	chainIDs := dedupeIDs(input.ChainIDs)
	var nodes []store.Node
	if len(nodeIDs) > 0 {
		if err := a.db.WithContext(c.Request.Context()).Preload("Tags").Where("id IN ?", nodeIDs).Find(&nodes).Error; err != nil {
			return nil, err
		}
	}
	if len(nodes) != len(nodeIDs) {
		return nil, fmt.Errorf("one or more selected nodes do not exist")
	}
	var chains []store.Chain
	if len(chainIDs) > 0 {
		if err := a.db.WithContext(c.Request.Context()).Preload("EntryNode").Preload("ExitNode").Where("id IN ?", chainIDs).Find(&chains).Error; err != nil {
			return nil, err
		}
	}
	if len(chains) != len(chainIDs) {
		return nil, fmt.Errorf("one or more selected chains do not exist")
	}
	profile.Name = strings.TrimSpace(input.Name)
	profile.Description = input.Description
	profile.Template = strings.TrimSpace(input.Template)
	if profile.Template != "" && profile.Template != "acl4ssr" {
		return nil, fmt.Errorf("template must be empty or acl4ssr")
	}
	profile.DefaultExitType = input.DefaultExitType
	profile.DefaultExitID = input.DefaultExitID
	profile.ForceDefaultExit = input.ForceDefaultExit
	if profile.DefaultExitType != "" && profile.DefaultExitType != "node" && profile.DefaultExitType != "chain" {
		return nil, fmt.Errorf("default_exit_type must be empty, node or chain")
	}
	if profile.DefaultExitType == "" && profile.DefaultExitID != "" {
		return nil, fmt.Errorf("default_exit_id requires a type")
	}
	if profile.DefaultExitType == "node" && input.DefaultExitID == "" {
		return nil, fmt.Errorf("default_exit_id is required for a node default")
	}
	if profile.DefaultExitType == "chain" && input.DefaultExitID == "" {
		return nil, fmt.Errorf("default_exit_id is required for a chain default")
	}
	if profile.ForceDefaultExit && profile.DefaultExitType == "" {
		return nil, fmt.Errorf("force default exit requires a default exit")
	}

	groupsJSON, err := marshalJSONArray(input.Groups)
	if err != nil {
		return nil, err
	}
	rulesJSON, err := marshalJSONArray(input.Rules)
	if err != nil {
		return nil, err
	}
	dnsJSON, err := marshalJSONObject(input.DNS)
	if err != nil {
		return nil, err
	}
	generalJSON, err := marshalJSONObject(input.General)
	if err != nil {
		return nil, err
	}
	if len(groupsJSON)+len(rulesJSON)+len(dnsJSON)+len(generalJSON) > 512*1024 {
		return nil, fmt.Errorf("profile advanced configuration is too large")
	}
	profile.GroupsJSON = groupsJSON
	profile.RulesJSON = rulesJSON
	profile.DNSJSON = dnsJSON
	profile.GeneralJSON = generalJSON

	bundle, err := buildBundle(profile, nodes, chains)
	if err != nil {
		return nil, err
	}
	if _, err := mihomo.Generate(bundle.Spec); err != nil {
		return nil, err
	}
	return bundle, nil
}

func marshalJSONArray(v any) (string, error) {
	if v == nil {
		return "[]", nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("advanced configuration is not serializable")
	}
	return string(raw), nil
}

func marshalJSONObject(v map[string]any) (string, error) {
	if len(v) == 0 {
		return "{}", nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("advanced configuration is not serializable")
	}
	return string(raw), nil
}

func (a *App) createProfile(c *gin.Context) {
	var input profileInput
	if !bindJSON(c, &input) {
		return
	}
	now := time.Now().UTC()
	profile := store.Profile{ID: newUUID(), CreatedAt: now, UpdatedAt: now}
	bundle, err := a.buildProfileBundle(c, input, profile)
	if err != nil {
		writeError(c, http.StatusUnprocessableEntity, "invalid_profile", err.Error())
		return
	}
	profile = bundle.Profile
	err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&profile).Error; err != nil {
			return err
		}
		return saveProfileLinks(tx, profile.ID, bundle.NodeIDs, bundle.ChainIDs)
	})
	if err != nil {
		a.log.Error("create profile", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	dto, err := a.profileDetail(c, profile.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"profile": dto})
}

func saveProfileLinks(tx *gorm.DB, profileID string, nodeIDs, chainIDs []string) error {
	if err := tx.Where("profile_id = ?", profileID).Delete(&store.ProfileNode{}).Error; err != nil {
		return err
	}
	if err := tx.Where("profile_id = ?", profileID).Delete(&store.ProfileChain{}).Error; err != nil {
		return err
	}
	for _, id := range nodeIDs {
		if err := tx.Create(&store.ProfileNode{ProfileID: profileID, NodeID: id}).Error; err != nil {
			return err
		}
	}
	for _, id := range chainIDs {
		if err := tx.Create(&store.ProfileChain{ProfileID: profileID, ChainID: id}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (a *App) updateProfile(c *gin.Context) {
	var existing store.Profile
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", c.Param("id")).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "profile not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	var input profileInput
	if !bindJSON(c, &input) {
		return
	}
	existing.UpdatedAt = time.Now().UTC()
	bundle, err := a.buildProfileBundle(c, input, existing)
	if err != nil {
		writeError(c, http.StatusUnprocessableEntity, "invalid_profile", err.Error())
		return
	}
	updated := bundle.Profile
	err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.Profile{}).Where("id = ?", updated.ID).Updates(map[string]any{
			"name": updated.Name, "description": updated.Description, "template": updated.Template,
			"default_exit_type": updated.DefaultExitType, "default_exit_id": updated.DefaultExitID,
			"force_default_exit": updated.ForceDefaultExit,
			"groups_json":        updated.GroupsJSON, "rules_json": updated.RulesJSON,
			"dns_json": updated.DNSJSON, "general_json": updated.GeneralJSON,
			"updated_at": updated.UpdatedAt,
		}).Error; err != nil {
			return err
		}
		return saveProfileLinks(tx, updated.ID, bundle.NodeIDs, bundle.ChainIDs)
	})
	if err != nil {
		a.log.Error("update profile", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	dto, err := a.profileDetail(c, updated.ID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.JSON(http.StatusOK, gin.H{"profile": dto})
}

func (a *App) deleteProfile(c *gin.Context) {
	var profile store.Profile
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", c.Param("id")).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "profile not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	err := a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("profile_id = ?", profile.ID).Delete(&store.SubscriptionToken{}).Error; err != nil {
			return err
		}
		if err := tx.Where("profile_id = ?", profile.ID).Delete(&store.ProfileNode{}).Error; err != nil {
			return err
		}
		if err := tx.Where("profile_id = ?", profile.ID).Delete(&store.ProfileChain{}).Error; err != nil {
			return err
		}
		return tx.Delete(&store.Profile{}, "id = ?", profile.ID).Error
	})
	if err != nil {
		a.log.Error("delete profile", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.Status(http.StatusNoContent)
}

func (a *App) profileDetail(c *gin.Context, id string) (gin.H, error) {
	bundle, err := loadProfileByID(a.db.WithContext(c.Request.Context()), id)
	if err != nil {
		return nil, err
	}
	tokens := []store.SubscriptionToken{}
	if err := a.db.WithContext(c.Request.Context()).Where("profile_id = ?", id).Order("created_at DESC").Find(&tokens).Error; err != nil {
		return nil, err
	}
	nodeSummaries := make([]gin.H, 0, len(bundle.Nodes))
	for _, n := range bundle.Nodes {
		cfg, err := decodeConfig(n.Config)
		if err != nil {
			return nil, err
		}
		nodeSummaries = append(nodeSummaries, gin.H{
			"id": n.ID, "name": n.Name, "protocol": n.Protocol,
			"server": cfg.Server, "port": cfg.Port, "tags": tagValues(n.Tags),
		})
	}
	chainSummaries := make([]gin.H, 0, len(bundle.Chains))
	for _, ch := range bundle.Chains {
		chainSummaries = append(chainSummaries, gin.H{
			"id": ch.ID, "name": ch.Name, "enabled": ch.Enabled,
			"entry_node_id": ch.EntryNodeID, "exit_node_id": ch.ExitNodeID,
		})
	}
	p := bundle.Profile
	groups := bundle.Spec.Groups
	if groups == nil {
		groups = []mihomo.Group{}
	}
	rules := bundle.Spec.Rules
	if rules == nil {
		rules = []mihomo.Rule{}
	}
	dns := bundle.Spec.DNS
	if dns == nil {
		dns = map[string]any{}
	}
	general := bundle.Spec.General
	if general == nil {
		general = map[string]any{}
	}
	return gin.H{
		"id": p.ID, "name": p.Name, "description": p.Description,
		"node_ids": bundle.NodeIDs, "chain_ids": bundle.ChainIDs,
		"nodes": nodeSummaries, "chains": chainSummaries, "template": p.Template,
		"default_exit_type": p.DefaultExitType, "default_exit_id": p.DefaultExitID,
		"force_default_exit": p.ForceDefaultExit,
		"groups":             bundle.Spec.Groups, "rules": bundle.Spec.Rules,
		"dns": bundle.Spec.DNS, "general": bundle.Spec.General,
		"tokens":     a.tokenInfos(tokens),
		"created_at": p.CreatedAt, "updated_at": p.UpdatedAt,
	}, nil
}

func (a *App) getProfile(c *gin.Context) {
	dto, err := a.profileDetail(c, c.Param("id"))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "profile not found")
			return
		}
		a.log.Error("load profile", "profile_id", c.Param("id"), "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to load profile")
		return
	}
	c.JSON(http.StatusOK, gin.H{"profile": dto})
}

func (a *App) generateProfile(c *gin.Context) (*mihomo.Result, *store.Profile, bool) {
	bundle, err := loadProfileByID(a.db.WithContext(c.Request.Context()), c.Param("id"))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "profile not found")
			return nil, nil, false
		}
		a.log.Error("load profile", "profile_id", c.Param("id"), "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "failed to load profile")
		return nil, nil, false
	}
	result, err := mihomo.Generate(bundle.Spec)
	if err != nil {
		writeError(c, http.StatusUnprocessableEntity, "generation_failed", err.Error())
		return nil, nil, false
	}
	return result, &bundle.Profile, true
}

func etagMatches(headerValue, etag string) bool {
	for _, part := range strings.Split(headerValue, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || part == etag || strings.TrimPrefix(part, "W/") == etag {
			return true
		}
	}
	return false
}

func (a *App) previewProfile(c *gin.Context) {
	result, profile, ok := a.generateProfile(c)
	if !ok {
		return
	}
	if inm := c.GetHeader("If-None-Match"); inm != "" && etagMatches(inm, result.ETag) {
		c.Header("ETag", result.ETag)
		c.Status(http.StatusNotModified)
		return
	}
	c.Header("ETag", result.ETag)
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "application/yaml; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`inline; filename="%s.yaml"`, sanitizeFilename(profile.Name)))
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", result.YAML)
}

func (a *App) downloadProfile(c *gin.Context) {
	result, profile, ok := a.generateProfile(c)
	if !ok {
		return
	}
	if inm := c.GetHeader("If-None-Match"); inm != "" && etagMatches(inm, result.ETag) {
		c.Header("ETag", result.ETag)
		c.Status(http.StatusNotModified)
		return
	}
	c.Header("ETag", result.ETag)
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.yaml"`, sanitizeFilename(profile.Name)))
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", result.YAML)
}

func (a *App) listTokens(c *gin.Context) {
	var profile store.Profile
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", c.Param("id")).First(&profile).Error; err != nil {
		writeError(c, http.StatusNotFound, "not_found", "profile not found")
		return
	}
	tokens := []store.SubscriptionToken{}
	if err := a.db.WithContext(c.Request.Context()).Where("profile_id = ?", profile.ID).Order("created_at DESC").Find(&tokens).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": a.tokenInfos(tokens)})
}

func (a *App) createToken(c *gin.Context) {
	var profile store.Profile
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", c.Param("id")).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "profile not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	raw, err := security.RandomToken(32)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	now := time.Now().UTC()
	token := &store.SubscriptionToken{
		ID: newUUID(), ProfileID: profile.ID, TokenHash: security.HashToken(raw), Token: raw, CreatedAt: now,
	}
	err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.SubscriptionToken{}).
			Where("profile_id = ? AND revoked_at IS NULL", profile.ID).
			Updates(map[string]any{"revoked_at": now}).Error; err != nil {
			return err
		}
		return tx.Create(token).Error
	})
	if err != nil {
		a.log.Error("create subscription token", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	subscriptionURL, err := url.JoinPath(a.cfg.BaseURL, "s", raw)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"token": raw, "url": subscriptionURL, "xray_url": subscriptionURL + "?format=xray",
		"token_id": token.ID, "created_at": token.CreatedAt,
	})
}

func (a *App) revokeToken(c *gin.Context) {
	var token store.SubscriptionToken
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", c.Param("id")).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "subscription token not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if token.RevokedAt == nil {
		now := time.Now().UTC()
		if err := a.db.WithContext(c.Request.Context()).Model(&store.SubscriptionToken{}).
			Where("id = ?", token.ID).Update("revoked_at", now).Error; err != nil {
			writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
	}
	c.Status(http.StatusNoContent)
}
