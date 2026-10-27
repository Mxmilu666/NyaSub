package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"nyasub/internal/mihomo"
	"nyasub/internal/store"
)

type chainInput struct {
	Name        string `json:"name"`
	EntryNodeID string `json:"entry_node_id"`
	ExitNodeID  string `json:"exit_node_id"`
	Enabled     *bool  `json:"enabled"`
}

func chainWarnings(entry, exit mihomo.Node) []string {
	warnings := []string{}
	exitNeedsUDP := exit.Protocol == mihomo.ProtocolHysteria2 || exit.Protocol == mihomo.ProtocolTUIC ||
		(exit.Config.UDP != nil && *exit.Config.UDP)
	if exitNeedsUDP {
		switch entry.Protocol {
		case mihomo.ProtocolHTTP:
			warnings = append(warnings, "出口节点使用 UDP/QUIC，但 HTTP 入口代理无法转发 UDP，链式代理可能失败。")
		case mihomo.ProtocolHysteria2, mihomo.ProtocolTUIC:
			warnings = append(warnings, "通过基于 QUIC 的入口节点转发 UDP 依赖客户端支持，导入后请验证 UDP 是否可用。")
		}
		if entry.Config.UDP != nil && !*entry.Config.UDP && entry.Protocol != mihomo.ProtocolHTTP {
			warnings = append(warnings, "入口节点未启用 UDP，但出口节点需要 UDP。请为入口节点启用 UDP，否则 UDP 流量可能失败。")
		}
	}
	if entry.Protocol == mihomo.ProtocolHTTP && !entry.Config.TLS {
		warnings = append(warnings, "入口 HTTP 代理未加密，链式流量的隐私仅取决于第一跳。")
	}
	if entry.Protocol == mihomo.ProtocolSOCKS5 && !entry.Config.TLS {
		warnings = append(warnings, "入口 SOCKS5 代理未加密，链式流量的隐私仅取决于第一跳。")
	}
	if exit.Protocol == mihomo.ProtocolSS && exit.Config.Plugin != "" {
		warnings = append(warnings, "出口 Shadowsocks 使用了插件，链式代理的 UDP 支持可能受限。")
	}
	return warnings
}

func detectChainCycle(chains []store.Chain) error {
	graph := map[string][]string{}
	seen := map[string]bool{}
	for _, c := range chains {
		graph[c.EntryNodeID] = append(graph[c.EntryNodeID], c.ExitNodeID)
		seen[c.EntryNodeID] = true
		seen[c.ExitNodeID] = true
	}
	state := map[string]int{}
	var visit func(string) error
	visit = func(node string) error {
		switch state[node] {
		case 1:
			return fmt.Errorf("chain dependency cycle detected")
		case 2:
			return nil
		}
		state[node] = 1
		for _, next := range graph[node] {
			if err := visit(next); err != nil {
				return err
			}
		}
		state[node] = 2
		return nil
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) chainResponse(c *gin.Context, chain store.Chain) (gin.H, error) {
	entry, err := nodeToMihomo(chain.EntryNode)
	if err != nil {
		return nil, err
	}
	exit, err := nodeToMihomo(chain.ExitNode)
	if err != nil {
		return nil, err
	}
	var profileCount int64
	if err := a.db.WithContext(c.Request.Context()).Model(&store.ProfileChain{}).Where("chain_id = ?", chain.ID).Count(&profileCount).Error; err != nil {
		return nil, err
	}
	return gin.H{
		"id":      chain.ID,
		"name":    chain.Name,
		"enabled": chain.Enabled,
		"entry_node": gin.H{
			"id": chain.EntryNode.ID, "name": chain.EntryNode.Name,
			"protocol": chain.EntryNode.Protocol, "server": entry.Config.Server, "port": entry.Config.Port,
		},
		"exit_node": gin.H{
			"id": chain.ExitNode.ID, "name": chain.ExitNode.Name,
			"protocol": chain.ExitNode.Protocol, "server": exit.Config.Server, "port": exit.Config.Port,
		},
		"warnings":      chainWarnings(entry, exit),
		"profile_count": profileCount,
		"created_at":    chain.CreatedAt,
		"updated_at":    chain.UpdatedAt,
	}, nil
}

func (a *App) listChains(c *gin.Context) {
	var chains []store.Chain
	if err := a.db.WithContext(c.Request.Context()).Preload("EntryNode").Preload("ExitNode").Find(&chains).Error; err != nil {
		a.log.Error("list chains", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	sort.SliceStable(chains, func(i, j int) bool {
		a, b := strings.ToLower(chains[i].Name), strings.ToLower(chains[j].Name)
		if a != b {
			return a < b
		}
		return chains[i].ID < chains[j].ID
	})
	out := make([]gin.H, 0, len(chains))
	for _, ch := range chains {
		dto, err := a.chainResponse(c, ch)
		if err != nil {
			a.log.Error("decode chain", "chain_id", ch.ID, "error", err)
			writeError(c, http.StatusInternalServerError, "internal_error", "a stored chain references an invalid node")
			return
		}
		out = append(out, dto)
	}
	c.JSON(http.StatusOK, gin.H{"chains": out})
}

func (a *App) getChain(c *gin.Context) {
	var chain store.Chain
	if err := a.db.WithContext(c.Request.Context()).Preload("EntryNode").Preload("ExitNode").Where("id = ?", c.Param("id")).First(&chain).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "chain not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	dto, err := a.chainResponse(c, chain)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "a stored chain references an invalid node")
		return
	}
	c.JSON(http.StatusOK, gin.H{"chain": dto})
}

func (a *App) loadChainNodes(ctx context.Context, entryID, exitID string) (store.Node, store.Node, error) {
	var entry, exit store.Node
	if err := a.db.WithContext(ctx).Where("id = ?", entryID).First(&entry).Error; err != nil {
		return entry, exit, fmt.Errorf("entry node not found")
	}
	if err := a.db.WithContext(ctx).Where("id = ?", exitID).First(&exit).Error; err != nil {
		return entry, exit, fmt.Errorf("exit node not found")
	}
	return entry, exit, nil
}

func validateChainName(name string) error {
	return mihomo.ValidateName(name)
}

func chainNodeConfigs(entry, exit store.Node) (mihomo.Node, mihomo.Node, error) {
	me, err := nodeToMihomo(entry)
	if err != nil {
		return me, mihomo.Node{}, err
	}
	mx, err := nodeToMihomo(exit)
	if err != nil {
		return me, mx, err
	}
	if err := mihomo.ValidateConfig(me.Protocol, me.Config); err != nil {
		return me, mx, fmt.Errorf("entry node: %w", err)
	}
	if err := mihomo.ValidateConfig(mx.Protocol, mx.Config); err != nil {
		return me, mx, fmt.Errorf("exit node: %w", err)
	}
	return me, mx, nil
}

type profileRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func profilesUsingChain(db *gorm.DB, chainID, excludeProfile string) ([]store.Profile, error) {
	var links []store.ProfileChain
	if err := db.Where("chain_id = ?", chainID).Find(&links).Error; err != nil {
		return nil, err
	}
	profiles := []store.Profile{}
	for _, link := range links {
		if link.ProfileID == excludeProfile {
			continue
		}
		var p store.Profile
		if err := db.Where("id = ?", link.ProfileID).First(&p).Error; err == nil {
			profiles = append(profiles, p)
		}
	}
	return profiles, nil
}

func profileReferencesChain(p store.Profile, chainID string) bool {
	if p.DefaultExitType == "chain" && p.DefaultExitID == chainID {
		return true
	}
	ref := "chain:" + chainID
	var groups []mihomo.Group
	if err := json.Unmarshal([]byte(p.GroupsJSON), &groups); err == nil {
		for _, g := range groups {
			for _, proxy := range g.Proxies {
				if proxy == ref {
					return true
				}
			}
		}
	}
	var rules []mihomo.Rule
	if err := json.Unmarshal([]byte(p.RulesJSON), &rules); err == nil {
		for _, r := range rules {
			if r.Target == ref {
				return true
			}
		}
	}
	return false
}

func (a *App) createChain(c *gin.Context) {
	var input chainInput
	if !bindJSON(c, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if err := validateChainName(input.Name); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_chain", "name: "+err.Error())
		return
	}
	if input.EntryNodeID == "" || input.ExitNodeID == "" {
		writeError(c, http.StatusBadRequest, "invalid_chain", "entry_node_id and exit_node_id are required")
		return
	}
	if input.EntryNodeID == input.ExitNodeID {
		writeError(c, http.StatusBadRequest, "invalid_chain", "entry and exit nodes must differ")
		return
	}
	entry, exit, err := a.loadChainNodes(c.Request.Context(), input.EntryNodeID, input.ExitNodeID)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_chain", err.Error())
		return
	}
	me, mx, err := chainNodeConfigs(entry, exit)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_chain", err.Error())
		return
	}
	var all []store.Chain
	if err := a.db.WithContext(c.Request.Context()).Find(&all).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	candidate := store.Chain{ID: newUUID(), EntryNodeID: input.EntryNodeID, ExitNodeID: input.ExitNodeID}
	if err := detectChainCycle(append(all, candidate)); err != nil {
		writeError(c, http.StatusUnprocessableEntity, "chain_cycle", err.Error())
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	now := time.Now().UTC()
	chain := &store.Chain{
		ID: candidate.ID, Name: input.Name, EntryNodeID: input.EntryNodeID, ExitNodeID: input.ExitNodeID,
		Enabled: enabled, CreatedAt: now, UpdatedAt: now,
	}
	if err := a.db.WithContext(c.Request.Context()).Create(chain).Error; err != nil {
		a.log.Error("create chain", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	chain.EntryNode, chain.ExitNode = entry, exit
	dto, _ := a.chainResponse(c, *chain)
	c.JSON(http.StatusCreated, gin.H{"chain": dto, "warnings": chainWarnings(me, mx)})
}

func (a *App) updateChain(c *gin.Context) {
	var existing store.Chain
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", c.Param("id")).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "chain not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	var input chainInput
	if !bindJSON(c, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if err := validateChainName(input.Name); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_chain", "name: "+err.Error())
		return
	}
	if input.EntryNodeID == "" || input.ExitNodeID == "" {
		writeError(c, http.StatusBadRequest, "invalid_chain", "entry_node_id and exit_node_id are required")
		return
	}
	if input.EntryNodeID == input.ExitNodeID {
		writeError(c, http.StatusBadRequest, "invalid_chain", "entry and exit nodes must differ")
		return
	}
	entry, exit, err := a.loadChainNodes(c.Request.Context(), input.EntryNodeID, input.ExitNodeID)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_chain", err.Error())
		return
	}
	me, mx, err := chainNodeConfigs(entry, exit)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_chain", err.Error())
		return
	}
	var all []store.Chain
	if err := a.db.WithContext(c.Request.Context()).Find(&all).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	others := all[:0]
	for _, ch := range all {
		if ch.ID != existing.ID {
			others = append(others, ch)
		}
	}
	candidate := store.Chain{ID: existing.ID, EntryNodeID: input.EntryNodeID, ExitNodeID: input.ExitNodeID}
	if err := detectChainCycle(append(others, candidate)); err != nil {
		writeError(c, http.StatusUnprocessableEntity, "chain_cycle", err.Error())
		return
	}

	enabled := existing.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if !enabled {
		profiles, err := profilesUsingChain(a.db.WithContext(c.Request.Context()), existing.ID, "")
		if err != nil {
			writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		var refs []profileRef
		for _, p := range profiles {
			if profileReferencesChain(p, existing.ID) {
				refs = append(refs, profileRef{ID: p.ID, Name: p.Name})
			}
		}
		if len(refs) > 0 {
			writeErrorDetails(c, http.StatusConflict, "chain_in_use", "disable the chain after removing it from profile defaults, groups and rules", gin.H{"profiles": refs})
			return
		}
	}
	if input.EntryNodeID != existing.EntryNodeID {
		profiles, err := profilesUsingChain(a.db.WithContext(c.Request.Context()), existing.ID, "")
		if err != nil {
			writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		var missing []profileRef
		for _, p := range profiles {
			var count int64
			_ = a.db.WithContext(c.Request.Context()).Model(&store.ProfileNode{}).
				Where("profile_id = ? AND node_id = ?", p.ID, input.EntryNodeID).Count(&count).Error
			if count == 0 {
				missing = append(missing, profileRef{ID: p.ID, Name: p.Name})
			}
		}
		if len(missing) > 0 {
			writeErrorDetails(c, http.StatusConflict, "entry_not_enabled", "the new entry node is not enabled in every profile that uses this chain", gin.H{"profiles": missing})
			return
		}
	}
	now := time.Now().UTC()
	if err := a.db.WithContext(c.Request.Context()).Model(&store.Chain{}).Where("id = ?", existing.ID).Updates(map[string]any{
		"name": input.Name, "entry_node_id": input.EntryNodeID, "exit_node_id": input.ExitNodeID,
		"enabled": enabled, "updated_at": now,
	}).Error; err != nil {
		a.log.Error("update chain", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	existing.Name, existing.EntryNodeID, existing.ExitNodeID, existing.Enabled, existing.UpdatedAt = input.Name, input.EntryNodeID, input.ExitNodeID, enabled, now
	existing.EntryNode, existing.ExitNode = entry, exit
	dto, _ := a.chainResponse(c, existing)
	c.JSON(http.StatusOK, gin.H{"chain": dto, "warnings": chainWarnings(me, mx)})
}

func (a *App) deleteChain(c *gin.Context) {
	force := c.Query("force") == "true" || c.Query("force") == "1"
	var chain store.Chain
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", c.Param("id")).First(&chain).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "chain not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	profiles, err := profilesUsingChain(a.db.WithContext(c.Request.Context()), chain.ID, "")
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	var refs []profileRef
	for _, p := range profiles {
		if profileReferencesChain(p, chain.ID) {
			refs = append(refs, profileRef{ID: p.ID, Name: p.Name})
		}
	}
	if len(refs) > 0 {
		writeErrorDetails(c, http.StatusConflict, "chain_in_use", "chain is referenced by profile defaults, groups or rules; remove those references first", gin.H{"profiles": refs})
		return
	}
	if len(profiles) > 0 && !force {
		var selected []profileRef
		for _, p := range profiles {
			selected = append(selected, profileRef{ID: p.ID, Name: p.Name})
		}
		writeErrorDetails(c, http.StatusConflict, "chain_in_use", "chain is enabled in profiles; confirm forced deletion to remove it", gin.H{"profiles": selected})
		return
	}
	err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("chain_id = ?", chain.ID).Delete(&store.ProfileChain{}).Error; err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, p := range profiles {
			if p.DefaultExitType == "chain" && p.DefaultExitID == chain.ID {
				if err := tx.Model(&store.Profile{}).Where("id = ?", p.ID).Updates(map[string]any{
					"default_exit_type": "", "default_exit_id": "", "updated_at": now,
				}).Error; err != nil {
					return err
				}
			} else {
				if err := tx.Model(&store.Profile{}).Where("id = ?", p.ID).Update("updated_at", now).Error; err != nil {
					return err
				}
			}
		}
		return tx.Delete(&store.Chain{}, "id = ?", chain.ID).Error
	})
	if err != nil {
		a.log.Error("delete chain", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.Status(http.StatusNoContent)
}
