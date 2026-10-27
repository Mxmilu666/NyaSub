package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"nyasub/internal/importers"
	"nyasub/internal/mihomo"
	"nyasub/internal/store"
)

type nodeInput struct {
	Name     string          `json:"name"`
	Country  string          `json:"country"`
	Protocol string          `json:"protocol"`
	Tags     []string        `json:"tags"`
	Config   json.RawMessage `json:"config"`
}

const maxTagsPerNode = 16

func normalizeTags(tags []string) ([]string, error) {
	if len(tags) > maxTagsPerNode {
		return nil, fmt.Errorf("at most %d tags are allowed per node", maxTagsPerNode)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(tags))
	for _, raw := range tags {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			continue
		}
		if len([]rune(tag)) > 32 {
			return nil, fmt.Errorf("tag must be at most 32 characters")
		}
		if strings.ContainsAny(tag, "\r\n") {
			return nil, fmt.Errorf("tag must not contain line breaks")
		}
		key := strings.ToLower(tag)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, tag)
	}
	sort.Strings(out)
	return out, nil
}

func (a *App) listNodes(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	protocolFilter := strings.ToLower(strings.TrimSpace(c.Query("protocol")))
	tagFilter := strings.TrimSpace(c.Query("tag"))
	if len(q) > 100 || len(tagFilter) > 32 {
		writeError(c, http.StatusBadRequest, "invalid_filter", "filter is too long")
		return
	}
	var nodes []store.Node
	if err := a.db.WithContext(c.Request.Context()).Preload("Tags").Find(&nodes).Error; err != nil {
		a.log.Error("list nodes", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := strings.ToLower(nodes[i].Name), strings.ToLower(nodes[j].Name)
		if a != b {
			return a < b
		}
		return nodes[i].ID < nodes[j].ID
	})
	tagCounts := map[string]int{}
	for _, n := range nodes {
		for _, t := range n.Tags {
			tagCounts[t.Tag]++
		}
	}
	tagNames := make([]string, 0, len(tagCounts))
	for t := range tagCounts {
		tagNames = append(tagNames, t)
	}
	sort.Strings(tagNames)

	filtered := make([]store.Node, 0, len(nodes))
	for _, n := range nodes {
		if protocolFilter != "" && strings.ToLower(n.Protocol) != protocolFilter {
			continue
		}
		if tagFilter != "" {
			found := false
			for _, t := range n.Tags {
				if strings.EqualFold(t.Tag, tagFilter) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if q != "" {
			cfg, _ := decodeConfig(n.Config)
			haystack := strings.ToLower(n.Name + " " + n.Protocol + " " + cfg.Server)
			if !strings.Contains(haystack, strings.ToLower(q)) {
				continue
			}
		}
		filtered = append(filtered, n)
	}
	out := make([]gin.H, 0, len(filtered))
	for _, n := range filtered {
		dto, err := nodeResponse(n)
		if err != nil {
			a.log.Error("decode node", "node_id", n.ID, "error", err)
			writeError(c, http.StatusInternalServerError, "internal_error", "stored node configuration is invalid")
			return
		}
		out = append(out, dto)
	}
	c.JSON(http.StatusOK, gin.H{"nodes": out, "total": len(out), "tags": tagNames})
}

func (a *App) listTags(c *gin.Context) {
	var tags []store.NodeTag
	if err := a.db.WithContext(c.Request.Context()).Find(&tags).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	counts := map[string]int{}
	for _, t := range tags {
		counts[t.Tag]++
	}
	type tagCount struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	out := make([]tagCount, 0, len(counts))
	for name, count := range counts {
		out = append(out, tagCount{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	c.JSON(http.StatusOK, gin.H{"tags": out})
}

func (a *App) deleteTag(c *gin.Context) {
	tag := strings.TrimSpace(c.Query("tag"))
	if tag == "" || len([]rune(tag)) > 32 || strings.ContainsAny(tag, "\r\n") {
		writeError(c, http.StatusBadRequest, "invalid_tag", "invalid tag")
		return
	}
	result := a.db.WithContext(c.Request.Context()).Where("tag = ?", tag).Delete(&store.NodeTag{})
	if result.Error != nil {
		a.log.Error("delete tag", "error", result.Error)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.JSON(http.StatusOK, gin.H{"tag": tag, "deleted": result.RowsAffected})
}

func (a *App) getNode(c *gin.Context) {
	var node store.Node
	if err := a.db.WithContext(c.Request.Context()).Preload("Tags").Where("id = ?", c.Param("id")).First(&node).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "node not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	dto, err := nodeResponse(node)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "stored node configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, gin.H{"node": dto})
}

func (a *App) validateNodeInput(input *nodeInput) (mihomo.Config, []string, error) {
	var cfg mihomo.Config
	protocol := mihomo.Protocol(strings.ToLower(strings.TrimSpace(input.Protocol)))
	if !mihomo.ProtocolValid(protocol) {
		return cfg, nil, fmt.Errorf("unsupported protocol %q", input.Protocol)
	}
	if err := mihomo.ValidateName(input.Name); err != nil {
		return cfg, nil, fmt.Errorf("name: %w", err)
	}
	cfg, err := decodeConfigJSON(input.Config)
	if err != nil {
		return cfg, nil, err
	}
	if err := mihomo.ValidateConfig(protocol, cfg); err != nil {
		return cfg, nil, err
	}
	if raw, err := json.Marshal(cfg); err != nil || len(raw) > 128*1024 {
		return cfg, nil, fmt.Errorf("config is too large")
	}
	tags, err := normalizeTags(input.Tags)
	if err != nil {
		return cfg, nil, err
	}
	return cfg, tags, nil
}

func normalizeCountryInput(c *gin.Context, input string) (string, bool) {
	country, err := mihomo.NormalizeCountry(input)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_country", err.Error())
		return "", false
	}
	return country, true
}

func (a *App) createNode(c *gin.Context) {
	var input nodeInput
	if !bindJSON(c, &input) {
		return
	}
	cfg, tags, err := a.validateNodeInput(&input)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_node", err.Error())
		return
	}
	country, ok := normalizeCountryInput(c, input.Country)
	if !ok {
		return
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_node", "config is not serializable")
		return
	}
	now := time.Now().UTC()
	node := &store.Node{
		ID: newUUID(), Name: strings.TrimSpace(input.Name), Country: country,
		Protocol: strings.ToLower(input.Protocol), Config: string(raw), CreatedAt: now, UpdatedAt: now,
	}
	err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(node).Error; err != nil {
			return err
		}
		return setNodeTags(tx, node.ID, tags)
	})
	if err != nil {
		a.log.Error("create node", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	var created store.Node
	_ = a.db.WithContext(c.Request.Context()).Preload("Tags").Where("id = ?", node.ID).First(&created).Error
	dto, _ := nodeResponse(created)
	c.JSON(http.StatusCreated, gin.H{"node": dto})
}

func (a *App) updateNode(c *gin.Context) {
	var existing store.Node
	if err := a.db.WithContext(c.Request.Context()).Preload("Tags").Where("id = ?", c.Param("id")).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "node not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	var input nodeInput
	if !bindJSON(c, &input) {
		return
	}
	cfg, tags, err := a.validateNodeInput(&input)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_node", err.Error())
		return
	}
	country, ok := normalizeCountryInput(c, input.Country)
	if !ok {
		return
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_node", "config is not serializable")
		return
	}
	now := time.Now().UTC()
	err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.Node{}).Where("id = ?", existing.ID).Updates(map[string]any{
			"name": strings.TrimSpace(input.Name), "country": country,
			"protocol": strings.ToLower(input.Protocol), "config": string(raw), "updated_at": now,
		}).Error; err != nil {
			return err
		}
		return setNodeTags(tx, existing.ID, tags)
	})
	if err != nil {
		a.log.Error("update node", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	var updated store.Node
	_ = a.db.WithContext(c.Request.Context()).Preload("Tags").Where("id = ?", existing.ID).First(&updated).Error
	dto, _ := nodeResponse(updated)
	c.JSON(http.StatusOK, gin.H{"node": dto})
}

func setNodeTags(tx *gorm.DB, nodeID string, tags []string) error {
	if err := tx.Where("node_id = ?", nodeID).Delete(&store.NodeTag{}).Error; err != nil {
		return err
	}
	if len(tags) == 0 {
		return nil
	}
	rows := make([]store.NodeTag, 0, len(tags))
	for _, tag := range tags {
		rows = append(rows, store.NodeTag{NodeID: nodeID, Tag: tag})
	}
	return tx.Create(&rows).Error
}

type nodeDependencyDetails struct {
	Chains        []gin.H `json:"chains,omitempty"`
	Profiles      []gin.H `json:"profiles,omitempty"`
	EmptyProfiles []gin.H `json:"empty_profiles,omitempty"`
}

type deleteFailure struct {
	status  int
	code    string
	message string
	details any
}

// deleteNodeExec performs dependency checks and deletes the node. It returns
// nil on success or a structured failure without writing to the response.
func (a *App) deleteNodeExec(ctx context.Context, id string, force bool) *deleteFailure {
	var node store.Node
	if err := a.db.WithContext(ctx).Where("id = ?", id).First(&node).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &deleteFailure{http.StatusNotFound, "not_found", "node not found", nil}
		}
		a.log.Error("lookup node for delete", "error", err)
		return &deleteFailure{http.StatusInternalServerError, "internal_error", "internal server error", nil}
	}
	var chains []store.Chain
	if err := a.db.WithContext(ctx).Where("entry_node_id = ? OR exit_node_id = ?", id, id).Find(&chains).Error; err != nil {
		a.log.Error("check node chains", "error", err)
		return &deleteFailure{http.StatusInternalServerError, "internal_error", "internal server error", nil}
	}
	var profileLinks []store.ProfileNode
	if err := a.db.WithContext(ctx).Where("node_id = ?", id).Find(&profileLinks).Error; err != nil {
		a.log.Error("check node profiles", "error", err)
		return &deleteFailure{http.StatusInternalServerError, "internal_error", "internal server error", nil}
	}
	details := nodeDependencyDetails{}
	for _, ch := range chains {
		details.Chains = append(details.Chains, gin.H{"id": ch.ID, "name": ch.Name})
	}
	var profiles []store.Profile
	for _, link := range profileLinks {
		var p store.Profile
		if err := a.db.WithContext(ctx).Where("id = ?", link.ProfileID).First(&p).Error; err == nil {
			profiles = append(profiles, p)
			var count int64
			_ = a.db.WithContext(ctx).Model(&store.ProfileNode{}).Where("profile_id = ?", p.ID).Count(&count).Error
			if count <= 1 {
				details.EmptyProfiles = append(details.EmptyProfiles, gin.H{"id": p.ID, "name": p.Name})
			}
		}
	}
	for _, p := range profiles {
		details.Profiles = append(details.Profiles, gin.H{"id": p.ID, "name": p.Name})
	}
	if len(chains) > 0 {
		return &deleteFailure{http.StatusConflict, "node_in_use", "node is referenced by chains; delete or edit those chains first", details}
	}
	if len(profiles) > 0 && !force {
		return &deleteFailure{http.StatusConflict, "node_in_use", "node is enabled in profiles; confirm forced deletion to remove it from them", details}
	}
	if force && len(details.EmptyProfiles) > 0 {
		return &deleteFailure{http.StatusConflict, "profile_would_be_empty", "forced deletion would leave a profile without nodes", details}
	}
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(profiles) > 0 {
			if err := tx.Where("node_id = ?", id).Delete(&store.ProfileNode{}).Error; err != nil {
				return err
			}
			now := time.Now().UTC()
			for _, p := range profiles {
				if p.DefaultExitType == "node" && p.DefaultExitID == id {
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
		}
		if err := tx.Where("node_id = ?", id).Delete(&store.NodeTag{}).Error; err != nil {
			return err
		}
		return tx.Delete(&store.Node{}, "id = ?", id).Error
	})
	if err != nil {
		a.log.Error("delete node", "error", err)
		return &deleteFailure{http.StatusInternalServerError, "internal_error", "internal server error", nil}
	}
	return nil
}

func (a *App) deleteNode(c *gin.Context) {
	force := c.Query("force") == "true" || c.Query("force") == "1"
	if failure := a.deleteNodeExec(c.Request.Context(), c.Param("id"), force); failure != nil {
		if failure.details != nil {
			writeErrorDetails(c, failure.status, failure.code, failure.message, failure.details)
		} else {
			writeError(c, failure.status, failure.code, failure.message)
		}
		return
	}
	c.Status(http.StatusNoContent)
}

func (a *App) bulkDeleteNodes(c *gin.Context) {
	var input struct {
		IDs   []string `json:"ids"`
		Force bool     `json:"force"`
	}
	if !bindJSON(c, &input) {
		return
	}
	if len(input.IDs) == 0 || len(input.IDs) > 500 {
		writeError(c, http.StatusBadRequest, "invalid_request", "ids must contain between 1 and 500 node ids")
		return
	}
	deleted := make([]string, 0, len(input.IDs))
	type failure struct {
		ID      string `json:"id"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Details any    `json:"details,omitempty"`
	}
	failures := []failure{}
	seen := map[string]bool{}
	for _, id := range input.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		if f := a.deleteNodeExec(c.Request.Context(), id, input.Force); f != nil {
			failures = append(failures, failure{ID: id, Code: f.code, Message: f.message, Details: f.details})
			continue
		}
		deleted = append(deleted, id)
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted, "errors": failures})
}

// --- import ----------------------------------------------------------------

type importInput struct {
	Content string   `json:"content"`
	URL     string   `json:"url"`
	Format  string   `json:"format"`
	Tags    []string `json:"tags"`
}

type subscriptionFetcher interface {
	Fetch(ctx context.Context, rawURL string) (string, error)
}

func (a *App) resolveImportInput(c *gin.Context, input importInput) (importInput, bool) {
	rawURL := strings.TrimSpace(input.URL)
	if rawURL == "" {
		if strings.TrimSpace(input.Content) == "" {
			writeError(c, http.StatusBadRequest, "content_required", "content or url is required")
			return input, false
		}
		return input, true
	}
	if strings.TrimSpace(input.Content) != "" {
		writeError(c, http.StatusBadRequest, "invalid_import_source", "provide either content or url, not both")
		return input, false
	}
	content, err := a.subFetcher.Fetch(c.Request.Context(), rawURL)
	if err != nil {
		a.writeSubscriptionFetchError(c, err)
		return input, false
	}
	input.Content = content
	input.Format = "auto"
	return input, true
}

func (a *App) writeSubscriptionFetchError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, importers.ErrInvalidSubscriptionURL):
		writeError(c, http.StatusBadRequest, "invalid_subscription_url", "subscription URL is invalid")
	case errors.Is(err, importers.ErrBlockedSubscriptionTarget):
		writeError(c, http.StatusUnprocessableEntity, "subscription_target_blocked", err.Error())
	case errors.Is(err, importers.ErrSubscriptionTooLarge):
		writeError(c, http.StatusRequestEntityTooLarge, "subscription_too_large", err.Error())
	case errors.Is(err, importers.ErrEmptySubscription):
		writeError(c, http.StatusUnprocessableEntity, "empty_subscription", err.Error())
	default:
		a.log.Warn("subscription fetch failed", "error", err.Error())
		writeError(c, http.StatusBadGateway, "subscription_fetch_failed", err.Error())
	}
}

func (a *App) buildImportResult(c *gin.Context, input importInput, persist bool) (gin.H, bool) {
	var ok bool
	input, ok = a.resolveImportInput(c, input)
	if !ok {
		return nil, false
	}
	if len(input.Content) > importers.MaxContentBytes {
		writeError(c, http.StatusRequestEntityTooLarge, "content_too_large", "import content exceeds 1 MiB")
		return nil, false
	}
	tags, err := normalizeTags(input.Tags)
	if err != nil {
		writeError(c, http.StatusBadRequest, "invalid_tags", err.Error())
		return nil, false
	}
	parsed := importers.Parse(input.Content, input.Format)
	var allNodes []store.Node
	if err := a.db.WithContext(c.Request.Context()).Preload("Tags").Find(&allNodes).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil, false
	}
	existing := map[string]store.Node{}
	for _, n := range allNodes {
		cfg, err := decodeConfig(n.Config)
		if err != nil {
			continue
		}
		existing[fingerprint(n.Protocol, cfg)] = n
	}

	batchSeen := map[string]bool{}
	createdIDs := []string{}
	skipped := 0
	type previewItem struct {
		Name           string        `json:"name"`
		Protocol       string        `json:"protocol"`
		Config         mihomo.Config `json:"config"`
		Tags           []string      `json:"tags"`
		Source         string        `json:"source"`
		Line           int           `json:"line"`
		Warnings       []string      `json:"warnings,omitempty"`
		Duplicate      bool          `json:"duplicate"`
		ExistingNodeID string        `json:"existing_node_id,omitempty"`
		ExistingName   string        `json:"existing_name,omitempty"`
	}
	type prepared struct {
		item importers.Item
		tags []string
	}
	items := make([]previewItem, 0, len(parsed.Items))
	var toCreate []prepared
	for _, item := range parsed.Items {
		if err := mihomo.ValidateName(item.Name); err != nil {
			parsed.Issues = append(parsed.Issues, importers.Issue{Line: item.Line, Source: item.Source, Message: "name: " + err.Error()})
			continue
		}
		itemTags, err := normalizeTags(append(append([]string{}, tags...), item.Tags...))
		if err != nil {
			parsed.Issues = append(parsed.Issues, importers.Issue{Line: item.Line, Source: item.Source, Message: err.Error()})
			continue
		}
		if raw, err := json.Marshal(item.Config); err != nil || len(raw) > 128*1024 {
			parsed.Issues = append(parsed.Issues, importers.Issue{Line: item.Line, Source: item.Source, Message: "node config is too large"})
			continue
		}
		fp := fingerprint(string(item.Protocol), item.Config)
		pi := previewItem{
			Name: item.Name, Protocol: string(item.Protocol), Config: item.Config, Tags: itemTags,
			Source: item.Source, Line: item.Line, Warnings: item.Warnings,
		}
		if found, ok := existing[fp]; ok {
			pi.Duplicate = true
			pi.ExistingNodeID = found.ID
			pi.ExistingName = found.Name
			skipped++
		} else if batchSeen[fp] {
			pi.Duplicate = true
			pi.ExistingName = "(duplicate in import batch)"
			skipped++
		} else {
			batchSeen[fp] = true
			toCreate = append(toCreate, prepared{item: item, tags: itemTags})
		}
		items = append(items, pi)
	}
	if !persist {
		return gin.H{"items": items, "issues": parsed.Issues, "duplicate_count": skipped}, true
	}

	if len(toCreate) > 0 {
		now := time.Now().UTC()
		err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
			for _, p := range toCreate {
				raw, err := json.Marshal(p.item.Config)
				if err != nil {
					return err
				}
				id := newUUID()
				node := &store.Node{
					ID: id, Name: strings.TrimSpace(p.item.Name), Protocol: string(p.item.Protocol),
					Config: string(raw), CreatedAt: now, UpdatedAt: now,
				}
				if err := tx.Create(node).Error; err != nil {
					return err
				}
				if err := setNodeTags(tx, id, p.tags); err != nil {
					return err
				}
				createdIDs = append(createdIDs, id)
			}
			return nil
		})
		if err != nil {
			a.log.Error("persist imported nodes", "error", err)
			writeError(c, http.StatusInternalServerError, "internal_error", "failed to save imported nodes")
			return nil, false
		}
	}
	return gin.H{
		"created": len(createdIDs), "skipped": skipped, "node_ids": createdIDs,
		"items": items, "issues": parsed.Issues,
	}, true
}

func (a *App) previewImport(c *gin.Context) {
	var input importInput
	if !bindJSON(c, &input) {
		return
	}
	result, ok := a.buildImportResult(c, input, false)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, result)
}

func (a *App) importNodes(c *gin.Context) {
	var input importInput
	if !bindJSON(c, &input) {
		return
	}
	result, ok := a.buildImportResult(c, input, true)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, result)
}

func fingerprint(protocol string, cfg mihomo.Config) string {
	raw, _ := json.Marshal(cfg)
	sum := sha256.Sum256([]byte(strings.ToLower(protocol) + "|" + string(raw)))
	return hex.EncodeToString(sum[:])
}

func (a *App) exportNodes(c *gin.Context) {
	var nodes []store.Node
	if err := a.db.WithContext(c.Request.Context()).Preload("Tags").Find(&nodes).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	converted := make([]mihomo.Node, 0, len(nodes))
	for _, n := range nodes {
		mn, err := nodeToMihomo(n)
		if err != nil {
			writeError(c, http.StatusInternalServerError, "internal_error", "stored node configuration is invalid")
			return
		}
		converted = append(converted, mn)
	}
	out, err := mihomo.ExportProxiesYAML(converted)
	if err != nil {
		writeError(c, http.StatusUnprocessableEntity, "export_failed", err.Error())
		return
	}
	c.Header("Content-Type", "application/yaml; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="nyasub-nodes.yaml"`)
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", out)
}
