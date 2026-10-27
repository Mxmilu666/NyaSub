package httpapi

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nyasub/internal/store"
)

func (a *App) dashboard(c *gin.Context) {
	ctx := c.Request.Context()
	var nodes, chains, enabledChains, profiles, activeTokens int64
	if err := a.db.WithContext(ctx).Model(&store.Node{}).Count(&nodes).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if err := a.db.WithContext(ctx).Model(&store.Chain{}).Count(&chains).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if err := a.db.WithContext(ctx).Model(&store.Chain{}).Where("enabled = ?", true).Count(&enabledChains).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if err := a.db.WithContext(ctx).Model(&store.Profile{}).Count(&profiles).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if err := a.db.WithContext(ctx).Model(&store.SubscriptionToken{}).Where("revoked_at IS NULL").Count(&activeTokens).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	var recentProfiles []store.Profile
	var recentNodes []store.Node
	_ = a.db.WithContext(ctx).Order("updated_at DESC").Limit(5).Find(&recentProfiles).Error
	_ = a.db.WithContext(ctx).Order("updated_at DESC").Limit(5).Find(&recentNodes).Error
	type recentItem struct {
		Type      string    `json:"type"`
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	recent := make([]recentItem, 0, 10)
	for _, p := range recentProfiles {
		recent = append(recent, recentItem{Type: "profile", ID: p.ID, Name: p.Name, UpdatedAt: p.UpdatedAt})
	}
	for _, n := range recentNodes {
		recent = append(recent, recentItem{Type: "node", ID: n.ID, Name: n.Name, UpdatedAt: n.UpdatedAt})
	}
	sort.SliceStable(recent, func(i, j int) bool { return recent[i].UpdatedAt.After(recent[j].UpdatedAt) })
	if len(recent) > 8 {
		recent = recent[:8]
	}

	c.JSON(http.StatusOK, gin.H{
		"stats": gin.H{
			"nodes":          nodes,
			"chains":         chains,
			"enabled_chains": enabledChains,
			"profiles":       profiles,
			"active_tokens":  activeTokens,
		},
		"recent": recent,
	})
}

func (a *App) settings(c *gin.Context) {
	info, err := os.Stat(filepath.Join(a.cfg.WebDir, "index.html"))
	hasWeb := err == nil && !info.IsDir()
	c.JSON(http.StatusOK, gin.H{
		"version":           a.version,
		"base_url":          a.cfg.BaseURL,
		"listen":            a.cfg.Listen,
		"data_dir":          a.cfg.DataDir,
		"log_level":         a.cfg.LogLevelName,
		"secure_cookies":    a.cfg.SecureCookies,
		"session_ttl_hours": int(a.cfg.SessionTTL.Hours()),
		"web_ui":            hasWeb,
		"backup_format":     1,
	})
}

func (a *App) setLogLevel(c *gin.Context) {
	var input struct {
		Level string `json:"level"`
	}
	if !bindJSON(c, &input) {
		return
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(input.Level)))); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_log_level", "level must be debug, info, warn or error")
		return
	}
	a.logLevel.Set(level)
	a.cfg.LogLevel = level
	a.cfg.LogLevelName = strings.ToLower(input.Level)
	a.log.Info("log level changed", "level", a.cfg.LogLevelName)
	c.JSON(http.StatusOK, gin.H{"log_level": a.cfg.LogLevelName})
}

func (a *App) serveSPA(c *gin.Context) {
	path := c.Request.URL.Path
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		writeError(c, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	if strings.HasPrefix(path, "/s/") {
		c.String(http.StatusNotFound, "not found")
		return
	}
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.String(http.StatusNotFound, "not found")
		return
	}
	webDir, err := filepath.Abs(a.cfg.WebDir)
	if err != nil {
		c.String(http.StatusServiceUnavailable, "web UI is not available")
		return
	}
	clean := filepath.Clean("/" + path)
	rel := strings.TrimPrefix(clean, "/")
	full := filepath.Join(webDir, rel)
	absFull, err := filepath.Abs(full)
	if err != nil || (absFull != webDir && !strings.HasPrefix(absFull, webDir+string(os.PathSeparator))) {
		c.String(http.StatusNotFound, "not found")
		return
	}
	if info, err := os.Stat(absFull); err == nil && !info.IsDir() {
		a.serveStatic(c, absFull, path)
		return
	}
	if rel != "" && strings.Contains(filepath.Base(rel), ".") {
		c.String(http.StatusNotFound, "not found")
		return
	}
	index := filepath.Join(webDir, "index.html")
	if info, err := os.Stat(index); err != nil || info.IsDir() {
		c.String(http.StatusServiceUnavailable, "web UI is not built; run the Nuxt build or use the Docker image")
		return
	}
	a.serveStatic(c, index, "/")
}

func (a *App) serveStatic(c *gin.Context, file, requestPath string) {
	if strings.HasPrefix(requestPath, "/_nuxt/") {
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		c.Header("Cache-Control", "no-cache")
	}
	c.File(file)
}
