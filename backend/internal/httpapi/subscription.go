package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"nyasub/internal/mihomo"
	"nyasub/internal/security"
	"nyasub/internal/store"
)

func subscriptionETag(content []byte) string {
	sum := sha256.Sum256(content)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// subscription serves a profile using only its independent subscription token.
// It never accepts or reads the management session cookie.
func (a *App) subscription(c *gin.Context) {
	format := strings.ToLower(strings.TrimSpace(c.Query("format")))
	switch format {
	case "", "mihomo", "yaml":
		format = "mihomo"
	case "xray", "v2ray", "base64":
		format = "xray"
	default:
		c.String(http.StatusBadRequest, "unsupported subscription format")
		return
	}
	raw := c.Param("token")
	if len(raw) < 16 || len(raw) > 200 {
		c.String(http.StatusNotFound, "not found")
		return
	}
	var token store.SubscriptionToken
	err := a.db.WithContext(c.Request.Context()).
		Where("token_hash = ? AND revoked_at IS NULL", security.HashToken(raw)).
		First(&token).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			a.log.Error("lookup subscription token", "error", err)
		}
		c.String(http.StatusNotFound, "not found")
		return
	}
	var profile store.Profile
	if err := a.db.WithContext(c.Request.Context()).Where("id = ?", token.ProfileID).First(&profile).Error; err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	bundle, err := loadProfileBundle(a.db.WithContext(c.Request.Context()), profile)
	if err != nil {
		a.log.Error("load subscription profile", "profile_id", token.ProfileID, "error", err)
		c.String(http.StatusInternalServerError, "subscription configuration is unavailable")
		return
	}
	result, err := mihomo.Generate(bundle.Spec)
	if err != nil {
		a.log.Error("generate subscription", "profile_id", token.ProfileID, "error", err)
		c.String(http.StatusUnprocessableEntity, "subscription configuration is invalid")
		return
	}
	content := result.YAML
	etag := result.ETag
	contentType := "application/yaml; charset=utf-8"
	disposition := `inline; filename="NyaSub.yaml"`
	if format == "xray" {
		content, err = buildXraySubscription(bundle, result)
		if errors.Is(err, errNoXrayNodes) {
			c.String(http.StatusUnprocessableEntity, "profile has no Xray-compatible nodes")
			return
		}
		if err != nil {
			a.log.Error("generate xray subscription", "profile_id", token.ProfileID, "error", err)
			c.String(http.StatusUnprocessableEntity, "subscription configuration is invalid")
			return
		}
		etag = subscriptionETag(content)
		contentType = "text/plain; charset=utf-8"
		disposition = `inline; filename="NyaSub.txt"`
	}
	now := time.Now().UTC()
	if token.LastUsedAt == nil || now.Sub(*token.LastUsedAt) > time.Hour {
		_ = a.db.WithContext(c.Request.Context()).Model(&store.SubscriptionToken{}).
			Where("id = ?", token.ID).UpdateColumn("last_used_at", now).Error
	}
	c.Header("ETag", etag)
	c.Header("Cache-Control", "private, no-cache")
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", disposition)
	c.Header("X-Robots-Tag", "noindex, nofollow")
	c.Header("X-Content-Type-Options", "nosniff")
	if inm := c.GetHeader("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		c.Status(http.StatusNotModified)
		return
	}
	if c.Request.Method == http.MethodHead {
		c.Header("Content-Length", strconv.Itoa(len(content)))
		c.Status(http.StatusOK)
		return
	}
	c.Data(http.StatusOK, contentType, content)
}
