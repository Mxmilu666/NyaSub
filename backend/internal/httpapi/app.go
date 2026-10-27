package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"nyasub/internal/config"
	"nyasub/internal/importers"
	"nyasub/internal/security"
	"nyasub/internal/store"
)

type App struct {
	cfg        *config.Config
	db         *gorm.DB
	log        *slog.Logger
	sessions   *security.SessionManager
	csrf       *security.CSRFManager
	loginRate  *security.Limiter
	userRate   *security.Limiter
	setupRate  *security.Limiter
	version    string
	dummyHash  string
	logLevel   *slog.LevelVar
	subFetcher subscriptionFetcher
}

func New(cfg *config.Config, db *gorm.DB, log *slog.Logger, version string, levelVar ...*slog.LevelVar) *App {
	// A valid hash used to equalise timing for unknown usernames.
	dummy, err := security.HashPassword("nyasub-dummy-password-never-used")
	if err != nil {
		panic(err)
	}
	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)
	if len(levelVar) > 0 && levelVar[0] != nil {
		level = levelVar[0]
	}
	return &App{
		cfg:        cfg,
		db:         db,
		log:        log,
		sessions:   security.NewSessionManager(db, cfg.SessionTTL),
		csrf:       security.NewCSRFManager(cfg.SessionSecret),
		loginRate:  security.NewLimiter(10, 5*time.Minute),
		userRate:   security.NewLimiter(5, 10*time.Minute),
		setupRate:  security.NewLimiter(8, 10*time.Minute),
		version:    version,
		dummyHash:  dummy,
		logLevel:   level,
		subFetcher: importers.NewSubscriptionFetcher(),
	}
}

func (a *App) Router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if err := r.SetTrustedProxies(a.cfg.TrustedProxies); err != nil {
		a.log.Error("invalid APP_TRUSTED_PROXIES; proxy trust disabled", "error", err)
		_ = r.SetTrustedProxies(nil)
	}
	r.Use(a.recoveryMiddleware())
	r.Use(a.requestLogger())
	r.Use(a.securityHeaders())
	r.Use(a.bodyLimit())
	r.Use(a.csrfMiddleware())

	r.GET("/healthz", a.health)
	r.GET("/api/health", a.health)
	r.GET("/s/:token", a.subscription)
	r.HEAD("/s/:token", a.subscription)

	api := r.Group("/api")
	api.GET("/auth/status", a.authStatus)
	api.GET("/auth/csrf", a.csrfToken)
	api.POST("/auth/setup", a.setup)
	api.POST("/auth/login", a.login)
	api.POST("/auth/logout", a.requireAuth(), a.logout)

	protected := api.Group("")
	protected.Use(a.requireAuth())
	{
		protected.GET("/auth/me", a.me)
		protected.PUT("/auth/password", a.changePassword)
		protected.GET("/auth/sessions", a.listSessions)
		protected.DELETE("/auth/sessions/:id", a.revokeSession)

		protected.GET("/dashboard", a.dashboard)
		protected.GET("/settings", a.settings)
		protected.PUT("/settings/log-level", a.setLogLevel)

		protected.GET("/nodes", a.listNodes)
		protected.POST("/nodes", a.createNode)
		protected.POST("/nodes/bulk-delete", a.bulkDeleteNodes)
		protected.POST("/nodes/import/preview", a.previewImport)
		protected.POST("/nodes/import", a.importNodes)
		protected.GET("/nodes/export", a.exportNodes)
		protected.GET("/nodes/tags", a.listTags)
		protected.DELETE("/nodes/tags", a.deleteTag)
		protected.GET("/nodes/:id", a.getNode)
		protected.PUT("/nodes/:id", a.updateNode)
		protected.DELETE("/nodes/:id", a.deleteNode)

		protected.GET("/chains", a.listChains)
		protected.POST("/chains", a.createChain)
		protected.GET("/chains/:id", a.getChain)
		protected.PUT("/chains/:id", a.updateChain)
		protected.DELETE("/chains/:id", a.deleteChain)

		protected.GET("/profiles", a.listProfiles)
		protected.POST("/profiles", a.createProfile)
		protected.GET("/profiles/:id", a.getProfile)
		protected.PUT("/profiles/:id", a.updateProfile)
		protected.DELETE("/profiles/:id", a.deleteProfile)
		protected.GET("/profiles/:id/preview", a.previewProfile)
		protected.GET("/profiles/:id/download", a.downloadProfile)
		protected.GET("/profiles/:id/tokens", a.listTokens)
		protected.POST("/profiles/:id/tokens", a.createToken)
		protected.DELETE("/subscription-tokens/:id", a.revokeToken)

		protected.GET("/backup", a.downloadBackup)
		protected.POST("/backup/restore", a.restoreBackup)
	}

	r.NoRoute(a.serveSPA)
	return r
}

func (a *App) recoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if rec := recover(); rec != nil {
				a.log.Error("panic while handling request", "path", redactPath(c.Request.URL.Path), "error", fmt.Sprint(rec))
				writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		c.Next()
	}
}

func (a *App) requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/healthz" || c.Request.URL.Path == "/api/health" {
			c.Next()
			return
		}
		start := time.Now()
		requestID, _ := security.RandomToken(9)
		c.Header("X-Request-ID", requestID)
		c.Next()
		a.log.Info("http request",
			"request_id", requestID,
			"method", c.Request.Method,
			"path", redactPath(c.Request.URL.Path),
			"status", c.Writer.Status(),
			"bytes", c.Writer.Size(),
			"duration_ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
			"user_agent", truncate(c.Request.UserAgent(), 160),
		)
	}
}

func redactPath(path string) string {
	if strings.HasPrefix(path, "/s/") {
		return "/s/[redacted]"
	}
	return path
}

func (a *App) securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if a.cfg.SecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		if !strings.HasPrefix(c.Request.URL.Path, "/_nuxt/") {
			h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		}
		c.Next()
	}
}

func (a *App) bodyLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := int64(4 << 20)
		if c.Request.URL.Path == "/api/backup/restore" {
			limit = 40 << 20
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

func (a *App) csrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}
		if origin := c.GetHeader("Origin"); origin != "" {
			if strings.TrimRight(origin, "/") != a.cfg.BaseURL {
				writeError(c, http.StatusForbidden, "csrf_failed", "request origin is not allowed")
				return
			}
		}
		cookieValue, err := c.Cookie(security.CSRFCookieName)
		headerValue := c.GetHeader("X-CSRF-Token")
		if err != nil || headerValue == "" || !a.csrf.VerifyPair(cookieValue, headerValue) {
			writeError(c, http.StatusForbidden, "csrf_failed", "missing or invalid CSRF token")
			return
		}
		c.Next()
	}
}

func (a *App) health(c *gin.Context) {
	sqlDB, err := a.db.DB()
	if err != nil || sqlDB.PingContext(c.Request.Context()) != nil {
		writeError(c, http.StatusServiceUnavailable, "unhealthy", "database is not reachable")
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": a.version})
}

// --- cookies ---------------------------------------------------------------

func (a *App) setSessionCookie(c *gin.Context, token string) {
	seconds := int(a.cfg.SessionTTL.Seconds())
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(security.SessionCookieName, token, seconds, "/", "", a.cfg.SecureCookies, true)
}

func (a *App) clearSessionCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(security.SessionCookieName, "", -1, "/", "", a.cfg.SecureCookies, true)
}

func (a *App) setCSRFCookie(c *gin.Context, token string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(security.CSRFCookieName, token, 24*60*60, "/", "", a.cfg.SecureCookies, false)
}

// --- auth context ----------------------------------------------------------

type ctxKey string

const (
	ctxUserKey    ctxKey = "user"
	ctxSessionKey ctxKey = "session"
)

func (a *App) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := c.Cookie(security.SessionCookieName)
		if err != nil || raw == "" {
			writeError(c, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		session, user, err := a.sessions.Validate(c.Request.Context(), raw)
		if err != nil {
			if !errors.Is(err, security.ErrSessionInvalid) {
				a.log.Error("session validation failed", "error", err)
			}
			a.clearSessionCookie(c)
			writeError(c, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		c.Set(string(ctxUserKey), user)
		c.Set(string(ctxSessionKey), session)
		c.Next()
	}
}

func currentUser(c *gin.Context) *store.User {
	v, ok := c.Get(string(ctxUserKey))
	if !ok {
		return nil
	}
	u, _ := v.(*store.User)
	return u
}

func currentSession(c *gin.Context) *store.Session {
	v, ok := c.Get(string(ctxSessionKey))
	if !ok {
		return nil
	}
	s, _ := v.(*store.Session)
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
