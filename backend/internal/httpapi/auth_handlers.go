package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"nyasub/internal/security"
	"nyasub/internal/store"
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$`)

const (
	minPasswordLen = 10
	maxPasswordLen = 128
)

var errAlreadyInitialized = errors.New("initialized")

type credentialsInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) authStatus(c *gin.Context) {
	var count int64
	if err := a.db.WithContext(c.Request.Context()).Model(&store.User{}).Count(&count).Error; err != nil {
		a.log.Error("count users", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	c.JSON(http.StatusOK, gin.H{"initialized": count > 0})
}

func (a *App) csrfToken(c *gin.Context) {
	value, err := c.Cookie(security.CSRFCookieName)
	if err != nil || !a.csrf.Verify(value) {
		value, err = a.csrf.NewToken()
		if err != nil {
			writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
	}
	a.setCSRFCookie(c, value)
	c.JSON(http.StatusOK, gin.H{"csrf_token": value})
}

func (a *App) setup(c *gin.Context) {
	ip := c.ClientIP()
	if retry, blocked := a.setupRate.Blocked(ip); blocked {
		c.Header("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeError(c, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return
	}
	var input credentialsInput
	if !bindJSON(c, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if !usernameRe.MatchString(input.Username) {
		a.setupRate.Failure(ip)
		writeError(c, http.StatusBadRequest, "invalid_username", "username must be 3-32 characters using letters, digits, dot, dash or underscore")
		return
	}
	if err := validatePassword(input.Password); err != nil {
		a.setupRate.Failure(ip)
		writeError(c, http.StatusBadRequest, "weak_password", err.Error())
		return
	}

	var count int64
	if err := a.db.WithContext(c.Request.Context()).Model(&store.User{}).Count(&count).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if count > 0 {
		writeError(c, http.StatusConflict, "already_initialized", "administrator account already exists")
		return
	}

	hash, err := security.HashPassword(input.Password)
	if err != nil {
		a.log.Error("hash password", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	user := &store.User{
		ID:           newUUID(),
		Username:     input.Username,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	err = a.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		res := tx.Exec("INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING", "initialized", "1")
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return errAlreadyInitialized
		}
		var existing int64
		if err := tx.Model(&store.User{}).Count(&existing).Error; err != nil {
			return err
		}
		if existing > 0 {
			return errAlreadyInitialized
		}
		return tx.Create(user).Error
	})
	if errors.Is(err, errAlreadyInitialized) || isUniqueViolation(err) {
		writeError(c, http.StatusConflict, "already_initialized", "administrator account already exists")
		return
	}
	if err != nil {
		a.log.Error("create administrator", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	raw, session, err := a.sessions.Create(c.Request.Context(), user.ID, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		a.log.Error("create setup session", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "administrator created; please log in")
		return
	}
	a.setupRate.Reset(ip)
	a.setSessionCookie(c, raw)
	c.JSON(http.StatusCreated, gin.H{
		"user":    userDTO(user),
		"session": sessionDTO(session),
	})
}

func (a *App) login(c *gin.Context) {
	ip := c.ClientIP()
	if retry, blocked := a.loginRate.Blocked(ip); blocked {
		c.Header("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeError(c, http.StatusTooManyRequests, "rate_limited", "too many failed login attempts, try again later")
		return
	}
	var input credentialsInput
	if !bindJSON(c, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if input.Username == "" || len(input.Password) > maxPasswordLen {
		a.loginRate.Failure(ip)
		writeError(c, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	userKey := ip + "|" + strings.ToLower(input.Username)
	if retry, blocked := a.userRate.Blocked(userKey); blocked {
		c.Header("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeError(c, http.StatusTooManyRequests, "rate_limited", "too many failed login attempts, try again later")
		return
	}

	var count int64
	if err := a.db.WithContext(c.Request.Context()).Model(&store.User{}).Count(&count).Error; err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if count == 0 {
		writeError(c, http.StatusConflict, "not_initialized", "no administrator account has been created")
		return
	}

	var user store.User
	err := a.db.WithContext(c.Request.Context()).Where("username = ?", input.Username).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		_, _ = security.VerifyPassword(a.dummyHash, input.Password)
		a.loginRate.Failure(ip)
		a.userRate.Failure(userKey)
		writeError(c, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	if err != nil {
		a.log.Error("lookup user", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	ok, err := security.VerifyPassword(user.PasswordHash, input.Password)
	if err != nil {
		a.log.Error("verify password hash", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if !ok {
		a.loginRate.Failure(ip)
		a.userRate.Failure(userKey)
		writeError(c, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}

	raw, session, err := a.sessions.Create(c.Request.Context(), user.ID, ip, c.Request.UserAgent())
	if err != nil {
		a.log.Error("create login session", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	a.loginRate.Reset(ip)
	a.userRate.Reset(userKey)
	_ = a.sessions.DeleteExpired(c.Request.Context())
	a.setSessionCookie(c, raw)
	c.JSON(http.StatusOK, gin.H{
		"user":    userDTO(&user),
		"session": sessionDTO(session),
	})
}

func (a *App) logout(c *gin.Context) {
	session := currentSession(c)
	if session != nil {
		if err := a.sessions.Revoke(c.Request.Context(), session.ID); err != nil {
			a.log.Error("revoke session", "error", err)
		}
	}
	a.clearSessionCookie(c)
	c.Status(http.StatusNoContent)
}

func (a *App) me(c *gin.Context) {
	user := currentUser(c)
	session := currentSession(c)
	if user == nil || session == nil {
		writeError(c, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user":    userDTO(user),
		"session": sessionDTO(session),
	})
}

type changePasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (a *App) changePassword(c *gin.Context) {
	user := currentUser(c)
	session := currentSession(c)
	if user == nil || session == nil {
		writeError(c, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	var input changePasswordInput
	if !bindJSON(c, &input) {
		return
	}
	if err := validatePassword(input.NewPassword); err != nil {
		writeError(c, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	key := "password|" + user.ID
	if retry, blocked := a.userRate.Blocked(key); blocked {
		c.Header("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeError(c, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return
	}
	ok, err := security.VerifyPassword(user.PasswordHash, input.CurrentPassword)
	if err != nil || !ok {
		a.userRate.Failure(key)
		writeError(c, http.StatusBadRequest, "invalid_password", "current password is incorrect")
		return
	}
	if input.CurrentPassword == input.NewPassword {
		writeError(c, http.StatusBadRequest, "same_password", "new password must differ from the current password")
		return
	}
	hash, err := security.HashPassword(input.NewPassword)
	if err != nil {
		a.log.Error("hash new password", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	now := time.Now().UTC()
	if err := a.db.WithContext(c.Request.Context()).Model(&store.User{}).Where("id = ?", user.ID).
		Updates(map[string]any{"password_hash": hash, "updated_at": now}).Error; err != nil {
		a.log.Error("update password", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if err := a.sessions.RevokeAllExcept(c.Request.Context(), user.ID, session.ID); err != nil {
		a.log.Error("revoke other sessions", "error", err)
	}
	a.userRate.Reset(key)
	c.Status(http.StatusNoContent)
}

func (a *App) listSessions(c *gin.Context) {
	user := currentUser(c)
	current := currentSession(c)
	sessions, err := a.sessions.List(c.Request.Context(), user.ID)
	if err != nil {
		a.log.Error("list sessions", "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	out := make([]gin.H, 0, len(sessions))
	for i := range sessions {
		s := sessions[i]
		out = append(out, gin.H{
			"id":           s.ID,
			"created_at":   s.CreatedAt,
			"last_seen_at": s.LastSeenAt,
			"expires_at":   s.ExpiresAt,
			"ip":           s.IP,
			"user_agent":   s.UserAgent,
			"current":      current != nil && current.ID == s.ID,
		})
	}
	c.JSON(http.StatusOK, gin.H{"sessions": out})
}

func (a *App) revokeSession(c *gin.Context) {
	user := currentUser(c)
	current := currentSession(c)
	id := c.Param("id")
	var session store.Session
	if err := a.db.WithContext(c.Request.Context()).Where("id = ? AND user_id = ?", id, user.ID).First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(c, http.StatusNotFound, "not_found", "session not found")
			return
		}
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if err := a.sessions.Revoke(c.Request.Context(), session.ID); err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	if current != nil && current.ID == session.ID {
		a.clearSessionCookie(c)
	}
	c.Status(http.StatusNoContent)
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if len(password) > maxPasswordLen {
		return fmt.Errorf("password must be at most %d characters", maxPasswordLen)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password must not be blank")
	}
	return nil
}

func userDTO(u *store.User) gin.H {
	return gin.H{"id": u.ID, "username": u.Username, "created_at": u.CreatedAt}
}

func sessionDTO(s *store.Session) gin.H {
	return gin.H{"id": s.ID, "created_at": s.CreatedAt, "expires_at": s.ExpiresAt}
}
