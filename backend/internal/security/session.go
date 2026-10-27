package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"nyasub/internal/store"
)

const (
	SessionCookieName = "nyasub_session"
	CSRFCookieName    = "nyasub_csrf"
)

var ErrSessionInvalid = errors.New("session invalid or expired")

type SessionManager struct {
	db  *gorm.DB
	ttl time.Duration
}

func NewSessionManager(db *gorm.DB, ttl time.Duration) *SessionManager {
	return &SessionManager{db: db, ttl: ttl}
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func RandomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Create generates a cryptographically-random session token, stores only its
// SHA-256 hash and returns the plaintext token exactly once.
func (m *SessionManager) Create(ctx context.Context, userID, ip, userAgent string) (string, *store.Session, error) {
	raw, err := RandomToken(32)
	if err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	now := time.Now().UTC()
	session := &store.Session{
		ID:         uuid.NewString(),
		TokenHash:  HashToken(raw),
		UserID:     userID,
		ExpiresAt:  now.Add(m.ttl),
		LastSeenAt: now,
		CreatedAt:  now,
		IP:         ip,
		UserAgent:  truncate(userAgent, 255),
	}
	if err := m.db.WithContext(ctx).Create(session).Error; err != nil {
		return "", nil, fmt.Errorf("create session: %w", err)
	}
	return raw, session, nil
}

// Validate resolves a plaintext session token. Expired sessions are deleted and
// treated as invalid.
func (m *SessionManager) Validate(ctx context.Context, token string) (*store.Session, *store.User, error) {
	if token == "" || len(token) > 128 {
		return nil, nil, ErrSessionInvalid
	}
	var session store.Session
	err := m.db.WithContext(ctx).Preload("User").Where("token_hash = ?", HashToken(token)).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, nil, fmt.Errorf("lookup session: %w", err)
	}
	now := time.Now().UTC()
	if !session.ExpiresAt.After(now) {
		_ = m.db.WithContext(ctx).Delete(&store.Session{}, "id = ?", session.ID).Error
		return nil, nil, ErrSessionInvalid
	}
	if now.Sub(session.LastSeenAt) > 5*time.Minute {
		_ = m.db.WithContext(ctx).Model(&store.Session{}).Where("id = ?", session.ID).UpdateColumn("last_seen_at", now).Error
		session.LastSeenAt = now
	}
	return &session, &session.User, nil
}

func (m *SessionManager) Revoke(ctx context.Context, sessionID string) error {
	return m.db.WithContext(ctx).Delete(&store.Session{}, "id = ?", sessionID).Error
}

func (m *SessionManager) RevokeAllExcept(ctx context.Context, userID, keepSessionID string) error {
	q := m.db.WithContext(ctx).Where("user_id = ?", userID)
	if keepSessionID != "" {
		q = q.Where("id <> ?", keepSessionID)
	}
	return q.Delete(&store.Session{}).Error
}

func (m *SessionManager) List(ctx context.Context, userID string) ([]store.Session, error) {
	var sessions []store.Session
	err := m.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC()).
		Order("created_at DESC").Find(&sessions).Error
	return sessions, err
}

func (m *SessionManager) DeleteExpired(ctx context.Context) error {
	return m.db.WithContext(ctx).Delete(&store.Session{}, "expires_at <= ?", time.Now().UTC()).Error
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
