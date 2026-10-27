package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// CSRFManager implements a signed double-submit cookie. The cookie is readable
// by the SPA (not HttpOnly) while every unsafe request must send the same value
// in the X-CSRF-Token header. The signature prevents an attacker from minting a
// valid pair without server involvement.
type CSRFManager struct {
	secret []byte
}

func NewCSRFManager(secret []byte) *CSRFManager {
	return &CSRFManager{secret: secret}
}

func (m *CSRFManager) NewToken() (string, error) {
	token, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	return token + "." + m.sign(token), nil
}

func (m *CSRFManager) sign(token string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *CSRFManager) Verify(value string) bool {
	if len(value) < 40 || len(value) > 128 {
		return false
	}
	idx := strings.LastIndexByte(value, '.')
	if idx <= 0 || idx == len(value)-1 {
		return false
	}
	token, sig := value[:idx], value[idx+1:]
	return hmac.Equal([]byte(sig), []byte(m.sign(token)))
}

// VerifyPair checks the signed cookie against the submitted header and that
// both values are identical in constant time.
func (m *CSRFManager) VerifyPair(cookieValue, headerValue string) bool {
	if !m.Verify(cookieValue) || !m.Verify(headerValue) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieValue), []byte(headerValue)) == 1
}
