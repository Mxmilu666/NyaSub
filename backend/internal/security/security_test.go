package security

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestArgon2idHashAndVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)
	require.Contains(t, hash, "$argon2id$")
	ok, err := VerifyPassword(hash, "correct horse battery staple")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = VerifyPassword(hash, "wrong")
	require.NoError(t, err)
	require.False(t, ok)

	second, err := HashPassword("correct horse battery staple")
	require.NoError(t, err)
	require.NotEqual(t, hash, second, "salts must be random")
}

func TestCSRFManagerPair(t *testing.T) {
	manager := NewCSRFManager([]byte("0123456789abcdef0123456789abcdef"))
	token, err := manager.NewToken()
	require.NoError(t, err)
	require.True(t, manager.Verify(token))
	require.True(t, manager.VerifyPair(token, token))
	require.False(t, manager.VerifyPair(token, token+"x"))
	require.False(t, manager.Verify("not-a-token"))
}

func TestLimiter(t *testing.T) {
	limiter := NewLimiter(2, time.Minute)
	now := time.Now()
	limiter.now = func() time.Time { return now }
	require.False(t, func() bool { _, blocked := limiter.Blocked("k"); return blocked }())
	limiter.Failure("k")
	limiter.Failure("k")
	_, blocked := limiter.Blocked("k")
	require.True(t, blocked)
	now = now.Add(2 * time.Minute)
	_, blocked = limiter.Blocked("k")
	require.False(t, blocked)
}
