package mihomo

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateConfigRejectsDroppedFields(t *testing.T) {
	base := Config{Server: "a.example.com", Port: 443}
	vless := base
	vless.UUID = "11111111-1111-4111-8111-111111111111"
	vless.Cipher = "aes-256-gcm"
	require.Contains(t, ValidateConfig(ProtocolVLESS, vless).Error(), "cipher")

	ss := base
	ss.Cipher = "aes-256-gcm"
	ss.Password = "pw"
	ss.Network = "ws"
	require.Contains(t, ValidateConfig(ProtocolSS, ss).Error(), "network")

	hy2 := base
	hy2.Password = "pw"
	hy2.UDP = boolPtr(true)
	require.Error(t, ValidateConfig(ProtocolHysteria2, hy2))

	tuic := base
	tuic.UUID = "33333333-3333-4333-8333-333333333333"
	tuic.Password = "pw"
	tuic.Fingerprint = "chrome"
	require.NoError(t, ValidateConfig(ProtocolTUIC, tuic))
}

func TestNameValidationRejectsCommaAndControl(t *testing.T) {
	require.Error(t, ValidateName("US, West"))
	require.Error(t, ValidateName("line\nbreak"))
	require.NoError(t, ValidateName("日本 01"))
	require.True(t, strings.Contains(validateError(ValidateName("a,b")), "comma"))
}

func validateError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

const sampleVLESSEncryption = "mlkem768x25519plus.native.0rtt.1wZcnLa4tFbs8Hu210chlpE4xbn3qESjp67toIqe2Dg"
const invalidVLESSEncryption = "mlkem768x25519plus.native.0rtt.-phJ1ZNPr5oDHsjMLvks2AR_svkbeOCplqs5lUlQwed5rUoAg3KwuwbQlpOqb7InU8AgHnbHOlkzL6zJzdodzLgpojYT9SIBlJLIRsBJjzBw6spz-XFa6pKSgyEqRlFmJKqzD8detXVqmGEapakzD9NEhFcg6js5B4IDkYBJIXkBAOXC4XqLfLo3QiVuLJjOJfeunuM10mMkmaFB3-sIzQcVQDMGqyfOYQjIlGR3rtyZ41zDf_pcJZi_6ttpvRMwJwauFOK"

func TestVLESSEncryptionValidation(t *testing.T) {
	base := Config{Server: "a.example.com", Port: 443, UUID: "11111111-1111-4111-8111-111111111111"}
	for _, value := range []string{"", "none", sampleVLESSEncryption} {
		cfg := base
		cfg.Encryption = value
		require.NoError(t, ValidateConfig(ProtocolVLESS, cfg), value)
	}
	for _, value := range []string{
		"mlkem768x25519plus.bogus.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"mlkem768x25519plus.native.bogus.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"mlkem768x25519plus.native.0rtt",
		"other.native.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"mlkem768x25519plus.native.0rtt.100-111-1111",
		invalidVLESSEncryption,
	} {
		cfg := base
		cfg.Encryption = value
		require.Error(t, ValidateConfig(ProtocolVLESS, cfg), value)
	}
	vmess := base
	vmess.Encryption = sampleVLESSEncryption
	require.Contains(t, ValidateConfig(ProtocolVMess, vmess).Error(), "encryption")
}

func TestSSHValidation(t *testing.T) {
	base := Config{Server: "ssh.example.com", Port: 22, Username: "root", Password: "pw"}
	require.NoError(t, ValidateConfig(ProtocolSSH, base))

	keyOnly := base
	keyOnly.Password = ""
	keyOnly.PrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----"
	require.NoError(t, ValidateConfig(ProtocolSSH, keyOnly))

	noAuth := base
	noAuth.Password = ""
	require.Contains(t, ValidateConfig(ProtocolSSH, noAuth).Error(), "password or private key")
	noUser := base
	noUser.Username = ""
	require.Contains(t, ValidateConfig(ProtocolSSH, noUser).Error(), "username")

	tls := base
	tls.TLS = true
	require.Error(t, ValidateConfig(ProtocolSSH, tls))

	withHostKeys := base
	withHostKeys.HostKey = []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"}
	withHostKeys.HostKeyAlgorithms = []string{"ssh-ed25519"}
	require.NoError(t, ValidateConfig(ProtocolSSH, withHostKeys))
}

func TestCountryDetectionAndOverride(t *testing.T) {
	require.Equal(t, "🇬🇧", CountryFlag("BT-UK"))
	require.Equal(t, "🇯🇵", CountryFlag("XTOM-GEN2-JP"))
	require.Equal(t, "🇭🇰", CountryFlag("HK-01"))
	require.Equal(t, "🇹🇼", CountryFlag("TW-01"))
	require.Equal(t, "🇹🇼", CountryFlag("台湾-01"))
	require.Equal(t, "🇹🇼", CountryFlag("Taiwan-01"))
	require.Equal(t, "", CountryFlag("Same-01"))
	require.Equal(t, "", CountryFlag("🇯🇵 JP-01"))

	require.Equal(t, "🇬🇧 BT-UK", exportDisplayName("BT-UK", ""))
	require.Equal(t, "🇺🇸 JP-01", exportDisplayName("JP-01", "US"))
	require.Equal(t, "GB", NormalizeCountryTest(t, "uk"))
}

func NormalizeCountryTest(t *testing.T, value string) string {
	t.Helper()
	country, err := NormalizeCountry(value)
	require.NoError(t, err)
	return country
}
