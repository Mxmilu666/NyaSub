package importers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxSubscriptionBytes is also the maximum size of a fetched response.
	MaxSubscriptionBytes = MaxContentBytes
	maxSubscriptionURL   = 4096
)

var (
	ErrInvalidSubscriptionURL    = errors.New("invalid subscription URL")
	ErrBlockedSubscriptionTarget = errors.New("subscription target must resolve to a public address")
	ErrSubscriptionTooLarge      = errors.New("subscription content exceeds 1 MiB")
	ErrSubscriptionFetch         = errors.New("failed to fetch subscription")
	ErrEmptySubscription         = errors.New("subscription response is empty")
)

// SubscriptionFetcher downloads a remote V2Ray or Mihomo subscription. It only
// connects to public HTTP(S) endpoints, including across redirects, so an
// authenticated administrator cannot turn the server into an SSRF proxy.
type SubscriptionFetcher struct {
	client *http.Client
}

func NewSubscriptionFetcher() *SubscriptionFetcher {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		// Do not honour HTTP(S)_PROXY: a proxy could bypass the address checks.
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialPublic(ctx, dialer, network, address)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           2,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &SubscriptionFetcher{
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("%w: too many redirects", ErrSubscriptionFetch)
				}
				if _, err := parseSubscriptionURL(req.URL.String()); err != nil {
					return err
				}
				return nil
			},
		},
	}
}

// Fetch downloads subscription content. The returned string is the raw body;
// Parse handles plain URI lists, Base64-encoded V2Ray lists and Mihomo YAML.
func (f *SubscriptionFetcher) Fetch(ctx context.Context, rawURL string) (string, error) {
	u, err := parseSubscriptionURL(rawURL)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", ErrInvalidSubscriptionURL
	}
	req.Header.Set("User-Agent", "NyaSub/1.0")
	req.Header.Set("Accept", "text/plain, application/yaml, application/x-yaml, */*;q=0.5")
	resp, err := f.client.Do(req)
	if err != nil {
		// http.Client wraps errors in *url.Error, whose message contains the
		// full request URL (and therefore any subscription token). Never pass
		// that through to API responses or logs.
		switch {
		case errors.Is(err, ErrInvalidSubscriptionURL):
			return "", ErrInvalidSubscriptionURL
		case errors.Is(err, ErrBlockedSubscriptionTarget):
			return "", ErrBlockedSubscriptionTarget
		default:
			return "", fmt.Errorf("%w: request failed", ErrSubscriptionFetch)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: upstream returned HTTP %d", ErrSubscriptionFetch, resp.StatusCode)
	}
	if resp.ContentLength > MaxSubscriptionBytes {
		return "", ErrSubscriptionTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSubscriptionBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: could not read response", ErrSubscriptionFetch)
	}
	if len(body) > MaxSubscriptionBytes {
		return "", ErrSubscriptionTooLarge
	}
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	if len(bytes.TrimSpace(body)) == 0 {
		return "", ErrEmptySubscription
	}
	return string(body), nil
}

func parseSubscriptionURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxSubscriptionURL {
		return nil, ErrInvalidSubscriptionURL
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, ErrInvalidSubscriptionURL
	}
	if u.User != nil {
		return nil, ErrInvalidSubscriptionURL
	}
	return u, nil
}

func dialPublic(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("%w: unsupported transport", ErrSubscriptionFetch)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid upstream address", ErrSubscriptionFetch)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: could not resolve upstream host", ErrSubscriptionFetch)
	}
	var lastErr error
	for _, addr := range ips {
		if !isPublicIP(addr.IP) {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: could not connect upstream", ErrSubscriptionFetch)
	}
	return nil, ErrBlockedSubscriptionTarget
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0,
			v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127,  // carrier-grade NAT
			v4[0] == 192 && v4[1] == 0 && v4[2] == 0,     // IETF protocol assignments
			v4[0] == 192 && v4[1] == 0 && v4[2] == 2,     // TEST-NET-1
			v4[0] == 198 && (v4[1] == 18 || v4[1] == 19), // benchmarking
			v4[0] == 198 && v4[1] == 51 && v4[2] == 100,  // TEST-NET-2
			v4[0] == 203 && v4[1] == 0 && v4[2] == 113,   // TEST-NET-3
			v4[0] >= 224: // multicast and reserved
			return false
		}
		return true
	}
	if len(ip) == net.IPv6len {
		if ip[0]&0xfe == 0xfc { // unique local fc00::/7
			return false
		}
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 { // 2001:db8::/32
			return false
		}
	}
	return true
}

// normalizeImportContent accepts both plain subscription bodies and the
// Base64-encoded URI lists served by most V2Ray panels.
func normalizeImportContent(content string) string {
	content = strings.TrimPrefix(content, "\ufeff")
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, content)
	if len(compact) < 16 {
		return content
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(compact)
		if err != nil || !utf8.Valid(decoded) {
			continue
		}
		text := strings.TrimSpace(strings.TrimPrefix(string(decoded), "\ufeff"))
		if looksLikeImportDocument(text) {
			return text
		}
	}
	return content
}

func looksLikeImportDocument(content string) bool {
	hasProxyFields := strings.Contains(content, "type:") && strings.Contains(content, "server:")
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "proxies:") ||
			strings.HasPrefix(line, "{") ||
			strings.HasPrefix(line, "[") {
			return true
		}
		if hasProxyFields && (strings.HasPrefix(line, "- ") ||
			strings.HasPrefix(lower, "type:") ||
			strings.HasPrefix(lower, "server:")) {
			return true
		}
		if scheme, _, ok := strings.Cut(line, "://"); ok {
			switch strings.ToLower(scheme) {
			case "vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic", "socks5", "socks", "http", "https":
				return true
			}
		}
	}
	return false
}
