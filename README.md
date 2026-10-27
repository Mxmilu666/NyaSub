# NyaSub

NyaSub is a lightweight, self-hosted web application for managing Mihomo/Clash Meta proxy nodes, `dialer-proxy` chains, and deterministic subscription profiles.

It is **not** an airport panel, billing system, traffic monitor, or a proxy kernel controller. NyaSub does not run Mihomo, expose an External Controller, or manage devices. It stores your own node definitions and renders complete Mihomo YAML for clients such as Clash Party, Mihomo Party, and OpenClash to fetch on their own schedule.

Deployment guide: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

- **Backend:** Go, Gin, GORM, SQLite (WAL), `log/slog`, Argon2id, server-side sessions, CSRF protection.
- **Frontend:** Nuxt 4, Vue 3, strict TypeScript, Nuxt UI, Tailwind CSS, Lucide icons. SPA build served by the Go binary.
- **Deployment:** one container, `/data` volume, Docker Compose, health check, graceful shutdown, `linux/amd64` and `linux/arm64` builds.

## Features

- Independent administrator authentication with first-run setup.
- Argon2id password hashing; no default password.
- Cryptographically random server-side sessions. The database stores only SHA-256 session token hashes.
- `HttpOnly`, `SameSite=Lax`, and `Secure` (when `APP_BASE_URL` is HTTPS) cookies.
- CSRF signed double-submit protection, login/setup rate limiting, session expiry and revocation.
- Node CRUD, batch delete, copy, rename, tags, search, filters, and global tag cleanup.
- Country flags in exported node names are auto-detected from name tokens such as `HK-01` or `XTOM-GEN2-JP`; each node also has a manual country override.
- Import VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, SOCKS5, HTTP and SSH nodes.
- Import a Mihomo `proxies` array or the `proxies` section of a full Mihomo config.
- Import remote subscription URLs (V2Ray Base64 URI lists and Mihomo/Clash YAML) server-side.
- Import preview with per-line errors, duplicate detection, and confirmation before saving.
- Unsupported URI parameters and unsupported YAML fields return explicit errors instead of being silently dropped.
- Visual chain editor on the same Nodes page: entry node → exit node, route preview, warnings, enable/disable.
- Chains render with Mihomo `dialer-proxy`; no deprecated `relay` groups.
- Profile editor with selected nodes, chains, default exit, visual policy groups, visual rules, and advanced DNS/general YAML.
- Built-in ACL4SSR rule template (default for new profiles) with no external conversion service.
- Profiles generate stable, deterministic YAML with ETag support.
- Optional Xray/V2Ray share-link subscription (`?format=xray`) for clients that import Base64 URI lists.
- Fixed subscription URLs with independent random tokens. Tokens can be viewed at any time and rotated/revoked.
- Backup/restore, runtime log level, session management, and app version in Settings.

## Quick start

```bash
git clone <your-repository-url> nyasub
cd nyasub
cp .env.example .env
# Set APP_BASE_URL to the public https:// URL in production.
docker compose up -d --build
```

Open the URL from `APP_BASE_URL` (default `http://localhost:8080`) and create the administrator account. Setup can only run once.

```bash
docker compose logs -f
docker compose down
```

The SQLite database, WAL files, and a generated session secret persist in the `nyasub-data` volume mounted at `/data`.

### Published image

Every push to `main` and every `v*` tag publishes `linux/amd64` and `linux/arm64` images to GHCR:

```text
ghcr.io/<owner>/<repo>:latest
ghcr.io/<owner>/<repo>:sha-<commit>
ghcr.io/<owner>/<repo>:<version>
```

Use it with Compose by setting `NYASUB_IMAGE`, then start without a local build:

```bash
NYASUB_IMAGE=ghcr.io/<owner>/nyasub:latest docker compose up -d --no-build
```

The complete deployment guide covers reverse proxies, upgrades, backups, and private GHCR packages: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

### Multi-architecture image

Local build for both architectures:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t your-registry/nyasub:latest \
  --build-arg VERSION=1.0.0 \
  --push .
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `APP_LISTEN` | `127.0.0.1:8080` | HTTP listen address. The Compose file sets `0.0.0.0:8080` inside the container. |
| `APP_BASE_URL` | `http://localhost:8080` | Public origin used for subscription URLs, cookies, and origin checks. Must be an absolute HTTP(S) URL with no path. |
| `APP_DATA_DIR` | `./data` | Directory containing `nyasub.db`, WAL files, and the generated session secret. Docker uses `/data`. |
| `APP_SESSION_SECRET` | generated | Optional. At least 32 characters. When empty, a random secret is created once and stored in `APP_DATA_DIR/session_secret`. |
| `APP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. Also adjustable at runtime in Settings (resets on restart). |
| `TZ` | system | Container timezone, for example `Europe/Berlin`. |
| `APP_WEB_DIR` | `./web` | Built frontend directory. The Docker image sets `/app/web`. |
| `APP_COOKIE_SECURE` | derived | Optional boolean override. By default cookies are `Secure` when `APP_BASE_URL` is HTTPS. |
| `APP_TRUSTED_PROXIES` | empty | Optional comma-separated proxy IPs/CIDRs. Set this when running behind a reverse proxy so client IPs and rate limiting work correctly. |
| `NYASUB_VERSION` | `dev` | Compose build argument baked into the binary and shown in Settings. Not read by the server at runtime. |
| `NYASUB_IMAGE` | `nyasub:latest` | Compose image name. Set to `ghcr.io/<owner>/<repo>:latest` to run the published image. |

### HTTPS and reverse proxies

NyaSub must be published over HTTPS in production. The app itself serves HTTP; terminate TLS at Caddy, Nginx, Traefik, or another reverse proxy.

**Caddy**

```caddyfile
nyasub.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**Nginx**

```nginx
server {
    listen 443 ssl http2;
    server_name nyasub.example.com;

    # ssl_certificate ...;
    # ssl_certificate_key ...;
    client_max_body_size 44m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

Set both `APP_BASE_URL=https://nyasub.example.com` and, if the proxy is not on loopback, `APP_TRUSTED_PROXIES` to the proxy address. In production, publish the container port only on loopback (`127.0.0.1:8080:8080`) or restrict it with a firewall; the default Compose mapping exposes it on all host interfaces.

The `Secure` cookie attribute is derived from `APP_BASE_URL`; setting the public HTTPS URL is required. The app deliberately does not trust arbitrary `X-Forwarded-Proto` headers by default.

## Subscriptions and tokens

Each profile has one active subscription token at a time:

```text
GET /s/{token}
Content-Type: application/yaml; charset=utf-8
```

- Tokens are generated with 32 cryptographically random bytes (base64url).
- The database stores the token value for display and a SHA-256 hash for lookup. The subscription URL can be opened again at any time.
- Rotating a token invalidates the previous URL immediately; the new URL remains viewable.
- Revoking a token stops the URL without deleting the profile.
- Subscription access is completely separate from the administrator session. A management cookie cannot authenticate a subscription and vice versa.
- The subscription handler ignores management credentials and does not set cookies.
- Subscription paths are redacted from request logs (`/s/[redacted]`).
- Subscription responses use `Content-Disposition: inline; filename="NyaSub.yaml"`, so clients display the profile as `NyaSub` rather than the internal profile name.
- Responses include an ETag and honor `If-None-Match`; deterministic output means an unchanged profile returns the same ETag.

Subscription tokens are sensitive credentials: anyone with a URL can download the generated configuration. Treat the database and backups as secrets. Tokens created before the plaintext-display migration do not have a stored value; rotate such a token once to make it viewable.

### Xray / V2Ray share-link subscription

Append `?format=xray` to the same token URL:

```text
GET /s/{token}?format=xray
Content-Type: text/plain; charset=utf-8
Content-Disposition: inline; filename="NyaSub.txt"
```

The body is standard Base64 encoding of newline-separated share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `socks5://`, `http://`/`https://`), so Xray/V2Ray-compatible clients such as v2rayNG can import it as a normal subscription. `format=v2ray` and `format=base64` are aliases.

- Only the profile's selected original nodes are exported.
- Hysteria2 is supported in its standard URI form, including `obfs`, `obfs-password`, `mport`, `up`/`down`, `pinSHA256`, SNI and ALPN.
- TUIC and SSH are omitted because v2rayNG/Xray-compatible share links do not cover them.
- Mihomo chain proxies use `dialer-proxy`; they cannot be represented by a single share link and are not included. Use the default YAML subscription for chains.
- If the profile contains no Xray-compatible nodes, the endpoint returns `422` instead of an empty subscription.
- The Xray response has its own ETag and also supports conditional requests.

The profile token dialog shows both the Mihomo YAML link and the Xray/V2Ray link.

### ACL4SSR rule template

New profiles default to the built-in ACL4SSR template. It is generated by NyaSub itself; no Subconverter service or converted-link round trip is involved. The template is based on `ACL4SSR_Online.ini` and includes:

- ACL4SSR proxy groups such as `🚀 节点选择`, `♻️ 自动选择`, `🎯 全球直连`, and `🐟 漏网之鱼`
- `rule-providers` pointing at the ACL4SSR rule lists (clients fetch and cache them)
- ACL4SSR rule order, including `GEOIP,CN` and the final `MATCH` rule
- All selected nodes and `dialer-proxy` chain exports, matched into the ACL4SSR groups
- Original nodes tagged `落地机` are excluded from `🚀 节点选择` and `♻️ 自动选择` by default; chain copies remain selectable

Switch a profile to `自定义策略组与规则` to use the visual group/rule editor. In ACL4SSR mode, custom groups, custom rules, and the profile default exit are stored but ignored during generation.

### Default exit and client compatibility

Profiles support a default exit node or chain, with two modes:

1. **Soft default** — the default export is placed first in a selectable group and routed through that group. This is convenient when clients honor the imported group order.
2. **Force default exit** — the final rule is written directly as `MATCH,<exported-proxy-name>` and `mode` is forced to `rule`. No selectable group sits between the rule and the proxy, so a client’s persisted group selection cannot change the final route.

Client-side limitations that NyaSub cannot remove:

- Mihomo clients may persist a policy-group choice via `profile.store-selected` or their own settings. Soft defaults can therefore be overridden in clients that restore old group selections.
- A client running in **Global** mode (or with rules disabled) bypasses `MATCH`. This is a client behavior, not a configuration generation bug.
- Other rules placed before `MATCH` intentionally route specific traffic elsewhere. The forced default only governs traffic that reaches the final `MATCH`.

For deterministic behavior, use force default exit and keep client mode set to `rule`.

## Chains and dependency safety

A chain is `entry node → exit node`. NyaSub keeps the entry node as-is and appends a renamed copy of the exit node with:

```yaml
dialer-proxy: "<entry exported name>"
```

- References use immutable internal UUIDs, never display names.
- The original exit node remains available for other chains and profiles.
- The chain exit gets a unique export name with a direction prefix such as `🇭🇰 → 🇺🇸 HK-01 → US-02`.
- Node name collisions are resolved deterministically with suffixes like `Same (2)`.
- `dialer-proxy` references are updated to the allocated entry name.
- Chain cycles and self-chains are rejected.
- Deleting a node referenced by a chain is blocked. Delete or edit the chain first.
- Deleting a chain referenced by a profile default/group/rule is blocked until those references are removed. A force delete can remove a chain that is merely selected in profiles.
- Deleting a node selected in profiles requires explicit force and is rejected if it would leave a profile with no nodes.

## Supported protocols

| NyaSub protocol | Mihomo proxy `type` | Main fields |
|---|---|---|
| VLESS | `vless` | UUID, flow, VLESS encryption, TLS, SNI, ALPN, REALITY, WS/gRPC/HTTP/H2, UDP |
| VMess | `vmess` | UUID, alter ID, cipher, TLS, SNI, ALPN, WS/gRPC/HTTP/H2, UDP |
| Trojan | `trojan` | password, SNI, ALPN, WS/gRPC, UDP |
| Shadowsocks | `ss` | cipher, password, UDP, UDP-over-TCP/version, plugin/plugin opts |
| Hysteria2 | `hysteria2` | password, SNI, ALPN, obfs, up/down, ports, hop interval, fingerprint |
| TUIC | `tuic` | UUID, password, SNI, ALPN, congestion controller, UDP relay mode, reduce RTT |
| SOCKS5 | `socks5` | username, password, TLS, SNI, UDP |
| HTTP | `http` | username, password, TLS, SNI, headers |
| SSH | `ssh` | username, password/private key, private-key passphrase, host key, host-key algorithms |

NyaSub generates Mihomo YAML, so it can only emit protocols that Mihomo can run as outbound proxies. Xray-only outbound types such as `freedom`, `blackhole`, `dokodemo-door`, `loopback` and `dns` are not proxy nodes and are outside the supported set. The optional Xray/V2Ray share-link subscription exports `vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `socks5` and `http` nodes; TUIC and SSH have no compatible share link in v2rayNG/Xray.

Protocol configuration is stored as a validated JSON object. First-class fields cover the common Mihomo parameters; additional Mihomo-supported fields (`tfo`, `mptcp`, `smux`, `packet-encoding`, and so on) are preserved in an explicit extra-fields map. The UI exposes advanced extras as JSON. Unknown or incompatible fields are rejected, never silently discarded.

Node display names and exported proxy names get a flag emoji when the name contains a country code token such as `UK`, `JP`, `HK` or `US`. Automatic detection uses the last recognized token; a node can override it with an explicit ISO alpha-2 `country` value. The stored node name itself is not modified.

VLESS `encryption` values (including `mlkem768x25519plus`) are preserved in share links and Mihomo YAML. NyaSub validates the mode and key encoding, and requires key material that Mihomo accepts (32-byte X25519 or 1184-byte ML-KEM-768). Truncated or incompatible encryption strings fail with a specific error instead of producing a subscription Mihomo cannot load.

### Import formats

- `vless://`
- `vmess://` (base64 JSON)
- `trojan://`
- `ss://` (SIP002 and legacy base64 forms, plugin parameters)
- `hysteria2://` and `hy2://`
- `tuic://`
- `socks5://`
- `http://` / `https://`
- Mihomo YAML: a top-level `proxies` array, a full config containing `proxies`, a single proxy mapping, or an array of proxies
- Base64-encoded V2Ray subscription content (standard or URL-safe Base64, with or without line wrapping)
- Remote subscription URL: `POST /api/nodes/import` and `/api/nodes/import/preview` accept `{"url":"https://..."}`. NyaSub fetches the URL server-side and auto-detects a Base64 V2Ray list or a Mihomo/Clash YAML response.

Import limits: 1 MiB of content or fetched response, 500 nodes, YAML depth/node count limits, and aliases/anchors are rejected to prevent YAML expansion attacks. Preview reports each bad line while valid items can still be imported.

## Security model

- First-run setup is atomic: a unique settings marker is inserted inside a transaction, so concurrent setup requests cannot both succeed.
- No default administrator account or password.
- Argon2id with a per-password salt (64 MiB, t=3, p=2 by default).
- Session tokens are random 256-bit values; only their SHA-256 hashes are stored.
- Session cookies are `HttpOnly`, `SameSite=Lax`, path `/`, and `Secure` when the public URL is HTTPS.
- CSRF uses a signed double-submit cookie; unsafe API requests require the `X-CSRF-Token` header. Origin is checked when present.
- Login and setup attempts are rate limited in memory.
- All management endpoints require a valid session. Only setup, login, CSRF bootstrap, auth status, and health are public.
- Subscription handlers use independent tokens and never read the management cookie.
- SQLite foreign keys are enabled; deletion paths check dependents before modifying data.
- Request logs omit query strings, redact `/s/*`, and never log node credentials or token plaintext. Configure your reverse proxy to mask `/s/*` in its own access logs as well; NyaSub cannot control proxy logs.
- The CSP is restrictive except for `script-src 'unsafe-inline'`, which is required by Nuxt's static SPA bootstrap. Vue escapes all rendered values, no user-controlled HTML is rendered, and no `v-html` is used.
- Node, chain, group and profile names cannot contain commas because Mihomo rule targets are comma-delimited. Other Unicode names are supported. `APP_BASE_URL` must match the exact browser origin (including port and http/https); origin checks reject mismatches.
- The API rejects unknown JSON fields and bodies over the configured limit.
- Remote subscription fetching only permits public HTTP(S) targets. Loopback, private, link-local, CGNAT, documentation, multicast and reserved addresses are rejected, redirect chains are capped, and connections are made to the validated IP to prevent DNS rebinding. Fetching never uses environment HTTP proxies.
- Static file serving resolves paths beneath `APP_WEB_DIR` and rejects traversal.
- Backup files contain password hashes and subscription token values. Treat them as secrets; store them encrypted and offline.

## API overview

All management routes are under `/api` and require a session (except setup, login, CSRF, and auth status). Errors use:

```json
{ "error": { "code": "invalid_node", "message": "...", "details": {} } }
```

| Method | Route |
|---|---|
| `POST` | `/api/auth/setup` |
| `POST` | `/api/auth/login` |
| `POST` | `/api/auth/logout` |
| `GET` | `/api/auth/me` |
| `PUT` | `/api/auth/password` |
| `GET` | `/api/auth/status` |
| `GET` | `/api/auth/csrf` |
| `GET`/`DELETE` | `/api/auth/sessions`, `/api/auth/sessions/:id` |
| `GET`/`POST` | `/api/nodes` |
| `GET`/`PUT`/`DELETE` | `/api/nodes/:id` |
| `POST` | `/api/nodes/import`, `/api/nodes/import/preview` (accepts `content` or a remote `url`), `/api/nodes/bulk-delete` |
| `GET`/`DELETE` | `/api/nodes/export`, `/api/nodes/tags` (DELETE uses `?tag=`) |
| `GET`/`POST` | `/api/chains` |
| `GET`/`PUT`/`DELETE` | `/api/chains/:id` |
| `GET`/`POST` | `/api/profiles` |
| `GET`/`PUT`/`DELETE` | `/api/profiles/:id` |
| `GET` | `/api/profiles/:id/preview`, `/api/profiles/:id/download` |
| `GET`/`POST` | `/api/profiles/:id/tokens` |
| `DELETE` | `/api/subscription-tokens/:id` |
| `GET` | `/s/:token` (public Mihomo YAML subscription) |
| `GET` | `/s/:token?format=xray` (public Xray/V2Ray Base64 share-link subscription) |
| `GET` | `/healthz` (public health check) |
| `GET`/`POST` | `/api/backup`, `/api/backup/restore` |
| `PUT` | `/api/settings/log-level` |

## Local development

Backend:

```bash
cd backend
go run ./cmd/nyasub
```

Frontend (Nuxt dev server proxies `/api` and `/s` to `127.0.0.1:8080`):

```bash
cd web
npm install
npm run dev
```

For local development, set:

```bash
APP_LISTEN=127.0.0.1:8080
APP_BASE_URL=http://localhost:3000
APP_DATA_DIR=./backend/data
APP_WEB_DIR=./web/.output/public
```

`APP_BASE_URL` must match the browser origin used to access the UI, because Origin checks protect unsafe requests.

## Tests and checks

```bash
cd backend
go test ./...
go vet ./...

cd ../web
npm run typecheck
npm run generate
```

Or run everything, including the frontend typecheck and production build:

```bash
./scripts/check.sh
```

Backend tests cover:

1. Administrator setup and duplicate setup (including concurrent setup).
2. Login, logout, session expiry and password-change session revocation.
3. Unauthenticated management access and CSRF failures.
4. Share-link parsing for all supported protocols.
5. Mihomo YAML import and explicit unsupported-field errors.
6. Node name collision allocation.
7. Chain generation and `dialer-proxy` references.
8. Chain cycle rejection and self-chain rejection.
9. Node deletion dependency checks.
10. Default exit generation (soft and forced).
11. Subscription token rotation and revocation.
12. YAML serialization and deterministic output.
13. Backup/restore round trip.
14. Rate limiting.
15. Xray/V2Ray Base64 share-link subscription generation and re-import.

To validate generated YAML against the official parser, provide a Mihomo binary:

```bash
MIHOMO_BIN=/path/to/mihomo go test ./internal/mihomo -run OfficialMihomo -v
```

The test generates a config using all supported protocols, a chain, groups, rules and DNS, then runs `mihomo -t`.

## Database

SQLite runs in WAL mode with foreign keys enabled and a 5-second busy timeout. Versioned migrations are applied at startup and recorded in `schema_migrations`. Core tables:

`users`, `sessions`, `nodes`, `node_tags`, `chains`, `profiles`, `profile_nodes`, `profile_chains`, `subscription_tokens`, `app_settings`, `schema_migrations`.

Node, chain and profile relationships use immutable UUIDs. Join tables and sessions have foreign keys with cascade behavior; chain node references use `RESTRICT`. Application-level dependency checks run before deletes to return actionable conflicts.

## Data and backup

- Database: `${APP_DATA_DIR}/nyasub.db` with SQLite WAL.
- Session secret (when generated): `${APP_DATA_DIR}/session_secret`, mode `0600`.
- Download a JSON backup in Settings. It includes users (password hashes), sessions, nodes, chains, profiles, joins, subscription token values, and the initialized marker.
- Restore replaces the entire database transactionally. No partial restore is written. You are logged out afterwards and must use the credentials from the restored snapshot.
- Restore validates formats, references, node configs, chains, and regenerates every profile before touching the database.

## Design notes

- Pinia is intentionally not used. Shared authentication/CSRF state is small and handled with Nuxt `useState` composables; adding Pinia would not remove complexity.
- Node IDs and profile/chain references are UUIDs. Display names never form relationships.
- YAML is generated from an ordered `yaml.Node` tree, not a map, so key order and output are stable across runs.
- SQLite uses a pure-Go driver (`glebarez/sqlite`), keeping the binary CGO-free and making amd64/arm64 builds simple.

## License

MIT. See [LICENSE](LICENSE).
