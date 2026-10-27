# Deployment

NyaSub runs as one container: the Go binary serves the REST API, the subscription endpoint, and the built Nuxt SPA. SQLite lives in `/data`.

## Images

The workflow in `.github/workflows/publish.yml` publishes multi-architecture images to GitHub Container Registry on every push to `main` and on `v*` tags:

```text
ghcr.io/<owner>/<repo>:latest
ghcr.io/<owner>/<repo>:sha-<commit>
ghcr.io/<owner>/<repo>:<version>
```

`linux/amd64` and `linux/arm64` are built from the same tag. Docker selects the matching architecture automatically.

The package is private by default. Either make the GHCR package public in GitHub package settings, or authenticate before pulling:

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
```

`GHCR_TOKEN` needs `read:packages` for a private package.

## Requirements

- Docker Engine 24 or newer
- Docker Compose v2
- A hostname and TLS certificate if the instance is reachable from the internet
- Persistent storage for `/data`

## Docker Compose

Create a directory and a Compose file:

```bash
mkdir -p /opt/nyasub
cd /opt/nyasub
```

`compose.yaml`:

```yaml
services:
  nyasub:
    image: ghcr.io/OWNER/nyasub:latest
    container_name: nyasub
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      APP_LISTEN: 0.0.0.0:8080
      APP_BASE_URL: https://nyasub.example.com
      APP_DATA_DIR: /data
      APP_SESSION_SECRET: change-me-to-at-least-32-random-characters
      APP_LOG_LEVEL: info
      APP_TRUSTED_PROXIES: 172.17.0.1
      TZ: UTC
    volumes:
      - nyasub-data:/data
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s

volumes:
  nyasub-data:
    name: nyasub-data
```

Replace `OWNER/nyasub` with the actual GHCR package path.

Generate a session secret:

```bash
openssl rand -base64 48
```

Start the service:

```bash
docker compose pull
docker compose up -d
docker compose logs -f
```

Open the public URL and create the administrator account. Setup can only run once.

## Environment

| Variable | Required | Description |
|---|---|---|
| `APP_BASE_URL` | Yes | Public HTTPS origin, for example `https://nyasub.example.com`. Must not contain a path. |
| `APP_SESSION_SECRET` | Recommended | At least 32 characters. If omitted, a secret is generated once under `/data`. |
| `APP_LISTEN` | No | Listen address inside the container. Keep `0.0.0.0:8080`. |
| `APP_DATA_DIR` | No | SQLite and generated secrets directory. Keep `/data` in Docker. |
| `APP_LOG_LEVEL` | No | `debug`, `info`, `warn`, or `error`. |
| `APP_TRUSTED_PROXIES` | Reverse proxy | Comma-separated proxy IPs or CIDRs. When Nginx/Caddy runs on the host, the container usually sees the Docker bridge gateway (often `172.17.0.1`); verify with `docker network inspect bridge`. |
| `TZ` | No | Container timezone, for example `Asia/Shanghai`. |

Do not publish port `8080` on all interfaces. The example binds it to loopback and expects the reverse proxy on the same host.

## Reverse proxy

### Caddy

```caddyfile
nyasub.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name nyasub.example.com;

    ssl_certificate     /etc/letsencrypt/live/nyasub.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nyasub.example.com/privkey.pem;

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

### Traefik

```yaml
labels:
  traefik.enable: "true"
  traefik.http.routers.nyasub.rule: Host(`nyasub.example.com`)
  traefik.http.routers.nyasub.entrypoints: websecure
  traefik.http.routers.nyasub.tls.certresolver: le
  traefik.http.services.nyasub.loadbalancer.server.port: "8080"
```

When the proxy is in another container, attach both services to the same Docker network and set `APP_TRUSTED_PROXIES` to the proxy container address or the Docker network CIDR. Do not trust arbitrary forwarded headers.

## Upgrade

```bash
cd /opt/nyasub
docker compose pull
docker compose up -d
docker image prune -f
```

Database migrations run automatically at startup. Keep a backup before a major version upgrade.

## Backup and restore

Use **Settings → Backup** to download a JSON snapshot. It includes users, sessions, nodes, chains, profiles, joins, and subscription token values.

Restore from **Settings → Restore** while the service is running. The restore is transactional: a validation failure leaves the current database untouched.

For a filesystem-level backup, stop the container first and archive the `/data` volume:

```bash
docker compose stop
docker run --rm -v nyasub-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/nyasub-data.tgz -C /data .
docker compose start
```

Backups contain password hashes, subscription tokens, and node credentials. Store them encrypted.

## Health and troubleshooting

```bash
curl -fsS https://nyasub.example.com/healthz
docker compose ps
docker compose logs --tail=200 nyasub
```

Common issues:

- **Secure cookies do not stick**: `APP_BASE_URL` must be the exact public HTTPS origin.
- **Client IPs are wrong**: set `APP_TRUSTED_PROXIES` to the real proxy address/CIDR.
- **Subscription links use the wrong scheme**: fix `APP_BASE_URL`, then restart.
- **Restore fails**: check the backup file came from the same or an older compatible NyaSub version.
- **ARM device builds slowly locally**: use the published multi-architecture image instead of `docker build`.

## Production checklist

- `APP_BASE_URL` uses `https://`.
- Port `8080` is reachable only by the reverse proxy.
- `APP_SESSION_SECRET` is set or `/data` is persisted.
- `/data` is on durable storage.
- Backups are stored off-host and encrypted.
- The GHCR image is pinned to a version or digest when reproducible deployments are required.
