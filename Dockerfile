# syntax=docker/dockerfile:1

FROM node:24-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run generate

FROM golang:1.26-alpine AS backend
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/nyasub ./cmd/nyasub

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata su-exec \
    && addgroup -S -g 10001 nyasub \
    && adduser -S -D -H -u 10001 -G nyasub nyasub \
    && mkdir -p /app/web /data \
    && chown -R nyasub:nyasub /app /data

WORKDIR /app
COPY --from=backend /out/nyasub /usr/local/bin/nyasub
COPY --from=web /web/.output/public /app/web
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

ENV APP_LISTEN=0.0.0.0:8080 \
    APP_DATA_DIR=/data \
    APP_WEB_DIR=/app/web \
    APP_LOG_LEVEL=info \
    TZ=UTC

EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
