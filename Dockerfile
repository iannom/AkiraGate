# syntax=docker/dockerfile:1

FROM node:22.12.0-bookworm-slim AS frontend-build

WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.23.10-bookworm AS gateway-build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src/userspace-gateway
COPY userspace-gateway/go.mod userspace-gateway/go.sum ./
RUN go mod download
COPY userspace-gateway/ ./
RUN go_arch="${TARGETARCH:-$(go env GOARCH)}"; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${go_arch}" \
    go build -trimpath -ldflags="-s -w" -o /out/akiragate-server ./cmd/akiragate-server; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${go_arch}" \
    go build -trimpath -ldflags="-s -w" -o /out/akiragate-gateway ./cmd/akiragate-gateway

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 akiragate \
    && useradd --uid 10001 --gid akiragate --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home akiragate \
    && mkdir -p /app/frontend/dist /data \
    && chown -R akiragate:akiragate /app /data

COPY --from=gateway-build /out/akiragate-server /usr/local/bin/akiragate-server
COPY --from=gateway-build /out/akiragate-gateway /usr/local/bin/akiragate-gateway
COPY --from=frontend-build --chown=akiragate:akiragate /src/frontend/dist /app/frontend/dist
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh /usr/local/bin/akiragate-server /usr/local/bin/akiragate-gateway

ENV AKIRAGATE_DATA_DIR=/data \
    AKIRAGATE_CONFIG=/data/config.json \
    AKIRAGATE_WEB_ROOT=/app/frontend/dist

WORKDIR /app
VOLUME ["/data"]
EXPOSE 8787 7928

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD port="$(sed -n 's/.*"web_port"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "${AKIRAGATE_CONFIG:-/data/config.json}" | head -n1)"; curl -sS -o /dev/null "http://127.0.0.1:${port:-8787}/" || exit 1

USER akiragate:akiragate
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["akiragate-server"]
