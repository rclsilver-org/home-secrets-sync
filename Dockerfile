FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS build
WORKDIR /src
COPY go.mod *.go ./
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" \
    -o /out/home-secrets-sync .

FROM node:22.23.3-bookworm-slim@sha256:3ed98443660ff48413b5af19ecefce3b9d50845a901a43420d47cc63a9fddbe9 AS cli
WORKDIR /opt/bitwarden
COPY packaging/package.json packaging/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund --cache /npm-cache \
    && rm -rf /npm-cache

FROM node:22.23.3-bookworm-slim@sha256:3ed98443660ff48413b5af19ecefce3b9d50845a901a43420d47cc63a9fddbe9
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=cli /opt/bitwarden/node_modules /opt/bitwarden/node_modules
COPY --from=build /out/home-secrets-sync /usr/local/bin/home-secrets-sync
COPY --chmod=0755 packaging/bw /usr/local/bin/bw
COPY packaging/licenses /usr/share/doc/home-secrets-sync/bitwarden-licenses
RUN mkdir -p /run/home-secrets-sync && chown 10001:10001 /run/home-secrets-sync \
    && chmod 0700 /run/home-secrets-sync
ENV HOME=/run/home-secrets-sync TMPDIR=/run/home-secrets-sync \
    BW_NOINTERACTION=true NODE_ENV=production
LABEL org.opencontainers.image.source="https://github.com/rclsilver-org/home-secrets-sync" \
      org.opencontainers.image.title="home-secrets-sync" \
      org.opencontainers.image.description="Selective one-way Vaultwarden to Infisical synchronization"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/home-secrets-sync"]
CMD ["-config", "/etc/home-secrets-sync/config.json"]
