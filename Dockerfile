# syntax=docker/dockerfile:1
#
# zeroauthy container image. Build: docker build -t zeroauthy .
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 .
#
# Go cross-compiles natively on the build platform, and the runtime stage has
# no RUN steps, so arm64 images build without emulation. The runtime image
# ships Node.js because Actions, custom database scripts and social profile
# scripts run in Node (social scripts need Node 25+; see docs/social-connections.md).
#
# Both stages are Chainguard (Wolfi) images pinned by digest, because the
# free tier publishes only `latest`; the comment beside each digest gives
# the tag, the image's creation date and what it ships. How to bump them is
# in docs/supply-chain.md ("What is pinned and how to bump it").

# cgr.dev/chainguard/go:latest, created 2026-11-02: Go 1.27.3, bash, git,
# glibc. The build forces the toolchain named in go.mod (below), so the
# image binary is built with the same Go as the release archives whatever
# Go the base ships.
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go@sha256:575572885e29c3c3bac6622d8db116e983436c546cb2987b001747ce6c278891 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
# GOTOOLCHAIN=goX.Y.Z (the go.mod `go` line) downloads and checksum-verifies
# exactly that toolchain instead of using the base image's newer Go.
RUN GOTOOLCHAIN="go$(sed -n 's/^go //p' go.mod)" go mod download
COPY . .
RUN GOTOOLCHAIN="go$(sed -n 's/^go //p' go.mod)" \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X main.version=${VERSION}" \
      -o /out/zeroauthy ./cmd/zeroauthy \
 && mkdir -p /out/data

# cgr.dev/chainguard/node:latest, created 2026-11-02: Node.js 26.13.0 and
# npm 12.2.1 (/usr/lib/node_modules/npm, found by the Actions builder beside
# /usr/bin/node), busybox (/bin/sh, for CMD-SHELL health checks), dumb-init,
# the CA bundle at /etc/ssl/certs/ca-certificates.crt (SSL_CERT_FILE is set),
# user `node` uid/gid 65532 with home /home/node, no package manager.
FROM cgr.dev/chainguard/node@sha256:4ad7301975908b87d321af8b9ed41630dc69015976269965ee459c27541df252
ARG VERSION=dev
LABEL org.opencontainers.image.title="zeroauthy" \
      org.opencontainers.image.description="Open-source, Auth0-compatible identity server" \
      org.opencontainers.image.source="https://github.com/occupysaas/zeroauthy" \
      org.opencontainers.image.documentation="https://github.com/occupysaas/zeroauthy/blob/main/docs/configuration.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/zeroauthy /usr/local/bin/zeroauthy
# Numeric ids: the base's `node` user is 65532, and numbers need no name
# lookup in the runtime image.
COPY --from=build --chown=65532:65532 /out/data /data
COPY LICENSE NOTICE /usr/share/doc/zeroauthy/
# Defaults for a single-container start: SQLite in the /data volume, migrated
# on start. Override any setting with ZEROAUTHY_* variables or --config.
ENV ZEROAUTHY_SERVER__LISTEN=:8080 \
    ZEROAUTHY_STORAGE__DSN=sqlite:///data/zeroauthy.db \
    ZEROAUTHY_STORAGE__AUTO_MIGRATE=true
USER 65532
WORKDIR /data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["zeroauthy"]
CMD ["serve"]
