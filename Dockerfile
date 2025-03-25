# syntax=docker/dockerfile:1.4

# Builder base with Go toolchain
FROM --platform=${BUILDPLATFORM} docker.io/golang:1.24-alpine AS builder
RUN apk add --no-cache git make
WORKDIR /src
ENV CGO_ENABLED=0
COPY ./go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Format check stage
FROM --platform=${BUILDPLATFORM} builder AS format-check
COPY . .
RUN find . -name "*.go" -type f -not -path "./vendor/*" | xargs gofmt -d -s -l | tee /tmp/gofmt.out && \
    test ! -s /tmp/gofmt.out

# Test stage
FROM --platform=${BUILDPLATFORM} builder AS test
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go test -v github.com/codefionn/msgtausch/... -coverprofile=coverage.out -covermode=count

FROM --platform=${BUILDPLATFORM} builder AS simulation
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go run cmd/simulation/main.go -minutes 1

# Build stage for cross-compilation
FROM --platform=${BUILDPLATFORM} builder AS build-dev
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT}
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p bin && \
    CGO_ENABLED=0 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
    -ldflags "-X main.version=${VERSION:-dev}" \
    github.com/codefionn/msgtausch

FROM --platform=${BUILDPLATFORM} builder AS build-release
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT}
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p bin && \
    CGO_ENABLED=0 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
    -ldflags "-X main.version=${VERSION:-dev} -s -w" \
    github.com/codefionn/msgtausch

# Runtime stage
FROM scratch AS runtime-dev
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
COPY --from=build-dev /src/bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} .
EXPOSE 8080
ENTRYPOINT ["./msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT}"]
CMD ["-config", "/config.json"]

FROM scratch AS runtime-release
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
COPY --from=build-release /src/bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} .
EXPOSE 8080
ENTRYPOINT ["./msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT}"]
CMD ["-config", "/config.json"]

# Nix flake build test stage
FROM nixos/nix:2.28.3 AS nix-build
WORKDIR /src
RUN nix --version
COPY flake.nix .
COPY flake.lock .
RUN nix --extra-experimental-features 'nix-command flakes' flake check .
COPY . .
RUN nix --extra-experimental-features 'nix-command flakes' build .#msgtausch
RUN ls -lh result/bin/ && (file result/bin/msgtausch || file result/bin/msgtausch-linux-amd64 || echo "Binary not found") && (result/bin/msgtausch --help || true)
