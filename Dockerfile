# syntax=docker/dockerfile:1.4

# Builder base with Go toolchain
FROM --platform=${BUILDPLATFORM} docker.io/golang:1.24-bookworm AS builder
ARG TARGETARCH
RUN apt-get update && apt-get install -y git make libsqlite3-dev
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        apt-get install -y gcc libc6-dev; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        apt-get install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross; \
    elif [ "$TARGETARCH" = "arm" ]; then \
        apt-get install -y gcc-arm-linux-gnueabihf libc6-dev-armhf-cross; \
    elif [ "$TARGETARCH" = "riscv64" ]; then \
        apt-get install -y gcc-riscv64-linux-gnu libc6-dev-riscv64-cross; \
    else \
        apt-get install -y gcc libc6-dev; \
    fi && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ENV CGO_ENABLED=1
COPY ./go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && \
    go install github.com/a-h/templ/cmd/templ@latest

# Templ generation stage
FROM --platform=${BUILDPLATFORM} builder AS templ-generate
COPY . .
RUN templ generate

# Format check stage
FROM --platform=${BUILDPLATFORM} templ-generate AS format-check
RUN find . -name "*.go" -type f -not -path "./vendor/*" | xargs gofmt -d -s -l | tee /tmp/gofmt.out && \
    test ! -s /tmp/gofmt.out

# Test stage
FROM --platform=${BUILDPLATFORM} templ-generate AS test
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go test -v github.com/codefionn/msgtausch/... -coverprofile=coverage.out -covermode=count

# Unit test stage
FROM --platform=${BUILDPLATFORM} templ-generate AS unit-test
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go test -v $(go list ./... | grep -v /e2e) -coverprofile=coverage.out -covermode=count

FROM --platform=${BUILDPLATFORM} templ-generate AS simulation
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go run cmd/simulation/main.go -minutes 1

# Proxy test stage
FROM --platform=${BUILDPLATFORM} templ-generate AS proxy-test
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go run cmd/proxy-test/main.go -proxy 127.0.0.1:8080 -timeout 10 -verbose

# Build stage for cross-compilation
FROM --platform=${BUILDPLATFORM} templ-generate AS build-dev
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT}
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p bin && \
    if [ "$TARGETOS" = "darwin" ] || [ "$TARGETOS" = "windows" ]; then \
        CGO_ENABLED=0 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev}" \
        github.com/codefionn/msgtausch; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev}" \
        github.com/codefionn/msgtausch; \
    elif [ "$TARGETARCH" = "arm" ]; then \
        CC=arm-linux-gnueabihf-gcc CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev}" \
        github.com/codefionn/msgtausch; \
    elif [ "$TARGETARCH" = "riscv64" ]; then \
        CC=riscv64-linux-gnu-gcc CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev}" \
        github.com/codefionn/msgtausch; \
    else \
        CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev}" \
        github.com/codefionn/msgtausch; \
    fi

FROM --platform=${BUILDPLATFORM} templ-generate AS build-release
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT}
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p bin && \
    if [ "$TARGETOS" = "darwin" ] || [ "$TARGETOS" = "windows" ]; then \
        CGO_ENABLED=0 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev} -s -w" \
        github.com/codefionn/msgtausch; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev} -s -w" \
        github.com/codefionn/msgtausch; \
    elif [ "$TARGETARCH" = "arm" ]; then \
        CC=arm-linux-gnueabihf-gcc CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev} -s -w" \
        github.com/codefionn/msgtausch; \
    elif [ "$TARGETARCH" = "riscv64" ]; then \
        CC=riscv64-linux-gnu-gcc CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev} -s -w" \
        github.com/codefionn/msgtausch; \
    else \
        CGO_ENABLED=1 go build -o bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} \
        -ldflags "-X main.version=${VERSION:-dev} -s -w" \
        github.com/codefionn/msgtausch; \
    fi

# Runtime stage
FROM scratch AS runtime-dev
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
COPY --from=build-dev /src/bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} /msgtausch
EXPOSE 8080
ENTRYPOINT ["/msgtausch"]
CMD ["-config", "/config.json"]

FROM scratch AS runtime-release
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
COPY --from=build-release /src/bin/msgtausch-${TARGETOS}-${TARGETARCH}${TARGETVARIANT} /msgtausch
EXPOSE 8080
ENTRYPOINT ["/msgtausch"]
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
