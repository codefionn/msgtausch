FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY server.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /out/backend ./server.go

FROM alpine:3.19
RUN apk add --no-cache wget ca-certificates \
    && adduser -D -H app
USER app
COPY --from=builder /out/backend /backend
ENV PORT=5678
ENV TLS=false
EXPOSE 5678 8443
ENTRYPOINT ["/backend"]
