FROM golang:1.26-alpine AS builder

ARG VERSION="v0.0.0"
ARG COMMIT_HASH="00000000-dirty"
ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG BUILDER="unknown"
ARG PROJECT_URL="https://github.com/babs/mcp-auth-proxy"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X 'main.Version=${VERSION}' \
      -X 'main.CommitHash=${COMMIT_HASH}' \
      -X 'main.BuildTimestamp=${BUILD_TIMESTAMP}' \
      -X 'main.Builder=${BUILDER}' \
      -X 'main.ProjectURL=${PROJECT_URL}'" \
    -o mcp-auth-proxy ./

# distroless/static-debian13:nonroot ships ca-certificates and runs as UID
# 65532 by default — no shell, no apt, minimal attack surface. The static
# Go binary (CGO_ENABLED=0) needs nothing else.
FROM gcr.io/distroless/static-debian13:nonroot

ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG COMMIT_HASH="00000000-dirty"
ARG PROJECT_URL="https://github.com/babs/mcp-auth-proxy"
ARG VERSION="v0.0.0"

LABEL org.opencontainers.image.source=${PROJECT_URL}
LABEL org.opencontainers.image.created=${BUILD_TIMESTAMP}
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${COMMIT_HASH}

COPY --from=builder /app/mcp-auth-proxy /usr/local/bin/mcp-auth-proxy

USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/mcp-auth-proxy"]
