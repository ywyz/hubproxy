FROM node:24-alpine AS frontend

WORKDIR /web
COPY web/package.json web/package-lock.json ./
ARG NPM_REGISTRY=https://registry.npmjs.org
RUN npm ci --registry="$NPM_REGISTRY" --replace-registry-host=always --no-audit --no-fund
COPY web/ .
RUN npm run build

FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY src/go.mod src/go.sum ./
RUN apk add --no-cache upx && go mod download

COPY src/ .
COPY --from=frontend /src/dist ./dist

ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-s -w -X main.Version=${VERSION}" -trimpath -o hubproxy . && upx -9 hubproxy

FROM alpine

WORKDIR /app

COPY --from=builder /app/hubproxy .
COPY src/config.toml ./config.toml

CMD ["./hubproxy"]
