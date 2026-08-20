# syntax=docker/dockerfile:1
# Multi-stage build: static, non-root image for running on Kubernetes.

FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache modules separately from sources.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG DATE=
RUN CGO_ENABLED=0 GOOS=linux go build \
        -ldflags="-s -w -X main.version=${VERSION} -X main.date=${DATE}" \
        -o /out/gobl.kyb \
        ./cmd/gobl.kyb

FROM alpine:3.21

# Links the ghcr.io package to this repository (and its visibility/permissions).
LABEL org.opencontainers.image.source="https://github.com/invopop/gobl.kyb"

RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 1000 gobl

COPY --from=builder /out/gobl.kyb /usr/local/bin/gobl.kyb

USER gobl
WORKDIR /home/gobl

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gobl.kyb"]
# Port, CouchDB, identity dir, etc. all come from the environment
# (see README "Configuration"); the listen port defaults to 8080.
CMD ["serve"]
