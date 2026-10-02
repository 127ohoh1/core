# Multi-target build for the 127ohoh1 public reference implementation.
#   docker build --target control-plane|edge|cli|demo-origin -f deploy/docker/Dockerfile .
# DEVELOPMENT IMAGES: they run as a non-root user and contain no secrets, but the
# reference implementation is not production-hardened (see README).
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w" -o /out/ ./cmd/...

FROM alpine:3.20 AS base
RUN apk add --no-cache ca-certificates wget && adduser -D -u 1000 ohoh
USER 1000

FROM base AS control-plane
COPY --from=build /out/control-plane /usr/local/bin/control-plane
ENTRYPOINT ["control-plane"]

FROM base AS edge
COPY --from=build /out/edge /usr/local/bin/edge
ENTRYPOINT ["edge"]

FROM base AS cli
COPY --from=build /out/127ohoh1 /usr/local/bin/127ohoh1
ENTRYPOINT ["127ohoh1"]

FROM base AS demo-origin
COPY --from=build /out/demo-origin /usr/local/bin/demo-origin
ENTRYPOINT ["demo-origin"]
