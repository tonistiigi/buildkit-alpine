# syntax=docker/dockerfile:1.4

# xx is a helper for cross-compilation
FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.1.1 AS xx

FROM --platform=$BUILDPLATFORM golang:alpine AS build
COPY --from=xx / /
WORKDIR /go/src/github.com/tonistiigi/buildkit-alpine
RUN apk add --no-cache file
ARG TARGETPLATFORM
RUN --mount=target=. --mount=target=/root/.cache,type=cache \
  CGO_ENABLED=0 xx-go build -o /out/bkabuild ./cmd/bkabuild && xx-verify --static /out/bkabuild
  
FROM alpine:3.16
COPY --from=build /out/bkabuild /bin/bkabuild
LABEL moby.buildkit.frontend.network.none="true"
LABEL moby.buildkit.frontend.caps="moby.buildkit.frontend.contexts,moby.buildkit.frontend.inputs"
ENTRYPOINT ["/bin/bkabuild"]