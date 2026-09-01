# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/scan2graph ./cmd/scan2graph

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/scan2graph /scan2graph
# Non-root, no shell, no package manager. Works with a read-only root filesystem
# as long as a writable temporary directory (e.g. a tmpfs on /tmp) is provided.
USER 65532:65532
# TMPDIR only. Every S2G_* setting is deliberately absent: a variable baked
# into the image is a real process environment variable, and those outrank the
# operator's configuration file - so an image that set the listen addresses
# would quietly ignore the first two lines of the file they copied.
ENV TMPDIR=/tmp
EXPOSE 8080 2525
ENTRYPOINT ["/scan2graph"]
