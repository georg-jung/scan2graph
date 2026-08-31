# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
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
ENV TMPDIR=/tmp \
    S2G_HTTP_ADDR=:8080 \
    S2G_SMTP_ADDR=:2525
EXPOSE 8080 2525
ENTRYPOINT ["/scan2graph"]
