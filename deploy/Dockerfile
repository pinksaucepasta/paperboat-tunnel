ARG GO_VERSION=1.25.7
ARG CADDY_VERSION=2.11.4
ARG PAPERBOAT_VERSION

FROM golang:${GO_VERSION}-bookworm AS go-build
ARG PAPERBOAT_VERSION
WORKDIR /src
COPY . .
RUN printf '%s\n' "${PAPERBOAT_VERSION}" | grep -Eq '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$' \
  && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/paperboat-tunnel ./cmd/paperboat-tunnel
RUN cd frp && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -tags='frps,noweb' -o /out/frps ./cmd/frps

FROM caddy:${CADDY_VERSION}-builder AS caddy-build
RUN xcaddy build --with github.com/caddy-dns/cloudflare@v0.2.4

FROM debian:bookworm-slim
ARG PAPERBOAT_VERSION
LABEL org.opencontainers.image.version="${PAPERBOAT_VERSION}"
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tini \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --home /var/lib/paperboat-tunnel --create-home paperboat-tunnel
COPY --from=go-build /out/paperboat-tunnel /usr/local/bin/paperboat-tunnel
COPY --from=go-build /out/frps /usr/local/bin/frps
COPY --from=caddy-build /usr/bin/caddy /usr/local/bin/caddy
RUN install -d -o paperboat-tunnel -g paperboat-tunnel /var/lib/paperboat-tunnel/runtime /var/lib/paperboat-tunnel/state
USER paperboat-tunnel
ENTRYPOINT ["/usr/bin/tini", "--", "paperboat-tunnel"]
CMD ["-deployment-config", "/etc/paperboat-tunnel/deployment.json", "-state-path", "/var/lib/paperboat-tunnel/state/state.json"]
