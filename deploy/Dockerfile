ARG GO_VERSION=1.26.6
ARG CADDY_VERSION=2.11.4
ARG XCADDY_VERSION=0.4.5
ARG PAPERBOAT_VERSION

FROM golang:${GO_VERSION}-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS go-build
ARG PAPERBOAT_VERSION
WORKDIR /src
COPY . .
RUN printf '%s\n' "${PAPERBOAT_VERSION}" | grep -Eq '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$' \
  && CGO_ENABLED=0 go build -p=2 -trimpath -ldflags='-s -w' -o /out/paperboat-tunnel ./cmd/paperboat-tunnel
RUN cd frp && CGO_ENABLED=0 go build -p=2 -trimpath -buildvcs=false -ldflags='-s -w' -tags='frps,noweb' -o /out/frps ./cmd/frps

FROM golang:${GO_VERSION}-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS caddy-build
ARG CADDY_VERSION
ARG XCADDY_VERSION
ENV CADDY_VERSION=v${CADDY_VERSION}
ENV XCADDY_SKIP_CLEANUP=1
RUN GOBIN=/usr/local/bin go install github.com/caddyserver/xcaddy/cmd/xcaddy@v${XCADDY_VERSION}
WORKDIR /src
COPY . .
RUN xcaddy build \
  --with github.com/caddy-dns/cloudflare@v0.2.4 \
  --replace github.com/pinksaucepasta/paperboat-tunnel=. \
  --with github.com/pinksaucepasta/paperboat-tunnel/caddymodules/paperboatquic=./caddymodules/paperboatquic

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG PAPERBOAT_VERSION
LABEL org.opencontainers.image.version="${PAPERBOAT_VERSION}"
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tini \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --home /var/lib/paperboat-tunnel --create-home paperboat-tunnel
COPY --from=go-build /out/paperboat-tunnel /usr/local/bin/paperboat-tunnel
COPY --from=go-build /out/frps /usr/local/bin/frps
COPY --from=caddy-build /src/caddy /usr/local/bin/caddy
RUN install -d -o paperboat-tunnel -g paperboat-tunnel /var/lib/paperboat-tunnel/runtime /var/lib/paperboat-tunnel/state
USER paperboat-tunnel
ENTRYPOINT ["/usr/bin/tini", "--", "paperboat-tunnel"]
CMD ["-deployment-config", "/etc/paperboat-tunnel/deployment.json", "-state-path", "/var/lib/paperboat-tunnel/state/state.json"]
