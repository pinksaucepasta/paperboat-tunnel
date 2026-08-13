# Paperboat Tunnel Release Provenance

This file tells maintainers and agents exactly what production runs and what `main` is
preparing next. Update it in the same change as any dependency, gitlink, container, local
module, or downstream-patch change. `MAINTENANCE.md` defines the procedure.

## Production

| Field | Value |
| --- | --- |
| Release tag | `2026.07.29.6` |
| Tunnel commit | `36798d7137a5a348c56ebd6d0cae07901162ac48` |
| frp upstream release | `v0.70.1` |
| frp fork commit | `f090f4a41868888d2e3b270ec6e7ad0a31d8d65e` |
| Caddy | `v2.11.4` |
| Caddy builder image | `caddy:2.11.4-builder@sha256:198d47eaee306d4d0c38a9960c89ff2c959aa29ad51d3e2dafa3e93ac961782a` |
| Caddy plugins | `github.com/caddy-dns/cloudflare@v0.2.4` |
| Runtime image | `debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818` |
| Rollback release | `2026.07.29.3`; deploy its recorded immutable image digest |

The production tag includes the local `paperboat_quic` Caddy module and immutable base
image pins. Those properties must not be reintroduced as candidate-only behavior.

## Main Candidate

These values describe the pending candidate represented by the repository files. They
become production only after merge to `main`, a successful `make release-check`, a new
calendar tag, publication, and deployment by immutable image digest.

| Component | Exact pin |
| --- | --- |
| Go builder | `golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651` |
| frp upstream base | `v0.70.1` (`fa3bcca2ed54bcf80a5d98c8c76f40f72c6b5291`) |
| frp fork branch | `paperboat/v0.70.1-edge` |
| frp fork commit | `028f085af3c787d7c0c77cd58f133ca8aed7ee75` |
| frp build tags | `frps,noweb` |
| Caddy | `v2.11.4` |
| Caddy builder | `caddy:2.11.4-builder@sha256:198d47eaee306d4d0c38a9960c89ff2c959aa29ad51d3e2dafa3e93ac961782a` |
| Caddy DNS plugin | `github.com/caddy-dns/cloudflare@v0.2.4` |
| Paperboat Caddy module | `github.com/pinksaucepasta/paperboat-tunnel/caddymodules/paperboatquic` at the tunnel release commit |
| Owned STUN | `github.com/pion/stun/v3@v3.1.6`; bounded Binding-only UDP service on the deployment `stun_listen_address` |
| Signaling candidate parser | `github.com/pion/ice/v4@v4.4.0`; parsing only, with tunnel policy rejecting TURN, TCP, mDNS, and relay candidates |
| Trusted client address resolver | `github.com/realclientip/realclientip-go@v1.0.0`; configured proxy ranges and rightmost-untrusted-hop policy at the owned HTTP boundary |
| Peer signaling WSS | `github.com/coder/websocket@v1.8.14`; bearer-admitted, binary-only `paperboat.peer-signaling.v1` attachment with compression disabled |
| Owned security floors | `golang.org/x/crypto@v0.54.0`, `golang.org/x/net@v0.56.0`, and `golang.org/x/sys@v0.47.0` |
| Caddy security floors | `google.golang.org/grpc@v1.82.1`, `go.opentelemetry.io/otel@v1.44.0`, and `github.com/klauspost/compress@v1.18.7` in the local module graph |
| Runtime image | `debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818` |

### Paperboat frp Delta From v0.70.1

All entries are currently `required` and live on `paperboat/v0.70.1-edge`:

| Commit | Purpose | Disposition |
| --- | --- | --- |
| `5904a92b` | Accept Paperboat admission session keys | required |
| `bcb3e5a7` | Close authorized HTTP streams correctly | required |
| `89479c7f` | Preserve trusted forwarded scheme | required |
| `02b5aafd` | Add the private raw stream broker | required |
| `7a4ff629` | Own edge traffic generations | required |
| `1d5b2c84` | Cover generation-pool lifecycle | required test |
| `9747d3ad` | Release retired traffic counters | required |
| `d8132a31` | Cover stream half-close behavior | required test |
| `ee67f633` | Synchronize client control shutdown | required |
| `f090f4a4` | Expose client control loss to its owner | required |
| `028f085a` | Align the pinned Go toolchain and module metadata | required build |

The authoritative full hashes are the fork history and `FRP_COMMIT` in `Makefile`; short
hashes above are navigation aids. When an upstream release replaces any behavior, mark it
`drop-ready`, remove it during intake, and record the replacement here.

### Paperboat Caddy Delta

- `caddymodules/paperboatquic` adds the native terminal QUIC Caddy app and shares Caddy's
  managed certificate state and HTTP server ownership.
- Owned Caddy configuration applies Paperboat route authorization, public preview safety
  headers, trusted proxy behavior, streaming, and bounded transport policy.
- The dedicated signaling host admits relay QUIC as full-duplex HTTP/3 request streams on
  `/v1/peer-relay`. Caddy overwrites the internal carrier marker before proxying, while the
  private gateway applies the same route-token, endpoint-role, one-time stream-handle, byte-limit,
  revocation, and usage policy as WSS. Native terminal ALPN remains capped at three streams per
  connection; HTTP/3 has a separate bounded 64-stream limit for application and health traffic.
- The dedicated signaling host exposes exact `GET /network-check/v1` as an empty no-store HTTPS
  204 response for bounded regional latency measurement. Every other unauthenticated path or
  method on that host remains rejected.
- The public HTTP server enables HTTP/3 alongside HTTP/2 for resumable file-transfer
  streaming; edge policy authorizes the complete `/v1/file-transfers` resource tree and
  preserves Range, ETag, PATCH, offset, cancellation, and operation headers without buffering.
- Public preview connectors attach through an authenticated full-duplex HTTP/3 carrier on
  `/v1/public-preview-relay`, with typed network-only fallback to HTTP/2. The carrier uses
  yamux only for edge-to-host preview request multiplexing; route ownership and connector
  generation are verified before publication, and authentication or protocol failures never
  trigger fallback.
- The module is source-built into Caddy with xcaddy; there is no separate Caddy fork.

### Compatibility And Rollback

- frp `v0.70.1-edge` is paired with helper connector behavior that supports QUIC/TCP-TLS
  racing, generation replacement, admission sessions, reconnect, and control-loss reporting.
- Caddy `v2.11.4` is paired with the local `paperboat_quic` module and Cloudflare DNS
  plugin `v0.2.4`. The local module raises only transitive security floors needed to clear
  reachable gRPC and imported-package OpenTelemetry/compression advisories; it does not fork
  or patch Caddy.
- Coder WebSocket `v1.8.14` is Apache-2.0 licensed and already pinned by the unified
  runtime. The signaling adapter uses no compression or browser-origin relaxation. Caddy
  exposes only `/v1/peer-signaling` on the dedicated static-certificate signaling host;
  rollback removes that route, handler, and dependency without changing existing frp traffic.
- Pion ICE `v4.4.0` is MIT licensed and pinned to the unified runtime version. The tunnel
  imports only candidate parsing; tests reject the dependency's inactive TURN/TCP/mDNS/relay
  capabilities at the signaling boundary.
- Before releasing this candidate, replace this sentence with the prior production image
  digest and attach real staged upgrade/rollback evidence. Never use a mutable tag as the
  rollback identifier.
