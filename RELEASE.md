# Paperboat Tunnel Release Provenance

This file tells maintainers and agents exactly what production runs and what `main` is
preparing next. Update it in the same change as any dependency, gitlink, container, local
module, or downstream-patch change. `MAINTENANCE.md` defines the procedure.

## Production

| Field | Value |
| --- | --- |
| Release tag | `2026.07.26.0` |
| Tunnel commit | `e6a471278370e42d12199929587a2f9019b5e570` |
| frp upstream release | `v0.70.0` |
| frp fork commit | `3d8e03cb1e81d7a4bb1afaec472c5649e0deac43` |
| Caddy | `v2.11.4` |
| Caddy builder image | `caddy:2.11.4-builder` (the released Dockerfile was not digest-pinned) |
| Caddy plugins | `github.com/caddy-dns/cloudflare@v0.2.4` |
| Runtime image | `debian:bookworm-slim` (the released Dockerfile was not digest-pinned) |
| Rollback release | First recorded container release; use the pre-release deployment digest from operator evidence |

The production tag predates the local `paperboat_quic` Caddy module and immutable base
image pins. That gap is closed by the next candidate and must not be reintroduced.

## Main Candidate

These values describe the pending candidate represented by the repository files. They
become production only after merge to `main`, a successful `make release-check`, a new
calendar tag, publication, and deployment by immutable image digest.

| Component | Exact pin |
| --- | --- |
| Go builder | `golang:1.25.7-bookworm@sha256:564e366a28ad1d70f460a2b97d1d299a562f08707eb0ecb24b659e5bd6c108e1` |
| frp upstream base | `v0.70.1` (`fa3bcca2ed54bcf80a5d98c8c76f40f72c6b5291`) |
| frp fork branch | `paperboat/v0.70.1-edge` |
| frp fork commit | `f090f4a41868888d2e3b270ec6e7ad0a31d8d65e` |
| frp build tags | `frps,noweb` |
| Caddy | `v2.11.4` |
| Caddy builder | `caddy:2.11.4-builder@sha256:198d47eaee306d4d0c38a9960c89ff2c959aa29ad51d3e2dafa3e93ac961782a` |
| Caddy DNS plugin | `github.com/caddy-dns/cloudflare@v0.2.4` |
| Paperboat Caddy module | `github.com/pinksaucepasta/paperboat-tunnel/caddymodules/paperboatquic` at the tunnel release commit |
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

The authoritative full hashes are the fork history and `FRP_COMMIT` in `Makefile`; short
hashes above are navigation aids. When an upstream release replaces any behavior, mark it
`drop-ready`, remove it during intake, and record the replacement here.

### Paperboat Caddy Delta

- `caddymodules/paperboatquic` adds the native terminal QUIC Caddy app and shares Caddy's
  managed certificate state and HTTP server ownership.
- Owned Caddy configuration applies Paperboat route authorization, public preview safety
  headers, trusted proxy behavior, streaming, and bounded transport policy.
- The module is source-built into Caddy with xcaddy; there is no separate Caddy fork.

### Compatibility And Rollback

- frp `v0.70.1-edge` is paired with helper connector behavior that supports QUIC/TCP-TLS
  racing, generation replacement, admission sessions, reconnect, and control-loss reporting.
- Caddy `v2.11.4` is paired with the local `paperboat_quic` module and Cloudflare DNS
  plugin `v0.2.4`.
- Before releasing this candidate, replace this sentence with the prior production image
  digest and attach real staged upgrade/rollback evidence. Never use a mutable tag as the
  rollback identifier.
