# paperboat-tunnel

The Paperboat data plane. It packages the pinned Paperboat frp fork, Caddy edge policy,
and the narrow admission, routing, usage, and node-lifecycle integration used by the
control plane.

The frp fork is tracked in `frp/` as a Git submodule and pinned to an exact release commit.
`origin` is the Paperboat fork; `upstream` tracks `fatedier/frp`.

## Development

Clone with submodules and use the repository Makefile so the pinned toolchain, submodule,
frp tests, and both binaries are verified consistently:

```sh
git clone --recurse-submodules https://github.com/pinksaucepasta/paperboat-tunnel.git
make check
```

See [AGENTS.md](AGENTS.md) for repository ownership and engineering requirements.
Dependency and branch maintenance is defined in [MAINTENANCE.md](MAINTENANCE.md). Exact
production and `main` candidate provenance is recorded in [RELEASE.md](RELEASE.md).
Deployment monitoring and incident recovery are defined in
[docs/operations.md](docs/operations.md) and [docs/runbooks.md](docs/runbooks.md).

## Deployment

Build `deploy/Dockerfile` from the repository root. The tunnel image contains
`paperboat-tunnel`, pinned frps, and Caddy with the `paperboat_quic` app. This single
deployment owns public HTTP/HTTPS, native terminal QUIC, and connector ingress. Copy
`deploy/.env.example` and `deploy/deployment.example.json`, fill deployment-owned values,
mount the required files under `deploy/secrets/`, then run:

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d
```

The configured Caddy uses on-demand ACME for validated helper and preview hostnames; its
`ask` URL must authorize only current Paperboat routes. `signaling_host` receives a static
certificate policy and proxies only `/v1/peer-signaling`; every other path on that host is
rejected. `signaling_capacity` bounds concurrent signaling sessions. The Cloudflare token
must be scoped and stored in `deploy/secrets/cloudflare_api_token`, never in the image or
deployment JSON.

Verify each lane independently after deployment:

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml ps
docker compose --env-file deploy/.env -f deploy/docker-compose.yml exec tunnel caddy validate --config /var/lib/paperboat-tunnel/runtime/caddy.json
ss -lnt '( sport = :443 or sport = :26023 )'
ss -lnu '( sport = :443 or sport = :26023 or sport = :3478 )'
docker compose --env-file deploy/.env -f deploy/docker-compose.yml exec tunnel curl -fsS http://127.0.0.1:9090/readyz
docker compose --env-file deploy/.env -f deploy/docker-compose.yml exec tunnel curl -fsS http://127.0.0.1:9090/metrics
```

TCP and UDP 443, connector TCP and UDP 26023, and UDP 3478 must map only to
`paperboat-tunnel`. UDP 3478 is the owned authenticated-agnostic STUN Binding service used
only for ICE address discovery; it does not expose an application listener.
Readiness and metrics report STUN and peer signaling independently; signaling telemetry is
limited to running state, session and attachment counts, and configured capacity.
Validate a helper hostname with `pb doctor`; it reports the requested terminal mode,
selected native QUIC or WSS transport, and bounded fallback category.
Certificate, authorization, route, and protocol failures must fail without WSS fallback.

Only a commit on `main` may be released or deployed to production. Release container tags
use `YYYY.MM.DD.X`; `latest` is updated only by the validated tag workflow. Follow the
preflight, tagging, verification, and rollback procedure in [MAINTENANCE.md](MAINTENANCE.md).

## License

MIT. See [LICENSE](LICENSE). The frp submodule retains its upstream license.
