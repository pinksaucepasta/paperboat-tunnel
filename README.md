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

## Deployment

Build `deploy/Dockerfile` from the repository root. The image contains
`paperboat-tunnel`, pinned frps, and Caddy with the Cloudflare DNS module. Copy
`deploy/.env.example` and `deploy/deployment.example.json`, fill deployment-owned values,
mount the required files under `deploy/secrets/`, then run:

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d
```

Wildcard certificates use ACME DNS-01. The Cloudflare token must be a scoped token stored
in `deploy/secrets/cloudflare_api_token`, never in the image or deployment JSON.

Release container tags use `YYYY.MM.DD.X`. Run `tools/release-version.sh next`, create
that exact tag without a `v` prefix, and push it.

## License

MIT. See [LICENSE](LICENSE). The frp submodule retains its upstream license.
