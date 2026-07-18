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

## License

MIT. See [LICENSE](LICENSE). The frp submodule retains its upstream license.
