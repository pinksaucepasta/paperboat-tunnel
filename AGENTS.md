# AGENTS.md - paperboat-tunnel

Inherit [`../AGENTS.md`](../AGENTS.md). Tunnel, edge, and data plane mean this repo.

## Ownership

Caddy, pinned frps packaging, QUIC/TCP-TLS connector transport, public HTTPS/WSS,
connector attachment, route forwarding, trusted limits, private control integration,
node lifecycle, and byte measurement. Server state remains authoritative.

## Stack

Go `1.25.7` for owned code; upstream frp pinned under `frp/` as a Git submodule; Caddy for
TLS and public edge policy. The frps dashboard is private diagnostics only.

## Local Rules

- Prefer supported frp hooks and adjacent services. A fork requires a proven missing
  capability, security/upgrade plan, compatibility tests, and explicit approval.
- First release supports helper traffic and public HTTP/WSS previews only; no raw TCP,
  public UDP, STCP, XTCP, NAT traversal, reviews, extensions, or protected previews.
- Preserve WSS, SSE, streaming, cancellation, headers, trusted client IP, backpressure,
  bounded resources, correlation, and redaction.
- Model route assignment, connector replacement, cleanup, counters, node registry, stale
  ownership, and draining explicitly.
- Admission and usage messages are authenticated, replay-safe, idempotent, and
  reconcilable across restart/failover.
- Pin every frp commit/release, Caddy/base image, and release artifact immutably.

## Verify

Run owned Go checks plus interoperability, race, load, multi-node, contract, and failure
injection tests appropriate to the change. Unit tests alone do not prove tunnel fidelity.
