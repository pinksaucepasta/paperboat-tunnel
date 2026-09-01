# Tunnel Operations

The Paperboat tunnel is a ciphertext-only data plane. Operators may inspect bounded health,
counts, durations, transport categories, and stable region/node identifiers. Never capture peer
candidate addresses, authorization material, endpoint certificates, file names, commands, paths,
or private payloads.

## Administrative surface

Metrics, health details, and profiles belong on the configured admin listener. Keep it disabled
unless an operator collector needs it. A network listener requires mTLS and an operator CIDR
allowlist; otherwise bind loopback or an owner-authenticated Unix socket. Public ingress listeners
must not route admin handlers. Treat any public reachability as a security incident.

## Required alerts

| Condition | Warning | Critical | First response |
| --- | --- | --- | --- |
| STUN or signaling failures | above 2% for 5 minutes | above 10% for 5 minutes | Separate listener health, authorization rejection, and upstream network loss. |
| Peer-relay QUIC failure | above 2% for 5 minutes | unavailable in one region for 5 minutes | Drain the affected node and preserve the approved WSS fallback. |
| WSS failure | above 1% for 5 minutes | unavailable while UDP is impaired | Stop rollout; do not enable an unapproved raw-port fallback. |
| Route or control lag | older than two control intervals | older than five intervals | Check snapshot acknowledgement, node generation, and control credentials. |
| Admission saturation | above 80% for 5 minutes | rejected at capacity | Drain new assignments and add a compatible node before raising a reviewed limit. |
| Usage delivery backlog | oldest item above 2 intervals | signature/sequence rejection or sustained growth | Preserve the durable queue and reconcile rather than deleting counters. |
| Certificate or trust refresh | refresh fails before half-life | freshness deadline reached | Stop new admission on the affected listener and restore valid signed state. |
| Connection/resource leak | sustained growth after traffic drains | configured ceiling reached | Drain, collect bounded profiles, restart, and verify leases/routes are fenced. |

Independent regional probes must cover STUN, signaling, peer-relay QUIC, WSS, HTTP/3, HTTP/2,
authorization, credential expiry, and node drain with synthetic identities that cannot address a
user machine. Alert labels are bounded region, transport, result, and reason values only.

## Canonical preview carrier

Canonical preview traffic uses the dedicated connector-v1 carrier listeners, not a separate
preview endpoint. Configure both `carrier_tcp_listen_address` and
`carrier_quic_listen_address`. Each edge process mints one in-memory TLS identity for both
listeners and publishes its exact certificate and SPKI pin in authenticated node registration.
Machine certificates are short-lived self-signed Ed25519 leaves, so the edge checks the exact
public-key thumbprint in the server admission registry. Never replace either exact binding with a
broad static CA or an operator-managed carrier certificate.

Node registration advertises the dedicated public carrier ports in the `carrier_endpoint` object.
The connector-v1 admission is the only source of route and connector bindings; operators must not
invent an endpoint or reconstruct a binding from a local port.

The control client pulls a complete node-scoped desired admission snapshot at
`/v1/edge/previews/carrier-admissions`. The response must contain `complete: true` and no more
than 4,096 metadata-only admissions. A failed, incomplete, or over-limit response leaves the
last-known-good set unchanged. For each valid snapshot entry, the tunnel stages the admission,
then sends the idempotent `/v1/edge/previews/carrier-admissions/ack` request. Only a successful
ACK marks that exact operation and attachment generation admissible to TLS; a pending entry is
never accepted by `PeerBinding`.

After an authenticated carrier is accepted, the edge attaches every matching route and posts
`edge_ready` observations. Carrier close and lease expiry are informational observations only.
Snapshot removal detaches locally; only a server-created detach command carries an exact terminal
generation and is posted as a bounded, retryable detachment acknowledgement. `access_mode: private` is
installed only in the authenticated accessor-carrier registry. Private HTTP arrives through the
stable-hostd PAC/CONNECT path and private TCP through the hostd loopback listener; both carry a
fresh machine-session grant bound to the exact route and generations. Private routes are never
installed in the public HTTP matcher. The edge accepts only the authenticated route binding and
never treats a browser request header as private-access authority.

The snapshot and ACK paths are the current server-edge wire assumption. They must be registered
by the control plane with node authentication, operation/lease/generation checks, idempotent
replay, and complete-set semantics. A delta/outbox page must not be returned at the snapshot path.

## Durable tunnel operations

The server owns the durable tunnel, route, domain, operation, and connector desired state. The
edge owns only the live attachment and forwarding observation. Connector loss, edge restart, or
node drain never deletes a tunnel, route, domain binding, DNS state, or certificate. A replacement
connector is ready before the old connector drains, and stale acknowledgements cannot remove the
replacement generation.

Route selection is exact hostname first, then the longest permitted one-label wildcard, then path
specificity and priority. A route keeps the public `Host` by default; origin `Host` and TLS SNI are
independent settings. `tcp_private` routes have no HTTP host or path matcher.

## DNS and certificate operations

Domain bindings are independently reconciled from connector health. The server's provider-aware
DNS instructions are authoritative for the required record, CAA policy, and challenge target.
Operators must verify normalized hostname ownership, CNAME/TXT propagation, ACME validation, and
certificate distribution to every captured edge process before declaring a domain ready. A DNS or
certificate failure keeps the previous valid generation active and reports a typed `dns` or
`certificate` health dimension. Never copy certificate private keys or provider credentials into
edge configuration, logs, tickets, or bundles.

## Private access boundary

Private HTTP is always:

```text
browser -> narrow PAC/system proxy -> stable hostd -> route-bound carrier -> edge -> origin
```

Hostd authenticates each request with its renewable machine session. The edge re-resolves the
current route and generation before forwarding. Private TCP uses the same authorization boundary
through a literal-loopback listener created by `pb access tunnel`; no public listener becomes a
private listener by inspection of a URL.

The edge returns `401 Unauthorized` when a current machine-session grant is missing or invalid,
`403 Forbidden` when the authenticated machine is denied or revoked for the exact route, and
`503 Service Unavailable` when hostd, the carrier, the current edge binding, or the authorization
authority is temporarily unavailable. Responses remain non-enumerating and never start a browser
login, cookie, or redirect flow.
