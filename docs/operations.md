# Tunnel Operations

The Paperboat tunnel is a ciphertext-only data plane. Operators may inspect bounded health,
counts, durations, transport categories, and stable region/node identifiers. Never capture peer
candidate addresses, authorization material, endpoint certificates, file names, commands, paths,
or private payloads.

## Administrative surface

Metrics, health details, and profiles belong on the configured admin listener. Keep it disabled
unless an operator collector needs it. A network listener requires mTLS and an operator CIDR
allowlist; otherwise bind loopback or an owner-authenticated Unix socket. The public Caddy and FRP
listeners must not route admin handlers. Treat any public reachability as a security incident.

## Required alerts

| Condition | Warning | Critical | First response |
| --- | --- | --- | --- |
| STUN or signaling failures | above 2% for 5 minutes | above 10% for 5 minutes | Separate listener health, authorization rejection, and upstream network loss. |
| Relay QUIC failure | above 2% for 5 minutes | unavailable in one region for 5 minutes | Drain the affected node and preserve WSS fallback. |
| WSS failure | above 1% for 5 minutes | unavailable while UDP is impaired | Stop rollout; do not enable a raw TCP or FRP fallback. |
| Route or control lag | older than two control intervals | older than five intervals | Check snapshot acknowledgement, node generation, and control credentials. |
| Admission saturation | above 80% for 5 minutes | rejected at capacity | Drain new assignments and add a compatible node before raising a reviewed limit. |
| Usage delivery backlog | oldest item above 2 intervals | signature/sequence rejection or sustained growth | Preserve the durable queue and reconcile rather than deleting counters. |
| Certificate or trust refresh | refresh fails before half-life | freshness deadline reached | Stop new admission on the affected listener and restore valid signed state. |
| Connection/resource leak | sustained growth after traffic drains | configured ceiling reached | Drain, collect bounded profiles, restart, and verify leases/routes are fenced. |

Independent regional probes must cover STUN, signaling, relay QUIC, WSS, HTTP/3, HTTP/2,
authorization, credential expiry, and node drain with synthetic identities that cannot address a
user machine. Alert labels are bounded region, transport, result, and reason values only.

