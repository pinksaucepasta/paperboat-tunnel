# Tunnel And Network Runbooks

For every incident record the immutable deployment digest, node/region, bounded health state,
first/last observation, containment, and verification. Never record credentials, candidate or
interface addresses, private request data, or packet payloads.

## STUN, signaling, or ICE regression

1. Separate UDP listener failure from signaling authorization, candidate-policy rejection, and
   endpoint network loss using bounded result metrics.
2. Keep unapproved listener and protocol variants unreachable. Do not enable a raw-port or
   alternate application protocol as incident mitigation.
3. Drain a bad node from new assignments while existing healthy paths finish within their lease.
4. After repair, prove authenticated gathering, nomination, direct QUIC, approved peer-relay
   fallback, address redaction, and revoked-credential rejection.

## Relay saturation, WSS failure, or UDP blocking

1. Compare admission, stream, byte, queue, FD, memory, and handshake ceilings by bounded region.
2. For peer-relay saturation, remove the node from new selection and let active leases drain. Add an
   identically configured node before changing capacity.
3. For QUIC loss, verify automatic WSS selection. For WSS loss, verify healthy UDP paths remain
   usable. Never expose raw TCP or customer ports.
4. Restore the failed carrier and prove new connections return according to hysteresis without
   moving established healthy sessions merely because another path appeared.

## Node drain, replacement, or control-stream divergence

1. Mark the node draining and stop new route ownership before process termination.
2. Confirm snapshot acknowledgement, bounded per-target queues, and current process epoch. Reject
   late observations, counters, or acknowledgements from the prior generation.
3. Replace by immutable image digest and current trust bundle. Do not copy runtime credentials or
   hand-edit route ownership.
4. Verify reassignment, connector replacement, usage reconciliation, stale lease cleanup, and zero
   routes on the retired node.

## Trusted-proxy or public-listener exposure

1. Remove the listener from service. Preserve only sanitized configuration and request IDs.
2. Verify the direct peer is inside the configured proxy CIDRs and that malformed or untrusted
   forwarding headers are stripped. Never broaden the CIDRs to restore traffic.
3. Confirm the public ingress trusted-proxy chain, the Paperboat `realclientip-go` boundary, and downstream
   forwarded-header replacement agree.
4. Scan public routes for admin, metrics, profile, hook, and private-vhost exposure;
   rotate affected control credentials and redeploy if any were reachable.

## Identity rotation, ciphertext integrity, or replay incident

1. Stop admission for the affected credential/certificate generation without collecting private
   key material or decrypted content.
2. Revoke the compromised public identity through the control plane and wait for a fresh signed
   trust snapshot. Never patch a local snapshot.
3. Reject certificate substitution, transcript mutation, replayed handles, invalid sequence/nonce,
   and authentication-tag failure without downgrading carriers.
4. Verify new direct and peer-relay sessions, in-band rekey, old-generation rejection, and that relay
   storage/logs/captures remain ciphertext-only.

## Network change, PMTU black hole, or port-mapper failure

1. Classify the event as `netmon` source failure, unsupported OS event, repeated rebind, UDP family
   loss, PMTU failure, discovery denial, gateway epoch reset, renewal failure, or release failure.
2. Keep one network monitor and one mapper bound to the owned ICE UDP socket. Do not start polling,
   a second mapper, direct `goupnp`, or Tailscale STUN.
3. Invalidate stale mappings and path-quality cache entries, then gather on the new generation.
4. Verify bounded PCP/NAT-PMP/UPnP lease cleanup where supported, adaptive keepalive, PMTU recovery,
   direct/relay selection, and no interface or address data in diagnostics.

## Run-scoped test cleanup failure

1. Identify resources only by the run label and recorded manifest. Never use broad Docker, network,
   process, firewall, or database cleanup.
2. Preserve bounded logs and resource samples when failure evidence is requested.
3. Remove only matching containers, networks, ports, credentials, rows, and impairment rules.
4. Run the preflight inventory and prove a concurrent run's resources remain intact.

## Preview and tunnel attachment failure

1. Separate a preview lease failure from a durable tunnel failure. A preview owns one foreground
   owner session and temporary endpoint; a tunnel keeps its identity, routes, domains, and DNS
   state while a connector or edge node is unavailable.
2. Compare the server operation, resource, route, connector, process, and configuration
   generations with the edge's last acknowledged complete snapshot. A malformed, incomplete, or
   unavailable snapshot leaves the last-known-good attachment active.
3. For a preview, use `pb preview stop <preview>` when the owner lease cannot recover. For a
   durable tunnel, drain or revoke only the affected connector and preserve the tunnel resource.
4. Verify that no stale acknowledgement, expired owner session, or detached edge process can
   remove a replacement attachment, and record only stable IDs and typed health codes.

## DNS or certificate repair

1. Run `pb tunnel status <tunnel-or-id> --json` and separate `dns` from `certificate` health.
2. Run `pb tunnel domain instructions <tunnel-or-id> <domain-or-id> --json`; apply only the
   returned provider-specific record and CAA changes at the authoritative DNS provider.
3. Run `pb tunnel domain verify <tunnel-or-id> <domain-or-id> --wait --timeout 10m --json`.
   Propagation, ACME, or edge-distribution failure keeps the last-known-good certificate active.
4. Do not remove user-owned DNS records during binding removal. Verify every captured edge has
   acknowledged the new certificate generation before traffic is declared ready.

## Connector enrollment, rotation, drain, and revoke

1. `pb tunnel connector add <tunnel-or-id> --json` starts enrollment through the installed host
   runtime. The CLI never prints or accepts enrollment secret bytes.
2. Confirm the new connector in `pb tunnel connector list <tunnel-or-id> --json` before draining
   the old one. Use `pb tunnel connector drain <tunnel-or-id> <connector-id> --wait --timeout 10m --json`
   to stop new work while existing streams finish.
3. Use `pb tunnel credentials rotate <tunnel-or-id> --yes --wait --timeout 10m --json` for a
   tunnel-wide credential generation change. Preserve the tunnel, route, domain, and certificate
   identities while the new connector becomes ready.
4. Use `pb tunnel connector revoke <tunnel-or-id> <connector-id> --yes --wait --timeout 10m --json`
   only for a compromised or permanently retired host. Verify old-generation admissions fail and
   unrelated connectors remain active.

## Control outage and last-known-good recovery

1. Stop mutations and record the deployment, node, operation, resource, and generation IDs only.
2. Keep the last valid complete edge snapshot and local connector configuration until its
   freshness deadline. Do not hand-edit snapshots or delete state to force convergence.
3. Restore the control plane or a verified compatible edge artifact, then wait for a complete
   snapshot and idempotent acknowledgement. Stale observations must be rejected.
4. Verify public route, private PAC/CONNECT access, private TCP loopback access, DNS/certificate
   state, and connector drain behavior before reopening changes.

## Private-access failure

1. Confirm the request used the hostd-owned narrow PAC/CONNECT proxy or the literal-loopback
   `pb access tunnel` listener. Direct browser-to-edge traffic is never private authorization.
2. Interpret `401` as missing or invalid current machine authentication, `403` as an authenticated
   but denied or revoked route binding, and `503` as temporary hostd, carrier, edge-binding, or
   authorization-authority unavailability. Do not replace these responses with a login redirect.
3. Compare the machine installation/session, route, connector, carrier session, configuration,
   assignment, edge-node, and process-epoch values. Reject any stale or partial binding.
4. Restore the renewable machine session or current route assignment through normal reconciliation.
   Never copy a grant, browser cookie, or proof header into a request or incident ticket.
5. Verify another account and a revoked machine receive the same non-enumerating denial class, then
   confirm an authorized request streams without buffering after recovery.

## Support evidence

Use the host-side bounded diagnostic flow described by `pb tunnel doctor <tunnel-or-id>`. A
support bundle may include typed health, generation, retry, and correlation metadata only. Review
the manifest for redactions before sharing it; never include credentials, private keys, URLs with
credentials, origin content, headers, local paths, or candidate addresses.
