# Tunnel And Network Runbooks

For every incident record the immutable deployment digest, node/region, bounded health state,
first/last observation, containment, and verification. Never record credentials, candidate or
interface addresses, private request data, or packet payloads.

## STUN, signaling, or ICE regression

1. Separate UDP listener failure from signaling authorization, candidate-policy rejection, and
   endpoint network loss using bounded result metrics.
2. Keep TURN, TCP, mDNS, WebRTC, FRP NAT-hole, XTCP, KCP, STCP, and SUDP unreachable. Do not enable
   one as incident mitigation.
3. Drain a bad node from new assignments while existing healthy paths finish within their lease.
4. After repair, prove authenticated gathering, nomination, direct QUIC, relay fallback, address
   redaction, and revoked-credential rejection.

## Relay saturation, WSS failure, or UDP blocking

1. Compare admission, stream, byte, queue, FD, memory, and handshake ceilings by bounded region.
2. For relay saturation, remove the node from new selection and let active leases drain. Add an
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
3. Confirm Caddy's trusted-proxy chain, the Paperboat `realclientip-go` boundary, and downstream
   forwarded-header replacement agree.
4. Scan public routes for admin, metrics, profile, FRP dashboard, hook, and private-vhost exposure;
   rotate affected control credentials and redeploy if any were reachable.

## Identity rotation, ciphertext integrity, or replay incident

1. Stop admission for the affected credential/certificate generation without collecting private
   key material or decrypted content.
2. Revoke the compromised public identity through the control plane and wait for a fresh signed
   trust snapshot. Never patch a local snapshot.
3. Reject certificate substitution, transcript mutation, replayed handles, invalid sequence/nonce,
   and authentication-tag failure without downgrading carriers.
4. Verify new direct and relay sessions, in-band rekey, old-generation rejection, and that relay
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

