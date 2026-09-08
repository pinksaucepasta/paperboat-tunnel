# Paperboat Preview and Tunnel Contract v1

This family is the single language-neutral source for preview and tunnel resource
names, lifecycle state, health, errors, and events. The authoritative product behavior
is the workspace `plans/paperboat-product-and-transport-plan.md`. Consumers copy these artifacts into repository-local
testdata and must not read the workspace copy at runtime.

## Declaration status and cutover

The **Edge migration decisions** section is the frozen replacement v1 declaration
from Task 3b (2026-09-05), not a claim that browser access, lazy activation, or capture
exists. Earlier wire schemas/fixtures and the remaining current-runtime sections
below describe the preserved installation. In particular, current `access_mode`
accepts public/private and private uses device-assisted access; these are not the
replacement audience/method semantics. Tasks 24–32 replace their owning schemas,
producers, consumers, OpenAPI, and positive/negative vectors together at the gates
listed below. Do not teach the old runtime to accept unsupported fields, add a v2,
or retain compatibility readers after cutover. This document in paperboat-server
owns product policy; identical copies in paperboat, paperboat-tunnel, and
paperboat-web give each consumer the same declaration.

## Fixed vocabulary

- A `preview_lease` is temporary, owns one random managed endpoint and local target, and is
  bound to an owner device and owner session. It is never restored after reboot. It may
  request up to eight normalized exact, apex, or one-label wildcard domain aliases.
- A `tunnel` is durable desired state owned by an account. Its stable identity is not
  a connector session.
- A `route` maps protocol, hostname and optional path to an origin.
- A `domain_binding` owns hostname verification, DNS instructions and certificate
  state independently from connector availability. Its `target_kind` is exactly one
  of `tunnel_route` or `preview_lease`; tunnel bindings require only `tunnel_id` and
  `route_id`, while preview bindings require only `preview_id`. Supplying both target
  families, or neither, is invalid.
- A `connector` is one replaceable authenticated host attachment to a tunnel.
- A `config_generation` is an immutable validated desired-state snapshot.
- A `tunnel_config_snapshot` is the canonical inner desired-state payload sent
  to a connector. It contains the complete tunnel projection and active routes,
  uses wire protocol names (`tcp_private`, `managed_exact`), and is serialized
  deterministically with routes ordered by priority, name, and ID.
- An `operation` records resumable long-running mutation progress.
- A `log_entry` is a bounded, redacted diagnostic record with an opaque resume
  cursor. A `dns_instructions` resource describes only provider-supported
  records and the persisted verification state; it never claims DNS or TLS
  readiness without external proof.
- `health`, `error`, and `event` are typed contracts, never prose-only status.

No public contract uses `serve`, `preview_session`, `preview_route`, `helper`, or a v2
name for these resources.

## Exposure and creation

`public` is the default access mode for previews and tunnels. There is no positive `--public` option.
`private` means the edge authenticates and authorizes a same-account device before forwarding.

A preview requires `owner_device_id` and `owner_session_id`, has
  `persistent: false`, accepts an optional maximum `user_deadline`, and ends on stop,
  deadline, or owner loss beyond the reconnect grace period. The create request may
  include `domains`, a sorted, duplicate-free list of normalized IDNA hostnames. A
  bare name is an exact/apex alias; a leading `*.` is permitted only for one-label
  wildcard matching. The random managed endpoint is always primary and is
  readiness-gated independently from aliases. `owner_session_id` is an opaque preview-owner nonce
selected for this lease and bound to the selected machine and create operation. It is
  not a browser session ID; closing a dashboard or browser session does not stop the
  preview. Device-authenticated local CLI creation uses the machine identity path and
  the verified machine ID, never a CLI client-session ID as `owner_device_id`.

The managed preview endpoint is `https://<opaque-id>.preview.pprbt.dev` in production
(or the same opaque label under a configured development base). The server generates
the DNS-safe leftmost label, keeps it immutable for the lease, and never prefixes it
with `preview-` or derives it from a user-controlled name.

A ready preview resource exposes bounded `domains` summaries. Every summary uses
`target_kind: "preview_lease"` and the owning `preview_id`, and contains only DNS,
certificate, generation, ETag, and optional safe DNS instructions. Domain summaries
never contain tunnel or route IDs, credentials, bearer material, or ACME challenge
secrets. Stopping or expiring a lease withdraws every alias; it never leaves an
active domain binding behind.

A tunnel is created only by a host-scoped actor. It has stable `id` and
`stable_endpoint_id`, persistent desired state, optional expiry, multiple routes and
multiple connectors. Connector loss never deletes the tunnel, route, domain binding,
DNS state, or certificate state.

The managed tunnel endpoint is `https://<canonical-lowercase-uuid>.tunnels.pprbt.dev`
under the production tunnel base (or the same UUID label under a configured
development base). The leftmost label is a server-generated opaque endpoint UUID,
not the tunnel name, display name, host name, internal tunnel ID, connector ID, or
any other user-controlled value. The endpoint UUID is immutable, persisted with the
tunnel, and replayed unchanged after retries or tunnel renames.

## Mutation and reconciliation

Every create accepts an idempotency key. Mutable durable resources have a positive
monotonic `generation` and strong `etag`; stale mutations require `If-Match` and fail
before state changes. Deletes are idempotent.

Connectors receive a complete validated `config_generation` before ordered deltas.
Missed generations require a full snapshot. Last-known-good state remains active when
new state is malformed, unauthorized, incomplete, or unavailable. Replacement becomes
ready before old work is drained.

## Preview dispatch

Every client calls `paperboat-server` only. After the server commits the preview lease
and its `preview.create` operation, it dispatches one canonical projection to the
selected online owner machine at the machine's active host-runtime route:
`POST /v1/preview-launches`. This includes a create initiated on the owner machine.
The stable host runtime, not the invoking CLI process, owns the machine carrier and
routes every preview owner session over that one authenticated carrier identity.

The JSON request has `kind: "preview_dispatch"` and the following fixed field order:
`schema`, `kind`, `preview_id`, `operation_id`, `account_id`, `actor_id`,
`owner_device_id`, `owner_session_id`, `target`, `access_mode`, `endpoint`,
`lease_deadline`, optional `user_deadline`, `lease_etag`, `state`, `allocation_state`,
`edge_state`, `origin_state`, `created_at`, `last_renewed_at`, `expected_generation`,
`idempotency_key`, `request_id`, `correlation_id`, `request_hash`. The request hash is
the lowercase SHA-256 digest of the deterministic JSON projection excluding
`request_hash`, including `lease_etag` and all trace fields. The projection contains
no URL credential, bearer token, private key, or reusable secret.

The server authenticates the request with a short-lived, single-use
`preview_launch` credential. Its claims and the request must exactly agree on account,
actor, owner machine and session, preview, operation, typed target, access mode,
endpoint, lease and user deadlines, lease ETag, lifecycle dimensions, expected
generation, request hash, idempotency key, request ID, and correlation ID. A mismatch,
replay, expired lease, stale generation, or inactive route is rejected without
starting a second carrier.

The only safe dispatch response is `{schema, kind, preview_id, operation_id, state,
generation}`, where `state` is `accepted`, `ready`, or `failed`. `accepted` is only a
transport acknowledgement; it never completes the create operation. The owner machine
must observe real edge and origin readiness through the device-auth-only
`POST /v1/previews/{id}/readiness` endpoint, using the server operation ID as both the
machine proof operation and `Idempotency-Key`, and the exact strong lease ETag in
`If-Match`. Only that compare-and-swap observation can complete the create operation.
An exact readiness replay returns the same ready projection and ETag. A timeout or
other uncertain dispatch keeps the same operation and lease uncertain for retry; an
explicit rejection fails them. No dispatch outcome reports a preview ready before
readiness observation.

## Domain DNS and managed TLS

Managed certificate issuance uses delegated DNS-01. For each verified domain the
server assigns one immutable, server-owned challenge target below its configured
challenge zone. DNS instructions expose a customer record of the form
`_acme-challenge.<domain> CNAME pb-<stable-domain-token>.<paperboat-challenge-zone>`;
the customer hostname remains the ACME authorization name, while Paperboat writes
the short-lived TXT value only at the delegated target. The target is derived from
the domain, account, tunnel, and server-issued challenge reference and cannot be
changed by a client or provider request. A domain is not TLS-ready until CNAME/TXT
propagation, ACME validation, and every bound edge certificate distribution target
have completed. A CAA denial, delegation mismatch, propagation timeout, revoked
certificate, or stale edge generation is surfaced as a typed certificate/DNS
diagnostic and leaves the prior last-known-good certificate active.

A wildcard binding such as `*.user.me` uses the same contract. The customer points
the wildcard traffic record at the stable Paperboat DNS target and delegates
`_acme-challenge.user.me` to the returned challenge target. Under the default
`managed` strategy, Paperboat owns wildcard issuance, renewal, distribution,
replacement, and revocation. No certificate or private-key upload is part of the
API. `on_demand_leaf` remains an explicit alternative that issues exact one-label
certificates under the verified wildcard; it is not required for managed wildcard
TLS.

Certificate private keys and provider credentials are write-only references. They
never appear in resource views, DNS instructions, operations, audit events, logs,
distribution envelopes after acknowledgement, or edge disk storage. Renewal and
replacement stage a new certificate on every captured edge target, wait for exact
ready acknowledgements, activate the new generation atomically, and only then
retire the old generation. Revocation is a distinct terminal state and is retried
against the durable target set after restart.

Domains bound to a public `tcp` route use `certificate_strategy: "none"` and
`certificate.state: "not_applicable"`. Their DNS instructions include the stable
assigned `public_tcp_port` separately from the origin port. DNS verification makes
the hostname usable at that port; it does not provide hostname routing, a default
port, a dedicated IP, or HTTP edge TLS. The edge passes application TLS bytes
unchanged and never uses client SNI to select the Paperboat route.

The server's `POST /v1/previews` response includes the durable create operation ID in
the safe `X-Paperboat-Operation-ID` header on both the 202 operation response and an
exact 200 replay. The CLI observes that operation while the stable host runtime resumes
carrier work; the operation ID is not copied into the public preview resource.

## Preview carrier attachment

`preview_carrier_attachment` is the secret-free, generation-fenced link between one
preview create operation, one owner session, one stable host carrier identity, one
ephemeral route, and one edge node. It is never a bearer credential and never contains
a token, private key, password, authorization header, or reusable secret.

The server owns attachment allocation and all terminal generations. The owner host
requests or renews an attachment using renewable machine identity and proof, the exact
lease ETag in `If-Match`, and the create operation ID as its idempotency and proof
operation. The binding fixes account, preview, operation, owner device and owner
session, host, lease generation, tunnel, connector, carrier session and process/config
generations, route and edge node. `host_id` must equal `owner_device_id`; tunnel and
connector IDs must differ. `edge_process_epoch` fences an old process that briefly
overlaps a replacement using the same stable edge node ID. Endpoint addresses are
transport metadata only. The two
carrier endpoints are `tls://` for authenticated TCP multiplexing and `quic://` for
authenticated QUIC; they are not mislabeled as HTTP or WebSocket endpoints.

Each edge process mints one in-memory TLS server leaf and key for both carrier
transports. Authenticated node registration binds its bounded public certificate chain
and `carrier_server_spki_sha256` to the exact edge node and process epoch. Attachments
project these as `edge_carrier_server_certificate_chain_pem` and
`edge_carrier_server_spki_sha256`. The host trusts only that admission-scoped chain,
verifies the carrier endpoint hostname and certificate validity, and then checks the
SPKI pin. Replacement processes use a new key and pin; system roots, static deployment
keys, `InsecureSkipVerify`, and private-key projection are forbidden.

The edge pulls a complete node-scoped snapshot from
`POST /v1/edge/previews/carrier-admissions`. A valid response has `schema`,
`kind: "preview_carrier_attachment"`, `complete: true`, non-null `admissions` and
`detachments` arrays, and at most 4,096 items in each array. An incomplete, malformed,
over-limit, or unavailable snapshot leaves the previous last-known-good set active.
Absence from a successful complete snapshot removes local ingress but does not invent a
server terminal generation.

The edge ACKs admission only after installing the exact binding and route generation.
It reports `edge_ready` separately. The host reports origin readiness separately after
a real probe. Only the server may project the attachment and preview ready after both
observations match the current generations. Local expiry, carrier loss, and shutdown
are informational observations. Only an exact server-issued detachment command may be
ACKed as terminal, and stale carrier sessions or process generations cannot remove a
replacement.

All previews for one machine installation and selected edge share one stable carrier
identity while retaining distinct route IDs and owner-session IDs. Independent CLI
processes never open competing machine carriers. The host runtime owns that carrier and
uses a bounded local owner-session lease to stop only the preview whose invoking CLI
exits, disconnects, or misses its heartbeat. Dashboard-dispatched previews use the same
host-runtime dispatcher and do not depend on a browser connection remaining open.

An admitted preview may also carry at most 64 requested custom-domain aliases. Each
alias is a metadata-only record containing `domain_id`, `hostname`, `match_type`, and
the `preview_generation`, `domain_generation`, and `certificate_generation` fences. The
edge rejects duplicate domain IDs or hostnames, stale preview generations, zero or
missing domain/certificate generations, and recursive wildcards. An alias is installable
only when all three generations match the current server projection; it never replaces
the random managed endpoint. Alias withdrawal on stop, expiry, revocation, or a complete
server snapshot omission removes ingress without inventing a terminal server state.

Credential material is write-only. Read models contain only `credential_reference`,
rotation generation and safe metadata. Reusable secrets, bearer tokens, private keys,
authorization headers and payload content are forbidden.

## Private access authorization

Private preview and tunnel routes use one local-runtime and edge authorization boundary:

```text
Browser -> narrow PAC/system proxy -> stable hostd -> authenticated route-bound carrier -> edge -> target carrier
```

The PAC or operating-system rule sends only Paperboat private hostnames to a
literal-loopback hostd proxy. Hostd checks its current renewable machine session for
every CONNECT/request and opens a fresh route-bound access stream. The browser sends no
Paperboat credential and has no Paperboat login, access cookie, callback, redirect,
extension, copied token, or JavaScript localhost check. Direct public-edge traffic never
becomes authorized private traffic.

The server-issued current-accessor snapshot is complete, machine-scoped, and bounded to
4,096 admissions. Each durable-tunnel admission carries validated `tunnel_name` and
`route_name` selector metadata. Stable hostd resolves `pb access tunnel
<tunnel-or-route>` against exact IDs or these exact case-sensitive names only within
that snapshot. It does not enumerate global or cross-account resources. Zero matches
return non-enumerating forbidden access. Multiple matches, including a name colliding
with another route ID, return unavailable without opening a listener or carrier.
Preview admissions never carry durable tunnel or route names.

Hostd verifies its renewable machine session and `POST`s a route-only grant request to
`/v1/edge/private-access/grants` with the machine credential and proof before opening
the access carrier. The carrier then carries only the short-lived signed `grant` and
the server-normalized signed `request` returned by that call. After receiving the
carrier, the edge sends that normalized `request` to
`/v1/edge/private-access/authorize` with its own authenticated edge control
channel and the grant in a write-only header. Browser request headers are never an
identity source. The request body never accepts an account, device, or client
session as authority. The server derives those values from the verified machine
proof and returns them only as safe binding metadata in the grant response.

The grant response is `{schema, kind, grant, expires_at, request_id, correlation_id,
request}`. `grant` is write-only, short-lived, audience-bound, and must not be logged,
cached, persisted, or returned by an edge decision. The normalized `request` is the
exact input for the second call and includes the verified account, accessor device and
access session, route, carrier session, connector (for durable tunnels), process,
config, and route generations. A caller must not substitute the preview owner device
or owner session for the accessing device/session.

The authorize request is a full normalized request. The edge supplies the grant in a
write-only header and the current authenticated edge node and process epoch in the
control headers. The server re-resolves the resource on every call and requires exact
account, resource, route, audience, protocol, accessor identity, carrier session,
connector, route generation, process generation, config generation, and edge
node/process binding. The three audiences are deliberately non-interchangeable:
`paperboat-preview-http`, `paperboat-tunnel-http`, and `paperboat-tunnel-tcp`.

For HTTPS CONNECT, the edge carries the allowed route and generation tuple on the
specific internal connection into its TLS terminator. After TLS termination, the
host/path match must equal that connection binding before forwarding. A shared
listener secret is not sufficient, and a grant for one route never authorizes a
sibling path route or a different hostname on the same connection.

An allowed decision contains only the safe binding and a short expiry. A denial has a
stable typed `reason` and never contains resource, route, connector, session, or
generation identifiers, so missing, cross-account, signed-out, revoked, expired, and
stale resources are non-enumerating. The edge may cache decision metadata only until
`expires_at`; it must close an active stream at that deadline and reauthorize before
reuse. Revocation, replacement, route changes, malformed or oversized responses, and
redirects fail closed. Idempotency keys are bound to the complete request fingerprint;
reusing one key with a different fingerprint is a typed conflict and never overwrites
the earlier result.

Private authorization is a policy check, not a transport credential. The edge removes
all proof and grant headers before forwarding HTTP, and raw TCP carries only the
authorized opaque carrier stream. No fixture or safe audit record contains bearer,
proof, private-key, cookie, authorization-header, origin-body, or reusable-secret
bytes.

The local proxy returns `401 Unauthorized` when the machine session is missing, logged
out, expired, or revoked; `403 Forbidden` when an authenticated device is not allowed
to use the route; and `503 Service Unavailable` when hostd, the carrier, or control-plane
verification is temporarily unavailable. Cross-account responses remain
non-enumerating. Private TCP uses the same authorization boundary through a bounded
literal-loopback listener created by `pb access`.

Connector enrollment proof transcripts bind the SHA-256 digest of the one-time
enrollment token, never the token bytes. Ed25519 credential verifier material is
public-only and uses the RFC 7638 JWK thumbprint as the unprefixed thumbprint;
connector wire key IDs use the `ed25519:` prefix.

## Routing

Hostname normalization uses ASCII IDNA, lowercase and no terminal dot. Host precedence
is exact, then the longest one-label wildcard suffix, then the most specific path, then
explicit priority, then a configured catch-all.

`*.example.com` matches `app.example.com` and does not match `a.b.example.com` or the
apex. A route preserves the public Host by default. Origin Host and TLS SNI are separate
explicit controls.

HTTPS origins verify the server certificate and hostname against the system trust store by
default. `custom_ca` requires an opaque Paperboat credential reference, and optional mTLS
uses a separate opaque client-credential reference. These fields never contain PEM, private
keys, bearer tokens, or raw filesystem paths. Explicit SNI controls certificate verification;
`preserve_host` and `host_override` independently control the HTTP Host header. Cleartext
HTTP/2 uses the explicit `h2c` scheme and is never silently downgraded to HTTP/1.1.

`insecure_development` is an explicit development-only exception. The server rejects it
unless development policy permits it, records an audit event without credential references
or resolved bytes, and surfaces a warning. Production policy never enables this mode.
Origin probes and live requests use the same TLS policy. A generation replacement creates
fresh transports, drains the old generation, and cannot reuse stale CA, SNI, or mTLS state.

## Typed health

Health has these dimensions:

`service`, `edge`, `config`, `route`, `origin`, `dns`, `certificate`, `access`, `update`.

Each dimension uses `unknown`, `ready`, `degraded`, `down`, or `not_applicable` and
includes a stable code, summary, start time, retry state, optional next retry, safe
repair action and correlation ID. Overall health is a deterministic projection of the
most actionable problem.

## Errors and events

Errors include stable `code`, component, safe message, outcome certainty, retryability,
optional retry time, repair action, request ID and correlation ID. Callers never branch
on message text.

Lifecycle events include a resumable opaque `cursor`, stable event type, resource kind
and ID, occurrence time, actor, correlation ID and safe metadata. Events never contain
credentials, headers, request bodies or response bodies.

## Compatibility ownership

The public family is `paperboat.preview-tunnel` version `1.0.0`:

- `paperboat-server` owns desired state, authorization, generations, operations, audit,
  DNS and certificate coordination.
- `paperboat` owns foreground preview leases, host service, local persistence,
  connectors, origins and updates.
- `paperboat-tunnel` owns ingress, TLS termination, route and connector selection,
  forwarding, draining and edge health.
- `paperboat-web` consumes safe server read models and never connector credentials,
  private keys or edge-private configuration.

There is no compatibility implementation for the superseded unreleased preview/serve
model and no v2 surface.
## Edge migration decisions

### Authority and identity

`audience` is exactly `public | private | team`; `connection_method` is exactly
`edge | native`. These are independent fields, not spellings of one access mode.
Public is the explicit-create default and requires authenticated publication.
Private authorizes the resource owner; team additionally permits current members
with an explicit resource grant. Membership alone, account discovery, email suffix,
URL knowledge, a ready carrier, and the application's own login grant nothing.
`native` supports private/team and uses Task 2's common pair/resource authority;
public/native is invalid. Native is end-to-end encrypted. Edge is browser HTTP
with TLS termination at paperboat-tunnel, including private/team; it never claims
end-to-end encryption. Neither method silently falls back to the other. HTTP/3 to
HTTP/2 connector fallback stays within edge and does not change audience.

The server owns these declarations; identifiers are opaque nonempty strings,
generations are positive monotonically increasing uint64 values (never wrap),
times are UTC instants, and all fields below are required unless marked optional:

| Declaration | Fields and invariant | Producer → consumer |
| --- | --- | --- |
| Resource binding | `account_id`, `resource_kind` (preview_lease/tunnel), `resource_id`, `resource_generation`, `route_id`, `route_generation`, `target_id`, `target_generation`, `audience`, `connection_method`; exact normalized hostname, path match and protocol | Server desired state → edge and daemon |
| Target binding | Above binding plus `owner_device_id`, `installation_generation`, `boot_id`, exact scheme/address and origin TLS policy; explicit previews also bind `owner_session_id`, while lazy leases bind current daemon registration and policy ownership; durable tunnels use their explicitly configured connector/target ownership, not a synthetic preview session | Server-approved daemon registration → server projection → edge/daemon |
| Subject grant | `grant_id`, `grant_generation`, principal user or scoped machine identity, exact resource/route/target selector, actions subset of view/inspect/replay, `expires_at`; team grants also bind `team_id` and `membership_generation` | Server membership/resource authorization → edge/daemon |
| Edge decision | Exact resolved binding, principal, granted action, `policy_generation`, optional membership/grant generations when applicable, `issued_at`, `expires_at`, `decision_id`; additionally connector session/process, config/assignment generations and edge node/process epoch | Server authorization → authenticated edge → exact daemon stream |
| Lazy policy | `policy_id`, `policy_generation`, owner/environment identity, audience private/team, exact allowed targets with permission following replacement listeners, reservation identity, expiry, and limits below | Owner mutation at server → daemon activation and edge lookup |

No caller can supply identity as authority. Server resolves selectors against
current state and returns the exact binding, not an account-wide forwarding grant.
A preview has one target; each durable route has an explicit target binding. Origin
address, TLS trust/SNI, ownership, audience, grants, or route match changes fence the
relevant generation before reuse. Heartbeat-only lease extension does not replace
the target identity. Native pair generation remains owned by the p2p-v1 contract;
these resource generations cannot mint or replace pair authority.

Task 26's implemented stable-preview authorization binds `route_generation` from
the ready attachment and rechecks it for each browser decision. The preview lease
heartbeat extends liveness through its own current lease ETag; it neither supplies
route authority nor substitutes for the attachment's route generation. Production
enablement still depends on the selected Public Suffix List isolation gate above;
the development HTTP origin is not evidence that this rollout prerequisite passed.

The edge authenticates and authorizes the exact selected route before requesting
activation, probing the origin, or opening forwarding. The daemon independently
checks the server-approved binding against its current target and ownership before
dialing. Connector membership is not permission to dial another target. Reject
ambiguous Host/:authority, encoded-path normalization disagreement, stale aliases,
and sibling-route substitution. Bind each HTTP request or multiplexed stream, not
just the TCP connection or TLS hostname. All public forwarding still requires an
unexpired publication binding; anonymous traffic cannot create or refresh it.

Before origin forwarding, strip all inbound case-insensitive `X-Paperboat-*`,
`Paperboat-*`, proxy authorization, and Paperboat cookie names; discard client
Forwarded/X-Forwarded-* identity and rebuild only configured proxy metadata. Strip
reserved response headers and attempts to set Paperboat cookie names too. Application
Authorization and non-Paperboat cookies retain their application meaning. Scoped
edge API authentication uses a reserved Paperboat header, consumed at the edge,
so it does not steal the application's Authorization header. Provenance is typed
connector metadata, never client-supplied headers or reusable browser credentials.

### Browser origin and session isolation

Keep the existing managed URL shapes: random explicit preview labels and stable
opaque tunnel labels; lazy labels are `p<port>-<server-issued-environment-id>` under
`preview.pprbt.dev`. Display names are not DNS identity. No managed label is ever
reassigned to another resource/account, including after deletion.

The chosen deployment prerequisite is Public Suffix List PRIVATE entries for
`pprbt.dev`, `preview.pprbt.dev`, and `tunnels.pprbt.dev`. Together they prevent
application cookies scoped to either the hosting suffix or its parent and make
individual managed hosts separate browser sites. No untrusted content is served
at these suffix apexes or at trusted API/login/dashboard origins. Reserve internal
hostnames in server configuration. DNS/TLS readiness alone does not satisfy this
gate: Task 3c records DNS/PSL submission authority, and Task 26 must demonstrate
browser cookie/site behavior in the supported browser matrix after distribution.
This is a selected prerequisite, not an assertion of PSL acceptance or deployment.
Do not enable replacement browser access before the isolation gate passes.
The PSL's current submission guidelines say small/beta services are likely to be
declined; Paperboat is unreleased. Acceptance/distribution is therefore an unresolved
rollout dependency, not a routine DNS step. Task 3c must retain that blocker unless
there is acceptance evidence or an explicit revision of this hostname strategy;
there is no automatic weaker-isolation fallback.

Trusted login uses the server-configured exact HTTPS authentication origin (the
existing Paperboat browser identity service), never an origin inferred from Host
or an application return parameter. Dashboard remains local-only under workspace
policy. Login session and CSRF cookies become `__Host-pb-session` and
`__Host-pb-csrf`: Secure, Path=/, no Domain, SameSite=Lax; session is HttpOnly.
Trusted state-changing endpoints require the session-bound CSRF token and exact
allowed Origin, not a same-site suffix test. Dev login on a Tailscale IP remains a
separate development configuration, never production isolation evidence.

For an unauthenticated top-level GET/HEAD navigation, the edge creates a 120-second
transaction with a random nonce, exact resource/hostname and server-stored relative
return path (maximum 2048 bytes, no scheme/authority, credentials, control bytes,
backslashes, or scheme-relative redirect). Trusted login rechecks authority and
issues a single-use opaque handoff valid for 30 seconds, bound to that transaction,
principal, exact HTTPS callback origin and resource generation. Redeem atomically
at the server; concurrent redemption has one winner. Deliver via a form POST to
reserved `/.paperboat/access/callback`, verify exact login Origin and transaction
state against a transient `__Host-pb-handoff` Secure/HttpOnly/Path=/,
SameSite=None cookie, then delete it. No bearer in URL, referrer, application body,
logs or browser storage. Callback/login responses use no-store and no-referrer,
restrict form-action/frame-ancestors, and are never forwarded to the application.

Issue an opaque `__Host-pb-edge` Secure/HttpOnly/Path=/, no-Domain, SameSite=Lax
cookie bound to the exact hostname and resource, with a 12-hour absolute and
30-minute inactivity expiry, capped by the trusted session/resource/grant expiry.
It identifies a session, not cached permission for 12 hours: each request and active
stream follows the decision freshness limit below. Rotate on authentication or
privilege change; reject duplicate reserved cookies. One hostname has one resource
owner/authentication boundary; path routes are within that resource and still need
separate route grants. Do not cohost independent tenants on sibling paths.
Paperboat access endpoints accept no application service-worker-controlled identity;
a compromised application can act only within its own already-authorized origin.
Never issue a trusted login credential to an application origin.

Custom domains at Task 29 retain exact-host cookies and must not overlap trusted
Paperboat origins or another account's ancestor/descendant binding. Domain ownership
covers the registrable domain for cookie-trust purposes; show that sibling content
under a customer-controlled site shares that customer's browser trust boundary.
Do not claim managed-host isolation for arbitrary customer sibling applications.
Every alias requires a separate handoff/session, and revocation fences all aliases.

Non-navigation requests, WebSockets, APIs, and webhook POSTs never redirect or buffer
and resend bodies for login: unauthenticated is 401, authenticated unauthorized or
nonexistent resource is the same non-enumerating 404. Authorized origin failure is
503 with a typed safe reason. Scoped machine credentials are resource/action-bound,
valid at most 5 minutes and subject to the same revocation limit. Cross-origin
cookie-authenticated unsafe methods and WebSocket handshakes require exact origin;
configured application CORS does not widen Paperboat authority. An unauthenticated
navigation may begin login without disclosing existence; post-login denial is the
same 404. Public webhook publication is explicit; the application verifies provider
signatures. No restricted-to-public recovery or automatic POST replay.

### Revocation and loss of authority

Replacement edge authorization freshness is at most **10 seconds**, including
cache propagation and clock uncertainty, from the server's authoritative read.
This replaces the current privateaccess 45-second default/2-minute maximum only at
Task 26. The server publishes ordered policy/resource/membership invalidations;
a gap or reconnect requires an authoritative snapshot before extending decisions.
Every cache key includes principal, action, full binding and policy/grant generations.
A cache hit never resets issued_at; renewal rechecks authoritative state.

The current Task 26 browser implementation keeps no per-principal permission cache
or replicated permission state at the edge. Every request and each five-second
active-stream refresh reads the server's authoritative database and receives a
decision expiring within ten seconds, enforced by a monotonic local deadline. The
ordered invalidation/snapshot rules above remain requirements for future caching
consumers; no browser invalidation event stream is claimed by this direct-read path,
and an unavailable authority read cannot extend an earlier decision.

Refresh active decisions by 5 seconds. Stop new requests and close both directions
of active HTTP bodies, WebSockets, SSE, gRPC and TCP streams by **15 seconds after
committed revocation**, including up to 5 seconds for bounded cancellation/close.
Explicit lease/grant expiry or locally observed owner termination is a hard deadline:
stop new work and cancel streams at that deadline, without an additional grace grant.
Do not drain privileged traffic after revoked authority or retry broken requests.
If authorization cannot refresh, expire it; a long-lived browser cookie, healthy
origin or stale edge snapshot cannot extend access. Use monotonic local deadlines
capped by server lifetime, subtract bounded clock uncertainty, and fail closed if
the uncertainty cannot fit the 10-second freshness budget. Task 3c must carry these
bounds into regional placement/partition scenarios; they are requirements, not SLO
measurements from Task 3a. Graceful operational drain applies only while authority
remains valid and cannot extend any security deadline.

### Lazy ownership and lifecycle

Reserve a stable environment/port identity independently of forwarding. The server
resolves only an owner-approved exact loopback HTTP/HTTPS/h2c target; a port in a URL
cannot choose scheme, IP, SNI, path, another interface, Unix socket or arbitrary TCP.
Other target types require explicit creation/configuration. A reservation is retained
until owner deletion, which tombstones its label permanently; it carries no access
right and consumes no connector/origin resources while dormant.

Lazy permission shares the approved exact port by default and follows replacement
listeners at that target within the approved environment. The owner approves the
device and target; applications need no registration, PID checks or service-instance
proof. Bind the policy and each activation to the owner device, installation
generation, fresh daemon boot ID and current authenticated daemon registration.
Application exit does not revoke the port policy; a missing listener is
`origin_unavailable`. Changed device, installation, boot or policy bindings fence
old activations and leases; they cannot adopt a replacement registration implicitly.

Port permission persists as policy across application and daemon restarts, not as
a preview lease across reboot. A fresh, authenticated daemon registration for the
current installation and boot is required before a post-reboot request can create
a new lease. Machine re-enrollment or transfer requires owner reapproval; an old
reservation or still-valid team membership cannot adopt a new machine. Current
owner/team grants, exact target authorization, revocation and lease deadlines remain
mandatory. It never starts apps, scans, wakes devices, or restores a forwarder during
boot. Durable tunnel reboot reconciliation remains Task 28.

| Lazy policy budget | Fixed v1 value and exhaustion behavior |
| --- | --- |
| Target allowlist | At most 32 exact targets per environment policy; no port ranges |
| Activation key | Full resource/target/owner/boot/policy-generation binding; one in-flight activation across edge nodes via server ownership |
| Activation deadline | 10 s total, including queue/control/connector; exact origin connect at most 3 s within it |
| Concurrency | 4 activations/environment, 16/account; at most 32 waiting requests per activation, reject excess with 429 and Retry-After: 1 |
| Request buffering | No application body read while activating; request cancellation releases its waiter; cancel activation when last waiter leaves |
| Failure cooldown | 2 s per exact activation key, only after an authorized attempt; no automatic hidden retry; new owner/generation invalidates it |
| Active lazy leases | At most 32/environment and 128/account; reject excess, never evict another active stream to admit new work |
| Owner heartbeat | Every 10 s, renewable deadline at most 30 s from authoritative renewal; known owner end closes immediately |
| Idle resources | Release after 5 min with zero active requests/streams; timer starts at last stream close; listening sockets do not reset it |
| Lease absolute lifetime | 8 h or earlier owner/policy/grant/user deadline; traffic cannot extend it; a later authorized request may create a new lease after fresh checks |
| Active stream lifetime | At most 1 h, capped by lease and authorization deadlines; status makes closure explicit, no hidden replay |

After authorization, distinguish `host_offline`, `origin_unavailable`,
`activation_timeout`, `owner_replaced`, `generation_conflict`, and
`forwarding_failed`. Only an exact usable route/carrier/origin becomes ready.
Lazy HTTP readiness uses one bounded `HEAD /` request to the exact approved target,
with no redirects or response-body retention. A protocol failure or 5xx response is
`origin_unavailable`; 2xx–4xx proves HTTP availability without bypassing application
authentication or requiring a particular application route. There is no hidden
origin-probe retry within a failed activation.
At generation change cancel pending activation and discard its late result.
Idle expiry releases only this lease's resources; stop/delete/revoke fences aliases
and active work without closing a shared connector needed by other resources.
Do not forward until ready, and never retry automatically after any application
request bytes have been forwarded, regardless of method.

### Daemon-local inspection and replay

The daemon owns one capture store shared by native and edge forwarding. It is an
in-memory bounded ring, not a server/edge database or disk archive; restart deletes
captures. Limits count metadata, bodies, raw data, indexes, in-flight capture buffers
and queued records, not just completed entries. Values below are hard maxima;
owner configuration may lower them. Byte units are binary KiB/MiB.

| Capture policy | Fixed v1 budget |
| --- | --- |
| Daemon aggregate | 64 MiB and 2000 records, whichever fills first |
| Per preview | 8 MiB and 200 records, whichever fills first |
| Retention | 15 min from request start, including in-flight records |
| Metadata per record | 16 KiB total, URL at most 2048 bytes and 64 header entries per direction; mark omissions |
| Body capture | Off by default; opt-in sanitized request/response bodies at most 64 KiB each |
| Raw replay capture | Separate explicit opt-in; request only, at most 256 KiB including headers/body, 2 min from request start; counts against all aggregate budgets |
| Capture work queue | At most 128 records/daemon and 16/preview, included in bytes/counts; full queue drops capture, never blocks forwarding |
| Retrieval | 100 records or 1 MiB/page, whichever first; 4 concurrent reads/daemon; slow reads canceled after 10 s without progress |
| Replay | At most 1 concurrent/preview, 4/daemon; 30 s total, capped by current authority/resource expiry |

Evict oldest complete records within the exceeded scope; when only active records
remain, stop/drop capture instead of retaining over budget. Raw bytes expire
independently even while sanitized metadata remains. Use bounded chunks; capturing
cannot accumulate a full streaming body, decompress unbounded data, defeat transport
backpressure or retain a buffer after cancellation. On resource stop/revocation,
immediately deny retrieval/replay and purge its records; removing one inspector's
grant denies that subject without deleting records still authorized to the owner.

Record opaque capture/request IDs, exact resource/target generations, method,
sanitized URL, status/timing and typed errors. Header values are redacted by default;
a small explicit non-sensitive allowlist (Content-Type, Content-Length) may be shown.
Authorization, cookies, API keys, signed tokens and Paperboat headers remain redacted.
Query values are redacted by default; configured additional sensitive names apply
case-insensitively. Body display defaults to omitted; opt-in display supports bounded
UTF-8 JSON with configured sensitive fields plus recursively matched, case-insensitive
password/secret/token/key fields redacted, and fails closed on malformed/unsupported encoding. Do not pretend that
arbitrary binary/form/text payloads can be safely redacted. Raw bytes are never part
of ordinary list/detail/export, diagnostics or audit records.

Capture states are `complete`, `truncated`, `dropped`, `unsupported`, `expired`;
record request/response body states separately and a typed replay-ineligibility
reason. Raw requests require an independent `replay` action; `inspect` returns only
sanitized records. Application view, team membership or machine connectivity implies
neither action. Even the owner must enable capture/raw mode explicitly. Grants are
checked on daemon-local retrieval and again on replay, against current server
resource authority with the same 10-second freshness/15-second revocation limits.

Replay accepts only capture ID, expected resource/target generations and an
idempotency key; it has no destination, header or body override. It reuses exact
supported request method/path/body and application headers, removes hop-by-hop and
reserved Paperboat credentials and recomputes transport framing for the same target.
It rechecks current ownership, grant, expiry, binding and complete retained raw
request before opening the target. Truncated/dropped/unsupported captures, upgrades,
WebSocket/SSE/gRPC streams, missing raw bytes, changed targets or generations cannot
be replayed. Non-idempotent HTTP may replay only as the deliberate user action;
show method/target/body state/possible side effects and use a new request ID linked
to the original. Duplicate action keys return the same replay operation, never a
second origin request. Losing an ambiguous result does not permit implicit retry.
Keep safe action-key/outcome metadata for the 15-minute capture lifetime; after
expiry the old capture ID is unavailable, not reconstructed. Provider signature
expiry is an origin result; do not bypass, re-sign, or claim provider redelivery.

CLI retrieval uses native authenticated daemon access. The local dashboard uses an
explicit authenticated edge inspection channel to the daemon at Task 32: it displays
that edge TLS termination exposes retrieved capture data to the edge. Nothing is
archived at the control plane/edge, responses are no-store, and native private
forwarding remains end-to-end encrypted. There is no silent inspection trust-boundary
fallback. Audit only actor/action, IDs/generations, time and outcome (no URL values,
headers or payload); reserve bounded safe audit/outcome capacity before dispatch and
reject replay if it cannot be recorded. Original and replay response captures are
separate records governed by the same limits.

### Replacement ownership and deletion gates

Task numbers refer to the workspace TRACKER.md; names below are repository-relative.
Keep runtime-backed vectors until their replacement passes, then remove obsolete
assertions rather than weakening them. Task 34 verifies no residual wiring after
these owning cutovers, not a license to retain two production paths.

| Existing surface | Replacement and gate |
| --- | --- |
| Server `internal/previewtunnelstore/preview_lease_v1.go`, `internal/previewtunnelapi`, `internal/httpapi/preview_lease_handlers.go`, attachment adapters/queries; all copies of resources/dispatch/attachment schemas and fixtures | Tasks 24–25: resource/target generations and explicit publication; Task 27: reserved lazy identity and ownership policy; Task 28: durable ownership |
| Server `internal/privateaccess` and `internal/db/queries/private_access_routes.sql`; `/v1/private-access/routes`, `/v1/edge/private-access/carrier-admissions`, `/v1/edge/private-access/grants`, `/v1/edge/private-access/authorize` and OpenAPI definitions | Task 26 replaces browser device-proof/accessor discovery authority with browser/scoped access. Native pair/resource consumers move at Task 19; remove old endpoints once both replacements pass |
| All `preview-tunnel-v1/schemas/private_access.schema.json` and `fixtures/private_access.ndjson`; `internal/contracttest/private_access_v1_test.go`, server machine/grant tests, OpenAPI tests | Task 26 replaces device/PAC browser vectors with handoff, isolation, team/revocation vectors; native coverage belongs to Task 19 |
| Server `internal/auth/auth.go` cookie names and browser CSRF/session consumers/tests, web login/session consumers | Task 26 replaces non-prefixed cookies and exact-origin handling together; no old-cookie reader survives cutover |
| paperboat `internal/privatepreviewproxy`, `internal/hostruntime/privateproxyconfig`, `internal/hostruntime/preview/private_access.go`, `accessor_discovery.go`, private TCP manager, `cmd/pb/access_tunnel_command.go` and their tests/config wiring | Tasks 19/26 replace native access and browser PAC/local-daemon paths respectively; remove PAC/system-proxy setup and cleanup its installed state at cutover |
| Tunnel `internal/edgehttp/private_access_stream.go`, `internal/edgehttp/private_connection.go` and Caddy binding in policy, `internal/control/private_access_grant.go`, `Config.PrivateAccessToken`, `internal/config/deployment.go` (`caddy_private_access_listen_address`) and corresponding tests | Tasks 24/26 replace carrier and browser ingress authority; Task 19 owns native private TCP. Remove the shared listener secret and accessor carrier path after those gates |
| All connector-v1 private_access_http/private_access_tcp kinds, StreamOpen access frames, schemas/vectors and `internal/connectorprotocol/access_stream.go` copies | Task 24 replaces edge connector framing; old accessor frames removed when native/browser replacements pass Tasks 19/26; never relabel them as browser login |
| Current “random lease only” URL and public/private-only `access_mode` declarations, validation and connector snapshots | Tasks 25–27 replace with explicit/lazy endpoint identity and separate audience/method in server, daemon, edge and web projections; existing explicit managed URL shape stays |
| Inspector and replay declarations in this section | Tasks 31–32 implement daemon store, authenticated retrieval, redaction, audit and replay with positive/negative budget/authority tests; current log_entry is not evidence of an inspector |

Task 3c owns the broader FRP/Caddy deployment/binary inventory and regional budgets.
Task 26 gates cross-account/sibling-domain cookies, forged return/Origin/state,
duplicate handoff/cookies, team removal, active-stream expiry, partitions and alias
fencing. Task 27 gates cancellation, coalescing across nodes, replacement/reboot,
idle versus active streams and capacity exhaustion. Tasks 31–32 gate memory under
streaming load, redaction failures, raw expiry, unavailable audit capacity,
unauthorized reads/replays and duplicate/ambiguous replay actions on real connected
paths. These are required future acceptance cases, not tests run by Task 3b.

### Security rationale sources

These choices apply browser primitives to Paperboat; they are not claims that an
upstream project implements this product policy. The
[PSL explanation](https://publicsuffix.org/learn/) describes cookie inheritance
boundaries; its [submission guidelines](https://github.com/publicsuffix/list/wiki/Guidelines)
make acceptance and distribution a real prerequisite. Mozilla's
[Set-Cookie reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
defines host-prefixed cookie attributes; Task 26 must verify them in supported browsers.
Workspace reference paths and implementation/test findings are recorded under Task 3b
in TRACKER.md. No upstream source code is copied by this declaration change.
