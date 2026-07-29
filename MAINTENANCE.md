# Paperboat Tunnel Maintenance

This is the operating procedure for agents maintaining `paperboat-tunnel`, its Caddy
build, and the Paperboat frp fork. Read it with `AGENTS.md` and `RELEASE.md` before making
dependency, data-plane, container, or release changes.

## Invariants

- `main` is the only production source branch. A production image is built from a
  calendar-version tag whose commit is contained in `origin/main`.
- `latest` means the newest successfully published production tag. Never publish it from
  a branch, local build, pull request, or manually selected commit.
- Agents work on named branches. A detached HEAD is never a valid development, merge,
  release, deployment, or hotfix state.
- CI may check out an immutable tag detached in its disposable runner. The release gate
  must prove that the tag commit is contained in `origin/main`; this is not permission for
  detached local work.
- `frp/` is a submodule of `pinksaucepasta/frp`, not vendored source. Its recorded gitlink,
  `Makefile` commit, fork branch, and `RELEASE.md` entry must agree.
- Released fork branches and dependency commits are immutable. Never force-push a fork
  branch consumed by a Paperboat release.
- Caddy, Caddy plugins, Go builder, runtime image, and frp are immutable inputs. Version
  labels without image digests are insufficient.

## Branch Convention

Use short lowercase slash-separated names:

| Purpose | Branch |
| --- | --- |
| Production integration | `main` |
| Product feature | `feat/<topic>` |
| Defect or security fix | `fix/<topic>` |
| Documentation | `docs/<topic>` |
| Build or maintenance | `chore/<topic>` |
| Release preparation | `release/<YYYY.MM.DD.X>` |
| frp intake | `upstream/frp-vX.Y.Z` |
| Caddy intake | `upstream/caddy-vX.Y.Z` |

Do not create another long-lived integration branch. Merge through review with required
checks. Delete merged short-lived branches. Before editing, run:

```sh
git status --short --branch
git symbolic-ref --short HEAD
git -C frp symbolic-ref --short HEAD
make maintenance-check
```

If either symbolic-ref command fails, stop and recover onto the intended named branch
before changing files. Do not commit from the detached state.

Configure the Git host to protect `main`: disallow force-push and deletion, require pull
requests and successful repository checks, dismiss stale approvals after new commits, and
restrict direct pushes. Repository documentation and CI do not replace those server-side
rules.

## Ownership Boundaries

- Stock Caddy and xcaddy assembly: `deploy/Dockerfile`.
- Paperboat Caddy behavior: `caddymodules/paperboatquic/` and owned Caddy configuration.
- Stock frp plus downstream commits: the `pinksaucepasta/frp` fork.
- Exact frp checkout: the `frp/` gitlink and `FRP_COMMIT` in `Makefile`.
- Human-readable dependency and patch provenance: `RELEASE.md`.
- Production publication: `.github/workflows/container.yml`.

Do not patch dependency code during the container build. Every source change must exist in
a reviewed repository commit before the tunnel gitlink is updated.

## Updating frp

1. Create `upstream/frp-vX.Y.Z` in this repository from current `main`.
2. In `frp/`, fetch both authorities and verify the signed/tagged upstream target:

   ```sh
   git fetch upstream --tags --prune
   git fetch origin --prune
   git switch -c paperboat/vX.Y.Z-edge vX.Y.Z
   ```

3. Audit upstream release notes, security advisories, protocol/config changes, removed
   APIs, and every Paperboat hook affected by the update.
4. Replay the still-required Paperboat commits as a reviewable series. Prefer supported
   upstream APIs and delete downstream patches that are no longer necessary. Do not merge
   unrelated upstream development or squash away patch identity.
5. Run frp unit, race, compatibility, reconnect, half-close, generation fencing, admission,
   usage, and real helper/tunnel tests. Compare behavior with the currently released pin.
6. Push the new fork branch without force, then update the tunnel gitlink, `FRP_VERSION`,
   `FRP_COMMIT`, contract metadata, and `RELEASE.md` in one change.
7. Run `make check`, build the container by digest, stage it, exercise rollback, and merge
   only with the evidence attached to the change.

For a patch on the current upstream base, branch from the existing
`paperboat/vX.Y.Z-edge`, add focused commits, and advance the pin. Never rewrite commits
already named by a release.

## Updating Caddy

1. Create `upstream/caddy-vX.Y.Z` from current `main`.
2. Update the Caddy builder version and immutable digest together. Update every xcaddy
   plugin version explicitly; never request an unversioned plugin.
3. Update the Caddy dependency in `caddymodules/paperboatquic/go.mod` and reconcile module
   sums. Review Caddy/CertMagic/QUIC API and behavior changes.
4. Test config generation and validation, ACME/on-demand authorization, HTTP/1.1 and
   HTTP/2 preview proxying, browser HTTP/3, native terminal QUIC, WSS fallback boundaries,
   streaming, cancellation, certificate persistence, and graceful restart.
5. Record the new version, builder digest, plugins, local module changes, compatibility
   findings, and rollback target in `RELEASE.md`.
6. Run `make check`, stage the image, verify its embedded `caddy version` and modules, and
   complete the same release gate as an frp update.

## Paperboat Patch Ledger

Every downstream frp commit listed in `RELEASE.md` needs a one-line purpose and one of:

- `required`: no safe supported upstream mechanism exists;
- `upstreamed`: link/reference the upstream change and retain until a released version has it;
- `drop-ready`: upstream now owns the behavior and the next intake must remove the patch.

Local Caddy behavior is recorded by module path and tunnel commit. If a change modifies a
wire contract, credential boundary, routing semantics, usage accounting, or deployment
topology, update the workspace contracts and operational documentation in the same work.

## Release And Production

1. Generate the next version with `tools/release-version.sh next`. On a
   `release/<YYYY.MM.DD.X>` branch, promote the candidate values into the `RELEASE.md`
   production table, name that exact release tag, and record the rollback digest.
2. Merge the complete candidate to `main`; pull and verify `HEAD == origin/main` in a clean
   named worktree. Run `make check`, then run
   `GITHUB_REF_NAME=<YYYY.MM.DD.X> make release-check`.
3. Create that exact `YYYY.MM.DD.X` tag on the verified `main` commit and push it. Never
   move or reuse a release tag.
4. CI fetches `origin/main`, proves the tag commit is on it, rebuilds from pinned inputs,
   and publishes the immutable calendar tag plus `latest`, provenance, and SBOM.
5. Record the image digest in deployment evidence. Deploy the immutable digest, not
   `latest`, then verify readiness, Caddy config, TCP/UDP listeners, terminal QUIC, WSS,
   upload, preview, connector replacement, counters, and restart recovery.
6. Roll back by deploying the previous image digest from `RELEASE.md`. Do not repoint an
   existing tag or mutate its frp fork branch.

Emergency fixes follow the same rule: `fix/<topic>` to `main`, full release checks, a new
calendar tag, and an immutable deployment. There is no production-only side branch.

## Required Review Checklist

- Named branches, clean submodule, and no detached agent worktree.
- Exact dependency versions, commits, image digests, and plugin versions recorded.
- Upstream delta and downstream patch ledger reviewed; obsolete patches removed.
- Security advisories, licenses, config/protocol compatibility, and rollback assessed.
- Contracts, `RELEASE.md`, tests, image provenance, and operational evidence agree.
- Production tag is immutable and contained in `origin/main`.
