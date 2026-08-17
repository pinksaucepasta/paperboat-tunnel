#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-development}

case "$mode" in
  development|ci|release) ;;
  *) echo "usage: $0 development | ci | release" >&2; exit 64 ;;
esac

fail() {
  echo "repository state: $*" >&2
  exit 1
}

branch=$(git -C "$root" symbolic-ref --quiet --short HEAD 2>/dev/null || true)
if [ -z "$branch" ]; then
  if [ "$mode" = development ] || { [ "$mode" = release ] && { [ -z "${GITHUB_REF_TYPE:-}" ] || [ "${GITHUB_REF_TYPE}" != tag ]; }; }; then
    fail "detached HEAD is forbidden; switch to a named branch"
  fi
else
  case "$branch" in
    main|feat/*|fix/*|docs/*|chore/*|release/*|upstream/frp-v*|upstream/caddy-v*) ;;
    *) fail "branch '$branch' violates MAINTENANCE.md naming convention" ;;
  esac
fi

frp_version=$(awk '/^FRP_VERSION := / { print $3 }' "$root/Makefile")
frp_commit=$(awk '/^FRP_COMMIT := / { print $3 }' "$root/Makefile")
[ -n "$frp_version" ] && [ -n "$frp_commit" ] || fail "Makefile frp pin is missing"
frp_expected_branch="paperboat/${frp_version}-edge"
frp_configured_branch=$(git -C "$root" config -f .gitmodules --get submodule.frp.branch || true)
[ "$frp_configured_branch" = "$frp_expected_branch" ] || fail ".gitmodules must track $frp_expected_branch"

[ "$(git -C "$root/frp" rev-parse HEAD)" = "$frp_commit" ] || fail "frp checkout does not match $frp_commit"
[ -z "$(git -C "$root/frp" status --short)" ] || fail "frp checkout has local changes"
frp_upstream_commit=$(git -C "$root/frp" rev-parse "${frp_version}^{commit}" 2>/dev/null || true)
[ -n "$frp_upstream_commit" ] || fail "frp upstream tag $frp_version is unavailable"
git -C "$root/frp" merge-base --is-ancestor "$frp_upstream_commit" "$frp_commit" || fail "frp fork commit does not descend from $frp_version"

if [ "$mode" = development ]; then
	frp_branch=$(git -C "$root/frp" symbolic-ref --quiet --short HEAD 2>/dev/null || true)
	[ "$frp_branch" = "$frp_expected_branch" ] || fail "frp must be on $frp_expected_branch, found '${frp_branch:-detached}'"
fi

grep -Fq "| frp upstream release | \`$frp_version\` |" "$root/RELEASE.md" || \
  grep -Fq "| frp upstream base | \`$frp_version\`" "$root/RELEASE.md" || \
  fail "RELEASE.md does not record $frp_version"
grep -Fq "| frp fork commit | \`$frp_commit\` |" "$root/RELEASE.md" || fail "RELEASE.md does not record $frp_commit"

caddy_version=$(awk -F= '/^ARG CADDY_VERSION=/ { print $2; exit }' "$root/deploy/Dockerfile")
[ -n "$caddy_version" ] || fail "Dockerfile CADDY_VERSION is missing"
grep -Fq "| Caddy | \`v$caddy_version\` |" "$root/RELEASE.md" || fail "RELEASE.md does not record Caddy v$caddy_version"
grep -Eq "github.com/caddyserver/caddy/v2[[:space:]]+v${caddy_version}([[:space:]]|$)" "$root/caddymodules/paperboatquic/go.mod" || fail "Caddy module does not use v$caddy_version"
grep -Eq -- '--with github.com/caddy-dns/cloudflare@v[0-9]+\.[0-9]+\.[0-9]+' "$root/deploy/Dockerfile" || fail "Caddy DNS plugin must use an exact version"
[ "$(grep -Ec '^FROM golang:\$\{GO_VERSION\}-bookworm@sha256:[0-9a-f]{64} ' "$root/deploy/Dockerfile")" -eq 2 ] || fail "Go and Caddy builders must use the digest-pinned Go image"
grep -Eq '^ARG XCADDY_VERSION=[0-9]+\.[0-9]+\.[0-9]+$' "$root/deploy/Dockerfile" || fail "xcaddy must use an exact version"
grep -Fq 'go install github.com/caddyserver/xcaddy/cmd/xcaddy@v${XCADDY_VERSION}' "$root/deploy/Dockerfile" || fail "Caddy must be built with the pinned xcaddy version"
grep -Eq '^FROM debian:bookworm-slim@sha256:[0-9a-f]{64}$' "$root/deploy/Dockerfile" || fail "runtime image must be digest-pinned"

if [ "$mode" = release ]; then
	head=$(git -C "$root" rev-parse HEAD)
	release_tag=${GITHUB_REF_NAME:-}
	[ -n "$release_tag" ] || fail "GITHUB_REF_NAME is required for a release check"
	grep -Fq "| Release tag | \`$release_tag\` |" "$root/RELEASE.md" || fail "RELEASE.md production table does not name $release_tag"
	gitlink=$(git -C "$root" ls-tree HEAD frp | awk '$1 == 160000 { print $3 }')
	[ "$gitlink" = "$frp_commit" ] || fail "released frp gitlink $gitlink does not match FRP_COMMIT $frp_commit"
  git -C "$root" show-ref --verify --quiet refs/remotes/origin/main || fail "origin/main is unavailable; fetch it before release"
  git -C "$root" merge-base --is-ancestor "$head" refs/remotes/origin/main || fail "release commit $head is not contained in origin/main"
  [ -z "$(git -C "$root" status --short --ignore-submodules=none)" ] || fail "release worktree is not clean"
  if [ -n "$branch" ]; then
    [ "$branch" = main ] || fail "release must run on main, found $branch"
    [ "$head" = "$(git -C "$root" rev-parse refs/remotes/origin/main)" ] || fail "local main is not exactly origin/main"
  fi
fi

echo "repository state: $mode checks passed"
