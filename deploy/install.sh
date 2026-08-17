#!/bin/sh
set -eu

usage() {
  echo "usage: install.sh --image REPO@sha256:DIGEST --node-id ID --connector-pool POOL --relay-id ID --relay-region REGION --relay-name NAME --deployment-config FILE --secrets-dir DIR [--target-dir DIR] [--verify-only]" >&2
  exit 64
}

image= node_id= connector_pool= relay_id= relay_region= relay_name= deployment_config= secrets_dir=
target_dir=/opt/paperboat-tunnel
verify_only=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --image) image=${2-}; shift 2 ;;
    --node-id) node_id=${2-}; shift 2 ;;
    --connector-pool) connector_pool=${2-}; shift 2 ;;
    --relay-id) relay_id=${2-}; shift 2 ;;
    --relay-region) relay_region=${2-}; shift 2 ;;
    --relay-name) relay_name=${2-}; shift 2 ;;
    --deployment-config) deployment_config=${2-}; shift 2 ;;
    --secrets-dir) secrets_dir=${2-}; shift 2 ;;
    --target-dir) target_dir=${2-}; shift 2 ;;
    --verify-only) verify_only=true; shift ;;
    *) usage ;;
  esac
done

case "$image" in *@sha256:????????????????????????????????????????????????????????????????) ;; *) usage ;; esac
valid_id() { case "$1" in ''|*[!a-z0-9_-]*|[-_]*) return 1 ;; esac; }
valid_id "$node_id" && valid_id "$connector_pool" && valid_id "$relay_id" && valid_id "$relay_region" || usage
[ -n "$relay_name" ] && [ "${#relay_name}" -le 80 ] || usage
[ -f "$deployment_config" ] && [ -d "$secrets_dir" ] || usage
case "$target_dir" in /*) ;; *) usage ;; esac
[ "$target_dir" != / ] || usage
[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root" >&2; exit 77; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 69; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose is required" >&2; exit 69; }

compose() { docker compose --project-directory "$target_dir" -f "$target_dir/docker-compose.yml" "$@"; }
verify() {
  compose ps --status running tunnel | grep -q tunnel || return 1
  container=$(compose ps -q tunnel)
  [ -n "$container" ] || return 1
  [ "$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}')" = healthy ]
}

if [ "$verify_only" = true ]; then
  verify || { echo "relay verification failed" >&2; exit 1; }
  echo "relay is healthy"
  exit 0
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
stage=$(mktemp -d "${target_dir}.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
install -m 644 "$script_dir/docker-compose.yml" "$stage/docker-compose.yml"
install -m 644 "$deployment_config" "$stage/deployment.json"
install -d -m 500 "$stage/secrets"
for secret in control_credential jwks.json revocations.json usage.key; do
  [ -f "$secrets_dir/$secret" ] || { echo "missing secret: $secrets_dir/$secret" >&2; exit 66; }
  install -m 400 "$secrets_dir/$secret" "$stage/secrets/$secret"
done
{
  printf 'PAPERBOAT_TUNNEL_IMAGE=%s\n' "$image"
  printf 'PAPERBOAT_TUNNEL_NODE_ID=%s\n' "$node_id"
  printf 'PAPERBOAT_TUNNEL_EDGE_POOL=%s\n' "$connector_pool"
  printf 'PAPERBOAT_TUNNEL_RELAY_ID=%s\n' "$relay_id"
  printf 'PAPERBOAT_TUNNEL_RELAY_REGION=%s\n' "$relay_region"
  printf 'PAPERBOAT_TUNNEL_RELAY_NAME=%s\n' "$relay_name"
} >"$stage/.env"
chmod 600 "$stage/.env"

if [ -d "$target_dir" ]; then
  backup="${target_dir}.previous.$(date -u +%Y%m%dT%H%M%SZ)"
  cp -a "$target_dir" "$backup"
fi
install -d -m 755 "$target_dir"
cp -a "$stage/." "$target_dir/"
chown -R 999:999 "$target_dir/secrets"
chmod 500 "$target_dir/secrets"
compose config --quiet
compose pull tunnel
compose up -d tunnel

attempt=0
while [ "$attempt" -lt 24 ]; do
  if verify; then
    echo "relay $relay_id is healthy in region $relay_region"
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 5
done
compose logs --tail 100 tunnel >&2 || true
echo "relay failed health verification; previous deployment remains at ${target_dir}.previous" >&2
exit 1
