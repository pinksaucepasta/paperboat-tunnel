#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 7 ]]; then
  echo "usage: $0 VERSION TUNNEL FRPS CADDY FAKE_CONTROL SBOM_TOOL OUTPUT" >&2
  exit 2
fi

version=$1
tunnel=$2
frps=$3
caddy=$4
fake_control=$5
sbom_tool=$6
output=$7
source_epoch=${SOURCE_DATE_EPOCH:-}
paperboat_commit=${PAPERBOAT_COMMIT:-}
frp_commit=${FRP_COMMIT:-}
go_version=${GO_VERSION:-}

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][a-zA-Z0-9._-]+)?$ ]] || [[ ! $source_epoch =~ ^[0-9]+$ ]]; then
  echo "VERSION and numeric SOURCE_DATE_EPOCH are required" >&2
  exit 2
fi
if [[ ! $paperboat_commit =~ ^[0-9a-f]{40}$ ]] || [[ ! $frp_commit =~ ^[0-9a-f]{40}$ ]] || [[ ! $go_version =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "PAPERBOAT_COMMIT, FRP_COMMIT, and GO_VERSION are required" >&2
  exit 2
fi
for command in sha256sum tar gzip date; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done
tar --version | head -1 | grep -q 'GNU tar' || { echo "GNU tar is required" >&2; exit 2; }
for file in "$tunnel" "$frps" "$caddy" "$fake_control" "$sbom_tool"; do
  [[ -f $file && -x $file ]] || { echo "missing executable: $file" >&2; exit 2; }
done

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
expected_frps=$(sed -n 's/.*"frps_sha256": "\([0-9a-f]\{64\}\)".*/\1/p' "$root/deploy/vps.deployment.json")
expected_caddy=$(sed -n 's/.*"caddy_sha256": "\([0-9a-f]\{64\}\)".*/\1/p' "$root/deploy/vps.deployment.json")
actual_frps=$(sha256sum "$frps" | cut -d' ' -f1)
actual_caddy=$(sha256sum "$caddy" | cut -d' ' -f1)
[[ $actual_frps == "$expected_frps" ]] || { echo "frps checksum does not match deployment config" >&2; exit 1; }
[[ $actual_caddy == "$expected_caddy" ]] || { echo "Caddy checksum does not match deployment config" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
release="$stage/paperboat-tunnel-$version"
mkdir -p "$release/bin" "$release/config" "$release/systemd" "$release/licenses"
install -m 0755 "$tunnel" "$release/bin/paperboat-tunnel"
install -m 0755 "$frps" "$release/bin/frps"
install -m 0755 "$caddy" "$release/bin/caddy"
install -m 0755 "$fake_control" "$release/bin/paperboat-fake-control"
install -m 0640 "$root/deploy/vps.deployment.json" "$release/config/deployment.json"
install -m 0640 "$root/deploy/fake-control.seed.json" "$release/config/fake-control.seed.json"
install -m 0644 "$root/deploy/paperboat-tunnel.service" "$release/systemd/paperboat-tunnel.service"
install -m 0644 "$root/deploy/paperboat-fake-control.service" "$release/systemd/paperboat-fake-control.service"
install -m 0644 "$root/LICENSE" "$release/licenses/paperboat-tunnel-MIT.txt"
install -m 0644 "$root/frp/LICENSE" "$release/licenses/frp-Apache-2.0.txt"
install -m 0644 "$root/frp/LICENSE" "$release/licenses/caddy-Apache-2.0.txt"
created=$(date -u -d "@$source_epoch" +%Y-%m-%dT%H:%M:%SZ)
"$sbom_tool" -tunnel "$tunnel" -frps "$frps" -caddy "$caddy" -fake-control "$fake_control" -created "$created" -output "$release/sbom.spdx.json"
printf '{\n  "version": "%s",\n  "created": "%s",\n  "paperboat_commit": "%s",\n  "frp_commit": "%s",\n  "go_version": "%s",\n  "caddy_version": "v2.11.4",\n  "platform": "linux/amd64",\n  "source_date_epoch": %s\n}\n' \
  "$version" "$created" "$paperboat_commit" "$frp_commit" "$go_version" "$source_epoch" >"$release/provenance.json"
(
  cd "$release"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
)
find "$release" -exec touch -h -d "@$source_epoch" {} +
mkdir -p "$(dirname "$output")"
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner --format=ustar -C "$stage" -cf - "$(basename "$release")" | gzip -n >"$output"
sha256sum "$output" >"$output.sha256"
