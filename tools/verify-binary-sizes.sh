#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
baseline=$root/tools/binary-size-baseline.tsv
output=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-tunnel-binary-size.XXXXXX")
trap 'rm -rf "$output"' EXIT HUP INT TERM

tab=$(printf '\t')
while IFS="$tab" read -r binary platform architecture baseline_bytes; do
  case "$binary" in ''|'#'*) continue ;; esac
  case "$baseline_bytes" in ''|*[!0-9]*)
    echo "invalid binary size baseline for $binary $platform/$architecture: $baseline_bytes" >&2
    exit 1
    ;;
  esac

  artifact=$output/$binary-$platform-$architecture
  case "$binary" in
    paperboat-tunnel)
      (
        cd "$root"
        CGO_ENABLED=0 GOOS=$platform GOARCH=$architecture GOTOOLCHAIN=local SOURCE_DATE_EPOCH=0 \
          go build -p=2 -buildvcs=false -trimpath -ldflags '-s -w' -o "$artifact" ./cmd/paperboat-tunnel
      )
      ;;
    frps)
      (
        cd "$root/frp"
        CGO_ENABLED=0 GOOS=$platform GOARCH=$architecture GOTOOLCHAIN=local SOURCE_DATE_EPOCH=0 \
          go build -p=2 -buildvcs=false -trimpath -ldflags '-s -w' -tags 'frps,noweb' -o "$artifact" ./cmd/frps
      )
      ;;
    *) echo "unknown binary in baseline: $binary" >&2; exit 1 ;;
  esac
  actual_bytes=$(wc -c < "$artifact" | tr -d ' ')
  growth_bytes=$((actual_bytes - baseline_bytes))
  if test "$growth_bytes" -gt 1048576 && \
    awk -v actual="$actual_bytes" -v baseline="$baseline_bytes" \
      'BEGIN { exit !((actual - baseline) * 100 > baseline * 5) }'; then
    echo "$binary $platform/$architecture grew from $baseline_bytes to $actual_bytes bytes" >&2
    echo "growth exceeds both 1 MiB and 5%; update the reviewed baseline with attribution" >&2
    exit 1
  fi
  printf '%s %s/%s: %s bytes\n' "$binary" "$platform" "$architecture" "$actual_bytes"
done < "$baseline"
