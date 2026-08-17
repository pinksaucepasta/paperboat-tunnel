#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-tunnel-reproducible.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

build_set() {
  output_dir=$1
  mkdir -p "$output_dir"
  (
    cd "$root"
    CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local SOURCE_DATE_EPOCH=0 \
      go build -p=2 -buildvcs=false -trimpath -ldflags '-s -w' \
      -o "$output_dir/paperboat-tunnel" ./cmd/paperboat-tunnel
  )
  (
    cd "$root/frp"
    CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local SOURCE_DATE_EPOCH=0 \
      go build -p=2 -buildvcs=false -trimpath -ldflags '-s -w' -tags 'frps,noweb' \
      -o "$output_dir/frps" ./cmd/frps
  )
}

build_set "$work/first"
build_set "$work/second"

for first in "$work/first"/*; do
  name=${first##*/}
  cmp -s "$first" "$work/second/$name" || {
    echo "reproducible builds: $name differs between builds" >&2
    exit 1
  }
done

echo "reproducible builds: shipped tunnel Go artifacts are identical"
