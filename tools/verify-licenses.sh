#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-tunnel-license.XXXXXX")

cleanup() {
	status=$?
	for module in root caddy; do
		case "$module" in
		root) directory=$root ;;
		caddy) directory=$root/caddymodules/paperboatquic ;;
		esac
		if ! cmp -s "$directory/go.mod" "$snapshot/$module.go.mod" || ! cmp -s "$directory/go.sum" "$snapshot/$module.go.sum"; then
			echo "license analysis changed $directory/go.mod or go.sum" >&2
			status=1
		fi
	done
	rm -rf "$snapshot"
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

cp "$root/go.mod" "$snapshot/root.go.mod"
cp "$root/go.sum" "$snapshot/root.go.sum"
cp "$root/caddymodules/paperboatquic/go.mod" "$snapshot/caddy.go.mod"
cp "$root/caddymodules/paperboatquic/go.sum" "$snapshot/caddy.go.sum"

cd "$root"
GOTOOLCHAIN=local go run github.com/google/go-licenses@v1.6.0 check \
	--disallowed_types=forbidden,restricted,unknown \
	./cmd/paperboat-tunnel

cd "$root/caddymodules/paperboatquic"
GOTOOLCHAIN=local go run github.com/google/go-licenses@v1.6.0 check \
	--disallowed_types=forbidden,restricted,unknown \
	--ignore=github.com/pinksaucepasta/paperboat-tunnel/caddymodules/paperboatquic \
	./...
