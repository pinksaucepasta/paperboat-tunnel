#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
snapshot=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-tunnel-analysis.XXXXXX")

cleanup() {
	status=$?
	for module in root caddy; do
		case "$module" in
		root) directory=$root ;;
		caddy) directory=$root/caddymodules/paperboatquic ;;
		esac
		if ! cmp -s "$directory/go.mod" "$snapshot/$module.go.mod" || ! cmp -s "$directory/go.sum" "$snapshot/$module.go.sum"; then
			echo "static analysis changed $directory/go.mod or go.sum" >&2
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
GOTOOLCHAIN=local go run honnef.co/go/tools/cmd/staticcheck@v0.8.0-rc.1 -checks='all,-ST1000,-ST1005' ./...
GOTOOLCHAIN=local go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./cmd/paperboat-tunnel ./internal/... ./tools/...

cd "$root/caddymodules/paperboatquic"
GOTOOLCHAIN=local go run honnef.co/go/tools/cmd/staticcheck@v0.8.0-rc.1 -checks='all,-ST1000,-ST1005' ./...
GOTOOLCHAIN=local go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./...
