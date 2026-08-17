#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

require_module() {
  module=$1
  path=$2
  version=$3
  actual=$(cd "$module" && GOTOOLCHAIN=local go list -m -f '{{.Version}}' "$path")
  [ "$actual" = "$version" ] || {
    echo "dependency mismatch in $module: $path is $actual, want $version" >&2
    exit 1
  }
}

require_module "$root" github.com/pion/ice/v4 v4.4.0
require_module "$root" github.com/pion/stun/v3 v3.1.6
require_module "$root" github.com/pion/transport/v4 v4.0.2
require_module "$root" github.com/realclientip/realclientip-go v1.0.0
require_module "$root" golang.org/x/crypto v0.54.0
require_module "$root/caddymodules/paperboatquic" github.com/quic-go/quic-go v0.61.0
require_module "$root/caddymodules/paperboatquic" golang.org/x/crypto v0.54.0
require_module "$root/frp" github.com/quic-go/quic-go v0.61.0
require_module "$root/frp" golang.org/x/crypto v0.54.0

if (cd "$root" && rg -n --glob '*.go' -g '!frp/**' 'github\.com/gorilla/websocket' .); then
  echo "owned tunnel source imports forbidden Gorilla WebSocket" >&2
  exit 1
fi

for module in "$root" "$root/caddymodules/paperboatquic"; do
  if (cd "$module" && GOTOOLCHAIN=local go list -deps -test ./...) | grep -q '^github.com/gorilla/websocket$'; then
    echo "Gorilla WebSocket entered an owned compiled graph: $module" >&2
    exit 1
  fi
done

echo "tunnel dependencies: valid"
