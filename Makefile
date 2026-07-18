GO_VERSION := 1.25.7
GO := GOTOOLCHAIN=local go
GOFMT := $(shell GOTOOLCHAIN=local go env GOROOT 2>/dev/null)/bin/gofmt
FRP_DIR := frp
FRP_VERSION := v0.70.0
FRP_COMMIT := 7b6e01f04f286632f0d23715aa17a3bc41234b5c
FRP_TAGS := noweb
OWNED_GO_FILES := $(shell find . -path ./frp -prune -o -name '*.go' -print)

.PHONY: build check clean fmt fmt-check generate race submodule-check test tidy verify-toolchain vet

verify-toolchain:
	@test "$$(GOTOOLCHAIN=local go env GOVERSION)" = "go$(GO_VERSION)" || { echo "required Go $(GO_VERSION), found $$(GOTOOLCHAIN=local go env GOVERSION)" >&2; exit 1; }

submodule-check:
	@test -f $(FRP_DIR)/go.mod || { echo "frp submodule is missing; run git submodule update --init --recursive" >&2; exit 1; }
	@test "$$(git -C $(FRP_DIR) rev-parse HEAD)" = "$(FRP_COMMIT)" || { echo "frp must be pinned to $(FRP_VERSION) ($(FRP_COMMIT))" >&2; exit 1; }
	@test -z "$$(git -C $(FRP_DIR) status --short)" || { echo "frp submodule has local changes" >&2; exit 1; }

build: verify-toolchain submodule-check
	@mkdir -p bin
	cd $(FRP_DIR) && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -tags "frps,$(FRP_TAGS)" -o ../bin/frps ./cmd/frps
	cd $(FRP_DIR) && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -tags "frpc,$(FRP_TAGS)" -o ../bin/frpc ./cmd/frpc

fmt:
	@if test -n "$(OWNED_GO_FILES)"; then $(GOFMT) -w $(OWNED_GO_FILES); fi

fmt-check:
	@if test -n "$(OWNED_GO_FILES)"; then test -z "$$($(GOFMT) -l $(OWNED_GO_FILES))" || { $(GOFMT) -l $(OWNED_GO_FILES); echo "Go files are not formatted" >&2; exit 1; }; fi

generate:
	@if test -n "$(OWNED_GO_FILES)"; then $(GO) generate ./...; fi

vet: submodule-check
	cd $(FRP_DIR) && $(GO) vet -tags "$(FRP_TAGS)" ./cmd/frps ./cmd/frpc ./client/... ./server/... ./pkg/...

test: submodule-check
	cd $(FRP_DIR) && $(GO) test -tags "$(FRP_TAGS)" ./assets/... ./cmd/... ./client/... ./server/... ./pkg/...

race: submodule-check
	cd $(FRP_DIR) && $(GO) test -race -tags "$(FRP_TAGS)" ./assets/... ./cmd/... ./client/... ./server/... ./pkg/...

tidy:
	$(GO) mod tidy

check: verify-toolchain submodule-check fmt-check vet test build

clean:
	rm -rf bin dist coverage.out
