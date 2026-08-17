GO_VERSION := 1.26.6
GO := GOTOOLCHAIN=local go
GOFMT := $(shell GOTOOLCHAIN=local go env GOROOT 2>/dev/null)/bin/gofmt
FRP_DIR := frp
CADDY_MODULE_DIR := caddymodules/paperboatquic
FRP_VERSION := v0.70.1
FRP_COMMIT := 028f085af3c787d7c0c77cd58f133ca8aed7ee75
FRP_TAGS := noweb
BUILD_FLAGS := -trimpath -buildvcs=false
OWNED_GO_FILES := $(shell find . -path ./frp -prune -o -name '*.go' -print)

.PHONY: binary-size-check build caddy-module-test check clean contracts dependencies fmt fmt-check generate license-check maintenance-check metrics-check metrics-generate race release-check reproducible-builds source-policy static-analysis submodule-check test tidy verification verify-toolchain vet vulnerability-check

contracts:
	@./testdata/contracts/validate.sh

dependencies: submodule-check
	@./tools/verify-dependencies.sh

source-policy:
	@./tools/verify-source-policy.sh

metrics-generate:
	$(GO) run ./tools/metric-schema -write docs/metrics.json

metrics-check:
	$(GO) run ./tools/metric-schema docs/metrics.json

maintenance-check:
	@./tools/verify-repository-state.sh $(if $(CI),ci,development)

release-check:
	@./tools/verify-repository-state.sh release

verify-toolchain:
	@test "$$(GOTOOLCHAIN=local go env GOVERSION)" = "go$(GO_VERSION)" || { echo "required Go $(GO_VERSION), found $$(GOTOOLCHAIN=local go env GOVERSION)" >&2; exit 1; }

submodule-check:
	@test -f $(FRP_DIR)/go.mod || { echo "frp submodule is missing; run git submodule update --init --recursive" >&2; exit 1; }
	@test "$$(git -C $(FRP_DIR) rev-parse HEAD)" = "$(FRP_COMMIT)" || { echo "frp must be pinned to $(FRP_VERSION) ($(FRP_COMMIT))" >&2; exit 1; }
	@test -z "$$(git -C $(FRP_DIR) status --short)" || { echo "frp submodule has local changes" >&2; exit 1; }

build: verify-toolchain submodule-check
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o bin/paperboat-tunnel ./cmd/paperboat-tunnel
	cd $(FRP_DIR) && CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -ldflags "-s -w" -tags "frps,$(FRP_TAGS)" -o ../bin/frps ./cmd/frps
	cd $(FRP_DIR) && CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -ldflags "-s -w" -tags "frpc,$(FRP_TAGS)" -o ../bin/frpc ./cmd/frpc

fmt:
	@if test -n "$(OWNED_GO_FILES)"; then $(GOFMT) -w $(OWNED_GO_FILES); fi

fmt-check:
	@if test -n "$(OWNED_GO_FILES)"; then test -z "$$($(GOFMT) -l $(OWNED_GO_FILES))" || { $(GOFMT) -l $(OWNED_GO_FILES); echo "Go files are not formatted" >&2; exit 1; }; fi

generate:
	@if test -n "$(OWNED_GO_FILES)"; then $(GO) generate ./...; fi

vet: submodule-check
	$(GO) vet ./...
	cd $(FRP_DIR) && $(GO) vet -tags "$(FRP_TAGS)" ./cmd/frps ./cmd/frpc ./client/... ./server/... ./pkg/...

test: submodule-check
	$(GO) test ./...
	cd $(FRP_DIR) && $(GO) test -tags "$(FRP_TAGS)" ./assets/... ./cmd/... ./client/... ./server/... ./pkg/...

caddy-module-test:
	cd $(CADDY_MODULE_DIR) && $(GO) test ./...

race: build
	$(GO) test -race ./...
	cd $(FRP_DIR) && $(GO) test -race -tags "$(FRP_TAGS)" ./assets/... ./cmd/... ./client/... ./server/... ./pkg/...

reproducible-builds: verify-toolchain submodule-check
	@./tools/verify-reproducible-builds.sh

binary-size-check: verify-toolchain submodule-check
	@./tools/verify-binary-sizes.sh

static-analysis: verify-toolchain source-policy
	@./tools/verify-static-analysis.sh

vulnerability-check: verify-toolchain
	@./tools/verify-vulnerabilities.sh

license-check: verify-toolchain
	@./tools/verify-licenses.sh

verification: check race static-analysis vulnerability-check license-check

tidy:
	$(GO) mod tidy

check: maintenance-check verify-toolchain contracts dependencies source-policy metrics-check fmt-check vet test caddy-module-test build

clean:
	rm -rf bin dist coverage.out
