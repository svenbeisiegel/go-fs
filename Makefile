BINARY  := go-fs
DIST    := dist

# The documented starter configuration, shipped next to the binaries under the
# name the binary looks for when -config is not given. This is the same file
# the binary embeds and -init writes, so what ships always matches the build.
TEMPLATE := internal/config/template.toml

# VERSION is the released version and lives in ./VERSION so it is bumped in one
# place. Override it on the command line for a one off build, e.g. from CI:
#   make release VERSION=1.0
VERSION     ?= $(strip $(shell cat $(CURDIR)/VERSION))
STAMP       := $(shell date +%Y%m%d-%H%M%S)
DEV_VERSION := $(VERSION)-dev-$(STAMP)

# CGO_ENABLED=0 selects the pure Go resolver and links nothing from the host.
# On Linux and Windows the result is a fully static binary; on macOS it still
# links libSystem, which is what a static build means there.
GOFLAGS  := -trimpath
BUILDENV := CGO_ENABLED=0

# {linux,windows} x {amd64,arm64} plus darwin/arm64 (Apple silicon)
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/arm64

# crosscompile builds every platform in PLATFORMS at the version passed in.
# build and release differ only in that version.
define crosscompile
	@mkdir -p $(DIST)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		out=$(DIST)/$(BINARY)_$(1)_$${os}_$${arch}; \
		if [ "$$os" = "windows" ]; then out=$$out.exe; fi; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch $(BUILDENV) go build $(GOFLAGS) \
			-ldflags "-s -w -X main.version=$(1)" -o $$out . || exit 1; \
	done
	@cp $(TEMPLATE) $(DIST)/$(BINARY).toml
	@echo "copied $(DIST)/$(BINARY).toml"
	@$(MAKE) --no-print-directory checksums
endef

.PHONY: all build test race vet fmt lint clean release checksums version

all: vet test build

# build produces the same set of binaries as release, stamped with the dev
# version so a local build always says when it was made.
build: clean
	$(call crosscompile,$(DEV_VERSION))

test:
	go test ./... -count=1

race:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt found unformatted files:"; gofmt -l .; exit 1)

version:
	@echo $(VERSION)

clean:
	rm -rf $(DIST) $(BINARY)

# release cross compiles every supported platform at the released version and
# writes the checksums.
release: clean
	$(call crosscompile,$(VERSION))

checksums:
	@cd $(DIST) && (sha256sum * > SHA256SUMS 2>/dev/null || shasum -a 256 * > SHA256SUMS)
	@echo "wrote $(DIST)/SHA256SUMS"
