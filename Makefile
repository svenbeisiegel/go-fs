BINARY  := go-fs
DIST    := dist

# go-fs-light is the second product built from the same code: the build tags
# in LIGHT_TAGS leave out every protocol but HTTP, HTTPS, the S3 API and the
# container registry. Its files are named after it, its updates are signed
# with a key of their own, and it installs to the same paths as go-fs.
LIGHT      := $(BINARY)-light
LIGHT_TAGS := light

# The documented starter configuration, the same file the binary embeds and
# -init writes; the installers ship it adjusted to their platform.
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

# the platforms a release has a package for: the rpm on linux, the msi on
# windows/amd64
PLATFORMS := linux/amd64 linux/arm64 windows/amd64

# tags prints the go build flag for the product named in the shell variable
# product: the light tags for go-fs-light, nothing for go-fs.
tags = $$(if [ "$$product" = "$(LIGHT)" ]; then echo "-tags $(LIGHT_TAGS)"; fi)

# crosscompile builds both products for every platform in PLATFORMS at the
# version passed in. build and release differ only in that version. The
# Windows binary is the one the msi installs, stamped as such, so that its
# .update keeps an msi install an msi install.
define crosscompile
	@mkdir -p $(DIST)
	@for product in $(BINARY) $(LIGHT); do \
		for platform in $(PLATFORMS); do \
			os=$${platform%/*}; arch=$${platform#*/}; \
			out=$(DIST)/$${product}_$(1)_$${os}_$${arch}; stamp=; \
			if [ "$$os" = "windows" ]; then out=$$out.exe; stamp="-X main.packaging=msi"; fi; \
			echo "building $$out"; \
			GOOS=$$os GOARCH=$$arch $(BUILDENV) go build $(GOFLAGS) $(tags) \
				-ldflags "-s -w -X main.version=$(1) $$stamp" -o $$out . || exit 1; \
		done; \
	done
	@$(MAKE) --no-print-directory checksums
endef

# The installers ship binaries of their own, stamped with the installer that
# owns them so that they leave updating to it, and a configuration that serves
# from a folder of the platform. They are built into PKG; the packages
# themselves land in DIST beside the release binaries.
PKG  := build/pkg
NFPM := go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0
# the basefolder line of the template, and what it says for each installer
TEMPLATE_BASEFOLDER := basefolder = "/srv/files"
LINUX_BASEFOLDER    := basefolder = "/var/lib/go-fs/files"
WINDOWS_BASEFOLDER  := basefolder = "C:/ProgramData/go-fs/files"
# the registryBaseFolder line of the template, and what it says for each
# installer: the folder registry beside the served folder
TEMPLATE_REGISTRY := registryBaseFolder = ""
LINUX_REGISTRY    := registryBaseFolder = "/var/lib/go-fs/registry"
WINDOWS_REGISTRY  := registryBaseFolder = "C:/ProgramData/go-fs/registry"

.PHONY: all build test race cover fuzz vet fmt lint clean release sign checksums version \
	packages rpm msi-inputs

all: vet test build

# build produces the same set of binaries as release, stamped with the dev
# version so a local build always says when it was made.
build: clean
	$(call crosscompile,$(DEV_VERSION))

test:
	go test ./... -count=1

race:
	go test ./... -race -count=1

# cover is race with a coverage profile, whose total is printed last.
cover:
	go test ./... -race -count=1 -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

# fuzz runs every Fuzz target in the module for FUZZTIME each. go test takes
# one target per run, so they are found and run one after the other. Their
# seed corpora already run as part of test.
FUZZTIME ?= 20s
fuzz:
	@set -e; for file in $$(grep -rl --include='*_test.go' '^func Fuzz' .); do \
		dir=./$$(dirname $${file#./}); \
		for fn in $$(grep -oE '^func Fuzz[A-Za-z0-9_]+' $$file | cut -d' ' -f2); do \
			echo "fuzzing $$dir $$fn for $(FUZZTIME)"; \
			go test $$dir -run '^$$' -fuzz "^$$fn\$$" -fuzztime $(FUZZTIME); \
		done; \
	done

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt found unformatted files:"; gofmt -l .; exit 1)

version:
	@echo $(VERSION)

clean:
	rm -rf $(DIST) build $(BINARY) coverage.out

# release cross compiles every supported platform at the released version.
# With the private keys in GOFS_SIGNING_KEY and GOFS_LIGHT_SIGNING_KEY it
# writes the signed .update files and keeps only those: a release ships
# packages and updates, not the plain binaries. Without the keys the binaries
# stay; the release workflow insists on both.
release: clean
	$(call crosscompile,$(VERSION))
	@if [ -n "$$GOFS_SIGNING_KEY" ] && [ -n "$$GOFS_LIGHT_SIGNING_KEY" ]; then \
		$(MAKE) --no-print-directory sign; \
		for bin in $(DIST)/$(BINARY)_* $(DIST)/$(LIGHT)_*; do \
			case $$bin in *.update) ;; *) rm -f $$bin;; esac; \
		done; \
		$(MAKE) --no-print-directory checksums; \
	else \
		echo "GOFS_SIGNING_KEY or GOFS_LIGHT_SIGNING_KEY is not set, no .update files were written"; \
	fi

# sign appends the update signature to every binary in dist, writing the
# .update file go-fs accepts over HTTP next to each one, and rewrites the
# checksums to cover them. The private key of go-fs is read from
# GOFS_SIGNING_KEY, that of go-fs-light from GOFS_LIGHT_SIGNING_KEY; the sign
# tool reads GOFS_SIGNING_KEY alone, so it is handed the one that fits.
sign:
	@test -n "$$GOFS_SIGNING_KEY" || (echo "GOFS_SIGNING_KEY is not set"; exit 1)
	@test -n "$$GOFS_LIGHT_SIGNING_KEY" || (echo "GOFS_LIGHT_SIGNING_KEY is not set"; exit 1)
	@for bin in $(DIST)/$(BINARY)_* $(DIST)/$(LIGHT)_*; do \
		case $$bin in *.update) continue;; esac; \
		key=$$GOFS_SIGNING_KEY; \
		case $$bin in $(DIST)/$(LIGHT)_*) key=$$GOFS_LIGHT_SIGNING_KEY;; esac; \
		GOFS_SIGNING_KEY=$$key go run ./tools/sign -in $$bin -out $$bin.update || exit 1; \
	done
	@$(MAKE) --no-print-directory checksums

checksums:
	@cd $(DIST) && (sha256sum * > SHA256SUMS 2>/dev/null || shasum -a 256 * > SHA256SUMS)
	@echo "wrote $(DIST)/SHA256SUMS"

# packages builds what the installers need at the released version: the rpm
# packages into DIST, and the binaries and configuration the msi is made of,
# which only the WiX Toolset on Windows can build, into PKG. It runs after
# release, which empties DIST, and writes the checksums again.
packages: rpm msi-inputs
	@$(MAKE) --no-print-directory checksums

# installerconfig writes the template with its basefolder line replaced by
# the first argument and its registryBaseFolder line by the third, and fails
# when the template no longer has those lines to replace.
define installerconfig
	@mkdir -p $(dir $(2))
	@grep -qxF '$(TEMPLATE_BASEFOLDER)' $(TEMPLATE) || \
		(echo "$(TEMPLATE) has no line $(TEMPLATE_BASEFOLDER)"; exit 1)
	@grep -qxF '$(TEMPLATE_REGISTRY)' $(TEMPLATE) || \
		(echo "$(TEMPLATE) has no line $(TEMPLATE_REGISTRY)"; exit 1)
	@sed -e 's|^$(TEMPLATE_BASEFOLDER)$$|$(1)|' \
		-e 's|^$(TEMPLATE_REGISTRY)$$|$(3)|' $(TEMPLATE) > $(2)
	@echo "wrote $(2)"
endef

# what the rpm of each product serves, the first line of its description and
# so its summary
RPM_SERVES       := FTP, FTPS, SFTP, HTTP, HTTPS, an S3 compatible API and TFTP
RPM_LIGHT_SERVES := HTTP, HTTPS, an S3 compatible API and an OCI registry

# nfpm takes its files from fixed paths, see packaging/linux/nfpm.yaml, so the
# products and architectures are packaged one after the other. Both products
# are packaged from that one file, told apart by NAME, CONFLICTS and SERVES,
# and conflict with each other: they install the same files. With
# SIGNING_KEY_FILE naming an armored PGP private key, and NFPM_RPM_PASSPHRASE
# unlocking it, the rpms are signed, as the package repository needs them to be.
rpm:
	$(call installerconfig,$(LINUX_BASEFOLDER),$(PKG)/linux/go-fs.toml,$(LINUX_REGISTRY))
	@mkdir -p $(DIST)
	@for product in $(BINARY) $(LIGHT); do \
		if [ "$$product" = "$(LIGHT)" ]; then \
			conflicts=$(BINARY); serves="$(RPM_LIGHT_SERVES)"; \
		else \
			conflicts=$(LIGHT); serves="$(RPM_SERVES)"; \
		fi; \
		for arch in amd64 arm64; do \
			echo "building $(PKG)/linux/$(BINARY) of $$product for $$arch"; \
			GOOS=linux GOARCH=$$arch $(BUILDENV) go build $(GOFLAGS) $(tags) \
				-ldflags "-s -w -X main.version=$(VERSION) -X main.packaging=rpm" \
				-o $(PKG)/linux/$(BINARY) . || exit 1; \
			NAME=$$product CONFLICTS=$$conflicts SERVES="$$serves" \
			VERSION=$(VERSION) ARCH=$$arch $(NFPM) package --config packaging/linux/nfpm.yaml \
				--packager rpm --target $(DIST)/ || exit 1; \
		done; \
	done

# both msi install the same configuration, each its own product's binary
msi-inputs:
	$(call installerconfig,$(WINDOWS_BASEFOLDER),$(PKG)/go-fs.windows.toml,$(WINDOWS_REGISTRY))
	@for product in $(BINARY) $(LIGHT); do \
		for arch in amd64; do \
			bin=$(PKG)/$${product}_windows_$$arch.exe; \
			echo "building $$bin"; \
			GOOS=windows GOARCH=$$arch $(BUILDENV) go build $(GOFLAGS) $(tags) \
				-ldflags "-s -w -X main.version=$(VERSION) -X main.packaging=msi" -o $$bin . || exit 1; \
		done; \
	done
