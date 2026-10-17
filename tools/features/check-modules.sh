#!/bin/sh
# check-modules.sh lists the modules the go-fs-light binary imports, for every
# platform it is released for, and fails on one that light-modules.txt does
# not allow. It reads the import graph, which is what go version -m and an
# SBOM report of the binary, not only what the linker keeps.
set -eu
cd "$(dirname "$0")/../.."
allowed=tools/features/light-modules.txt
status=0
for platform in linux/amd64 linux/arm64 windows/amd64; do
	found=$(GOOS=${platform%/*} GOARCH=${platform#*/} CGO_ENABLED=0 go list -deps -tags light \
		-f '{{if .Module}}{{if not .Module.Main}}{{.Module.Path}}{{end}}{{end}}' . | sort -u)
	for module in $found; do
		if ! grep -qxF "$module" "$allowed"; then
			echo "go-fs-light for $platform imports $module, which $allowed does not allow"
			status=1
		fi
	done
done
[ "$status" -eq 0 ] && echo "go-fs-light imports only the modules $allowed allows"
exit $status
