#!/usr/bin/env bash
# make.sh builds the rpms the tests of internal/rpm and internal/repository
# read, with the nfpm the Makefile packages go-fs with. They are checked in, so
# the tests need neither; run it again only to change them:
#
#   internal/rpm/testdata/make.sh
#
# hello-1.0, -1.1 and -2.0 are unsigned, as a package built without a key is;
# hello-1.1 is also built signed with foreign.asc, a key that is not the
# repository's; tool-0.1 is a second package, with a file in a bin folder,
# a config file and dependencies, so the metadata has something of each.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
nfpm="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

printf '#!/bin/sh\necho hello\n' > "$work/hello"
printf 'setting = 1\n' > "$work/tool.conf"

package() { # name version config-extra output [key]
    local name=$1 version=$2 extra=$3 out=$4 key=${5:-}
    cat > "$work/nfpm.yaml" <<YAML
name: $name
arch: amd64
platform: linux
version: $version
release: 1
maintainer: go-fs tests
vendor: go-fs
homepage: https://example.com/$name
license: Apache-2.0
description: |
  A package the go-fs tests build a repository from.
$extra
YAML
    printf 'rpm:\n  summary: the %s test package\n' "$name" >> "$work/nfpm.yaml"
    if [ -n "$key" ]; then
        printf '  signature:\n    key_file: %s\n' "$key" >> "$work/nfpm.yaml"
    fi
    (cd "$work" && $nfpm package --config nfpm.yaml --packager rpm --target "$here/$out" >/dev/null)
}

hello='contents:
  - src: hello
    dst: /usr/share/hello/hello.sh
    file_info:
      mode: 0755'
tool='depends:
  - bash
  - /bin/sh
provides:
  - tool-api = 1
conflicts:
  - oldtool < 2
contents:
  - src: hello
    dst: /usr/bin/tool
    file_info:
      mode: 0755
  - src: tool.conf
    dst: /etc/tool.conf
    type: config|noreplace'

package hello 1.0 "$hello" hello-1.0-1.x86_64.rpm
package hello 1.1 "$hello" hello-1.1-1.x86_64.rpm
package hello 2.0 "$hello" hello-2.0-1.x86_64.rpm
package hello 1.1 "$hello" hello-1.1-1.foreign.x86_64.rpm "$here/foreign.asc"
package tool 0.1 "$tool" tool-0.1-1.x86_64.rpm
ls -l "$here"/*.rpm
