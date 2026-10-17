//go:build !light

package selfupdate

import _ "embed"

// Product is the name of what this build is: go-fs, the full server with every
// protocol it can be built with. It names the update files of a release and is
// what main shows next to the version.
const Product = "go-fs"

// keysFile holds the public keys the full product trusts, one base64 key per
// line. It is compiled in, so nothing at runtime — not the configuration file,
// not the admin interface — can add a key. go-fs-light trusts a different set
// from keys_light.txt, which is what keeps one product from ever installing an
// update of the other: both publish into the same release, and a file signed
// with the other product's key is refused as signed with an unknown key.
//
//go:embed keys.txt
var keysFile string
