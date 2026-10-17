//go:build light

package selfupdate

import _ "embed"

// Product is the name of what this build is: go-fs-light, the same code built
// with the light tag and without the protocols it leaves out. It names the
// update files of a release and is what main shows next to the version.
const Product = "go-fs-light"

// keysFile holds the public keys go-fs-light trusts, one base64 key per line.
// It is compiled in, so nothing at runtime can add a key. The full product
// trusts the keys in keys.txt instead and the two sets share no key, so a
// light install refuses an update of the full product, and the reverse, as
// signed with an unknown key even though both publish into the same release.
//
//go:embed keys_light.txt
var keysFile string
