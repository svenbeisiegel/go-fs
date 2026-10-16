#!/usr/bin/env bash
# import-key.sh imports the PGP private key in PACKAGE_SIGNING_KEY into gpg and
# appends GPG_KEY_ID, its fingerprint, to GITHUB_ENV when that is set. With a
# file argument it also writes the key there armored, the form nfpm reads.
#
# The secret may be the armored key (-----BEGIN PGP PRIVATE KEY BLOCK-----),
# with CRLF line ends or with its line breaks written as \n, the same base64
# encoded, or a binary export base64 encoded. PACKAGE_SIGNING_PASSPHRASE
# unlocks it if it has one. Nothing of the key is ever printed.
set -euo pipefail

: "${PACKAGE_SIGNING_KEY:?the PACKAGE_SIGNING_KEY secret is not set}"
out=${1:-}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

printf '%s\n' "$PACKAGE_SIGNING_KEY" | tr -d '\r' > "$tmp/key"
begin='-----BEGIN PGP PRIVATE KEY BLOCK-----'
if ! grep -q -- "$begin" "$tmp/key"; then
    if base64 -d "$tmp/key" > "$tmp/decoded" 2>/dev/null && [ -s "$tmp/decoded" ]; then
        tr -d '\r' < "$tmp/decoded" > "$tmp/key"
    fi
fi
# a key pasted as one line with literal \n between the lines
if [ "$(wc -l < "$tmp/key")" -le 1 ] && grep -qF -- '\n' "$tmp/key"; then
    sed -i 's/\\n/\n/g' "$tmp/key"
fi

describe() {
    echo "PACKAGE_SIGNING_KEY: $(wc -c < "$tmp/key") bytes, $(wc -l < "$tmp/key") lines" >&2
    grep -q -- "$begin" "$tmp/key" && echo "  has the BEGIN PGP PRIVATE KEY BLOCK line" >&2 || echo "  has no BEGIN PGP PRIVATE KEY BLOCK line" >&2
    grep -q -- '-----END PGP PRIVATE KEY BLOCK-----' "$tmp/key" && echo "  has the END line" >&2 || echo "  has no END line" >&2
    grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "$tmp/key" && echo "  holds a PUBLIC key block: the secret must be the private key" >&2
    true
}

if ! gpg --batch --import "$tmp/key" 2>"$tmp/import.log"; then
    sed 's/^/  gpg: /' "$tmp/import.log" >&2
    echo "PACKAGE_SIGNING_KEY could not be imported; it should be the output of gpg --armor --export-secret-keys <key id>" >&2
    describe
    exit 1
fi
fpr=$(gpg --list-secret-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }')
if [ -z "$fpr" ]; then
    echo "PACKAGE_SIGNING_KEY holds no private key" >&2
    describe
    exit 1
fi
echo "imported signing key $fpr"
[ -n "${GITHUB_ENV:-}" ] && echo "GPG_KEY_ID=$fpr" >> "$GITHUB_ENV"

if [ -n "$out" ]; then
    gpg --batch --pinentry-mode loopback --passphrase-fd 0 --armor \
        --export-secret-keys "$fpr" > "$out" <<<"${PACKAGE_SIGNING_PASSPHRASE:-}"
    chmod 600 "$out"
fi
