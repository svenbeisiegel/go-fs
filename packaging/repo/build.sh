#!/usr/bin/env bash
# build.sh builds the package repository served on GitHub Pages into OUT:
#
#   rpm/                an rpm-md repository for zypper and dnf, repomd.xml signed,
#                       with the packages of go-fs and go-fs-light
#   rpm/go-fs.repo      the repository definition zypper and dnf add
#   go-fs.asc           the public key, armored
#
# It is rebuilt whole from the rpm assets of the KEEP newest GitHub releases,
# so older versions drop out as new ones are released. An rpm that is not
# signed with the key, as those of the releases before the repository existed,
# is left out: zypper and dnf would refuse it.
#
# Needs gh (GH_TOKEN), createrepo_c, rpmkeys and gpg with the signing key
# imported: GPG_KEY_ID names it, GPG_PASSPHRASE unlocks it if it has one.
# REPO_URL is where the site is served, by default the repository's Pages URL.
set -euo pipefail

out=${1:?usage: build.sh OUT}
keep=${KEEP:-5}
key=${GPG_KEY_ID:?GPG_KEY_ID names the signing key}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is owner/name}
owner=${repo%%/*}
url=${REPO_URL:-https://${owner,,}.github.io/${repo#*/}}

sign() {
    gpg --batch --yes --local-user "$key" --pinentry-mode loopback \
        --passphrase-fd 0 "$@" <<<"${GPG_PASSPHRASE:-}"
}

rm -rf "$out"
mkdir -p "$out/rpm" "$out/download"

gpg --armor --export "$key" > "$out/go-fs.asc"

tags=$(gh release list --repo "$repo" --exclude-drafts --exclude-pre-releases \
    --limit "$keep" --json tagName --jq '.[].tagName')
[ -n "$tags" ] || { echo "no releases to publish" >&2; exit 1; }
for tag in $tags; do
    echo "adding $tag"
    gh release download "$tag" --repo "$repo" --dir "$out/download" \
        --pattern '*.rpm' || echo "$tag has no packages"
done

# the signatures are checked against the key alone, in a keyring of its own
rpmdb=$(mktemp -d)
trap 'rm -rf "$rpmdb"' EXIT
rpmkeys --dbpath "$rpmdb" --import "$out/go-fs.asc"
shopt -s nullglob
count=0
for rpm in "$out"/download/*.rpm; do
    # an unsigned rpm passes too, on its digests alone; a signed one says so
    if result=$(rpmkeys --dbpath "$rpmdb" --checksig "$rpm" 2>&1) &&
        grep -qE 'signatures OK|pgp' <<<"$result"; then
        mv "$rpm" "$out/rpm/"
        count=$((count + 1))
    else
        echo "leaving out $(basename "$rpm"), it is not signed with the key"
    fi
done
rm -rf "$out/download"
[ "$count" -gt 0 ] || { echo "no signed packages to publish" >&2; exit 1; }

# rpm-md, for zypper and dnf
createrepo_c "$out/rpm"
sign --armor --detach-sign --output "$out/rpm/repodata/repomd.xml.asc" "$out/rpm/repodata/repomd.xml"
# zypper also looks for the key beside repomd.xml
cp "$out/go-fs.asc" "$out/rpm/repodata/repomd.xml.key"
cat > "$out/rpm/go-fs.repo" <<EOF
[go-fs]
name=go-fs
baseurl=$url/rpm
type=rpm-md
enabled=1
autorefresh=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$url/go-fs.asc
EOF

cat > "$out/index.html" <<EOF
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>go-fs packages</title>
<style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5}pre{background:#f4f4f4;padding:.75rem;overflow-x:auto}</style>
<h1>go-fs packages</h1>
<p>Signed with <a href="go-fs.asc">this key</a>. The $keep newest releases are kept.</p>
<p>The repository has two packages, which exclude each other: go-fs with every
protocol, and go-fs-light with HTTP, HTTPS, the S3 API and the container
registry alone. Install go-fs-light in place of go-fs below for the light one.</p>
<h2>openSUSE and SLES</h2>
<pre>sudo zypper addrepo $url/rpm/go-fs.repo
sudo zypper refresh &amp;&amp; sudo zypper install go-fs
sudo zypper update go-fs</pre>
<h2>Fedora, RHEL and Rocky Linux</h2>
<pre>sudo dnf config-manager addrepo --from-repofile=$url/rpm/go-fs.repo
sudo dnf install go-fs</pre>
<h2>Windows</h2>
<p>The msi of go-fs or go-fs-light of the <a href="https://github.com/$repo/releases/latest">latest release</a>.
Once installed, go-fs updates itself from the releases in its admin interface.</p>
<p>Source: <a href="https://github.com/$repo">github.com/$repo</a></p>
</html>
EOF

echo "built $out: $count rpm packages from $(echo $tags | wc -w) releases"
