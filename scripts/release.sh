#!/usr/bin/env bash
# Builds a macOS release into dist/:
#
#   npssh-<version>-darwin-universal.tar.gz   universal (arm64 + x86_64) binary, ad-hoc signed
#   npssh.rb                                  Homebrew formula pointing at that tarball
#
# Usage: scripts/release.sh <version>      e.g. scripts/release.sh 0.1.0
# The formula's URL assumes the tarball is attached to GitHub release v<version>
# of $GITHUB_REPOSITORY (default matjaz/npssh).
set -euo pipefail

version="${1:?usage: scripts/release.sh <version>}"
version="${version#v}"
repo="${GITHUB_REPOSITORY:-matjaz/npssh}"
cd "$(dirname "$0")/.."

# Without this, clang targets the build machine's macOS and the binary
# refuses to start on older systems. 11.0 is Go 1.24's own minimum. The flags
# go in CGO_CFLAGS/LDFLAGS too: those are part of Go's build-cache key, so
# cgo objects cached from a plain `go build` aren't reused.
min=11.0
export MACOSX_DEPLOYMENT_TARGET=$min
export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -g -mmacosx-version-min=$min"
export CGO_LDFLAGS="-mmacosx-version-min=$min"

rm -rf dist
mkdir -p dist/build
for arch in arm64 amd64; do
  GOOS=darwin GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$version" \
    -o "dist/build/npssh-$arch" .
done
lipo -create -output dist/build/npssh dist/build/npssh-arm64 dist/build/npssh-amd64
codesign --force --sign - dist/build/npssh # lipo output needs a fresh ad-hoc signature

tarball="npssh-$version-darwin-universal.tar.gz"
tar -C dist/build -czf "dist/$tarball" npssh
sha256="$(shasum -a 256 "dist/$tarball" | cut -d' ' -f1)"

cat > dist/npssh.rb <<EOF
class Npssh < Formula
  desc "SSH agent with keys in NordPass and Touch ID for every signature"
  homepage "https://github.com/$repo"
  url "https://github.com/$repo/releases/download/v$version/$tarball"
  version "$version"
  sha256 "$sha256"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on :macos

  def install
    bin.install "npssh"
  end

  def caveats
    <<~EOS
      npssh needs the NordPass CLI:
        brew tap nordpass/tap https://downloads.npass.app/cli/homebrew-tap.git
        brew install nordpass/tap/np && np signin

      Start the agent (launchd) and follow the setup it prints:
        npssh install

      After \`brew upgrade npssh\`, run \`npssh install\` again so the agent
      restarts on the new version, then \`npssh load\`.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/npssh version")
  end
end
EOF

echo "dist/$tarball  sha256 $sha256"
echo "dist/npssh.rb"
