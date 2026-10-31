#!/usr/bin/env bash
# Builds the release archives for one version: whichphp for Linux, macOS and Windows on
# amd64 and arm64, each packed with LICENSE and README.md, plus SHA256SUMS.
#
#   scripts/build-release.sh v0.1.0 dist
#
# The release workflow runs it on a tag, and CI runs it on every change so a broken
# cross-compile or archive shows up before tagging. Archives are reproducible for a
# given Go version: file order, timestamps (the commit time), modes and owners are
# fixed, and gzip stores no name or time. The Go version is printed so a rebuild can
# use the same one.
set -euo pipefail
export TZ=UTC
umask 022

tag="${1:?usage: build-release.sh <tag, e.g. v0.1.0> <output dir>}"
out="${2:?usage: build-release.sh <tag> <output dir>}"
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "build-release.sh: \"$tag\" is not a version tag like v1.2.3" >&2
  exit 1
fi
version="${tag#v}"
epoch="$(git log -1 --format=%ct)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
out="$(cd "$out" && pwd)"
go version
built=()

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="whichphp_${version}_${os}_${arch}"
  exe=whichphp
  if [ "$os" = windows ]; then exe=whichphp.exe; fi
  mkdir -p "$work/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=$tag" -o "$work/$name/$exe" ./cmd/whichphp
  cp LICENSE README.md "$work/$name/"
  find "$work/$name" -exec touch -h -d "@$epoch" {} +
  chmod -R u=rwX,go=rX "$work/$name"
  if [ "$os" = windows ]; then
    rm -f "$out/$name.zip"
    (cd "$work" && find "$name" -print | LC_ALL=C sort | zip -qX "$out/$name.zip" -@)
    built+=("$name.zip")
  else
    tar -C "$work" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -cf - "$name" |
      gzip -n -9 > "$out/$name.tar.gz"
    built+=("$name.tar.gz")
  fi
done

# Only this run's archives, even if the directory holds older ones.
(cd "$out" && sha256sum -- "${built[@]}" > SHA256SUMS)
cat "$out/SHA256SUMS"
