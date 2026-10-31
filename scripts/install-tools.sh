#!/usr/bin/env bash
# Installs the Syft and Grype release binaries into a directory, checking each archive
# against a SHA-256 pinned below. The index workflow and the GitHub Action use it in
# place of the projects' install.sh, so no downloaded script ever runs.
#
#   SYFT_VERSION=v1.55.0 GRYPE_VERSION=v0.121.0 bash scripts/install-tools.sh ~/bin
#
# To move to new versions, update the defaults here, in action.yml and in the index
# workflow, and add the archives' hashes from each release's checksums file;
# scripts/check-tool-pins.sh checks that they agree. A version that isn't pinned here is
# still checked, against its release's checksums file, with a warning, unless
# REQUIRE_PINNED is set (to anything but 0 or false), which makes it an error.
set -euo pipefail

dir="${1:?usage: install-tools.sh <directory>}"
SYFT_VERSION="${SYFT_VERSION:-v1.55.0}"
GRYPE_VERSION="${GRYPE_VERSION:-v0.121.0}"

pinned() {
  case "$1" in
    syft_1.55.0_linux_amd64.tar.gz) echo bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d ;;
    syft_1.55.0_linux_arm64.tar.gz) echo 929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304 ;;
    syft_1.55.0_darwin_amd64.tar.gz) echo e2e5831cbabaec9a36fe65c34755c1113982c842a685edce3ce0b54a0ded8003 ;;
    syft_1.55.0_darwin_arm64.tar.gz) echo 1217c258bd5eb91ef3189cf22a82e02f9cac07e4ce934350f428e93aff674625 ;;
    grype_0.121.0_linux_amd64.tar.gz) echo 64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519 ;;
    grype_0.121.0_linux_arm64.tar.gz) echo 86f570f75ca947ea3dd6486309232bcff6d78e44ba081ae75ab14eab72be3dae ;;
    grype_0.121.0_darwin_amd64.tar.gz) echo 27eef17e42f0340af6582cdbc33ad18faf9f601c613ab81d2e1658a94cbc357f ;;
    grype_0.121.0_darwin_arm64.tar.gz) echo 7be39d3a0428c664ce0183e4aba31ed9accffce9eda7e7f6fa84e9c512285f27 ;;
  esac
}

sha256() {
  if command -v sha256sum > /dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "install-tools.sh: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "install-tools.sh: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$dir"

install_tool() {
  local name=$1 version=$2
  if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "install-tools.sh: \"$version\" isn't a version like v1.2.3" >&2
    exit 1
  fi
  local file="${name}_${version#v}_${os}_${arch}.tar.gz"
  local base="https://github.com/anchore/$name/releases/download/$version"
  curl -sSfL --retry 3 -o "$work/$file" "$base/$file"
  local want
  want="$(pinned "$file")"
  if [ -z "$want" ]; then
    case "${REQUIRE_PINNED:-}" in
      "" | 0 | false) ;;
      *)
        msg="$file isn't pinned in install-tools.sh, and REQUIRE_PINNED is set"
        if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::$msg"; else echo "install-tools.sh: $msg" >&2; fi
        exit 1 ;;
    esac
    msg="$file isn't pinned in install-tools.sh; checking it against the release's checksums file only"
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::warning::$msg"; else echo "install-tools.sh: $msg" >&2; fi
    want="$(curl -sSfL --retry 3 "$base/${name}_${version#v}_checksums.txt" | awk -v f="$file" '$2 == f {print $1}')"
  fi
  local got
  got="$(sha256 "$work/$file")"
  if [ -z "$want" ] || [ "$got" != "$want" ]; then
    echo "install-tools.sh: $file failed its checksum (got $got, want ${want:-none})" >&2
    exit 1
  fi
  tar -xzf "$work/$file" -C "$work" "$name"
  install -m 0755 "$work/$name" "$dir/$name"
  echo "Installed $name $version ($file, sha256 $got)"
}

install_tool syft "$SYFT_VERSION"
install_tool grype "$GRYPE_VERSION"
