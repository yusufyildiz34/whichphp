#!/usr/bin/env bash
# Checks that the Syft and Grype versions in install-tools.sh, action.yml and the index
# workflow agree, and that install-tools.sh pins a SHA-256 for every platform the
# action supports. Run from the repository root:
#
#   bash scripts/check-tool-pins.sh
set -euo pipefail

script=scripts/install-tools.sh
fail=0
err() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::$1"; else echo "check-tool-pins.sh: $1" >&2; fi
  fail=1
}

for tool in syft grype; do
  upper="$(printf '%s' "$tool" | tr '[:lower:]' '[:upper:]')"
  want="$(sed -n "s/^${upper}_VERSION=\"\${${upper}_VERSION:-\(v[0-9.]*\)}\"\$/\1/p" "$script")"
  if [ -z "$want" ]; then
    err "can't find the default $tool version in $script"
    continue
  fi
  action="$(yq -r ".inputs.\"$tool-version\".default" action.yml)"
  index="$(yq -r ".env.${upper}_VERSION" .github/workflows/index.yml)"
  [ "$action" = "$want" ] || err "action.yml installs $tool $action, but $script defaults to $want"
  [ "$index" = "$want" ] || err "the index workflow installs $tool $index, but $script defaults to $want"
  for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
    file="${tool}_${want#v}_${platform}.tar.gz"
    if ! grep -Eq "^ +$file\) echo [0-9a-f]{64} ;;\$" "$script"; then
      err "$script has no SHA-256 for $file"
    fi
  done
done

if [ "$fail" = 0 ]; then echo "Tool versions agree and are pinned for every platform."; fi
exit "$fail"
