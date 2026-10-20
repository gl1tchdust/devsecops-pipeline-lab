#!/usr/bin/env bash
# Fetch a scan target, pinned to a commit.
#
#   ./target/fetch.sh            # all targets
#   ./target/fetch.sh vampi      # just one
#
# Pinned, not tracked. A moving target makes every result unreproducible: a
# finding that appears tomorrow tells you nothing about whether a rule improved
# or whether upstream edited a line. Bump a SHA deliberately, in its own
# commit, and re-read the benchmark diff.
#
# Targets are fetched at build time rather than vendored, so this repo carries
# no third-party source. Both are permissively licensed (VAmPI MIT, DVNA MIT).

set -euo pipefail

# name|repo|commit
TARGETS=(
  "vampi|https://github.com/erev0s/VAmPI.git|f16052dce83f05847133ec98f01c5193a41de7d8"
  "dvna|https://github.com/appsecco/dvna.git|9ba473add536f66ac9007966acb2a775dd31277a"
)

fetch_one() {
  local name="$1" repo="$2" sha="$3"
  local dest="target/$name"

  if [ -d "$dest/.git" ]; then
    echo "  $name: already present"
  else
    echo "  $name: cloning"
    git clone --quiet "$repo" "$dest"
  fi

  git -C "$dest" fetch --quiet origin "$sha" 2>/dev/null || git -C "$dest" fetch --quiet origin
  git -C "$dest" checkout --quiet "$sha"
  echo "  $name: pinned at $(git -C "$dest" rev-parse --short HEAD)"
}

want="${1:-all}"
found=0

for entry in "${TARGETS[@]}"; do
  IFS='|' read -r name repo sha <<< "$entry"
  if [ "$want" = "all" ] || [ "$want" = "$name" ]; then
    fetch_one "$name" "$repo" "$sha"
    found=1
  fi
done

if [ "$found" -eq 0 ]; then
  echo "unknown target: $want" >&2
  printf 'known targets:' >&2
  for entry in "${TARGETS[@]}"; do printf ' %s' "${entry%%|*}" >&2; done
  echo >&2
  exit 1
fi
