#!/usr/bin/env bash
# nix-dev.sh -- day-to-day helper for penguin's Nix build.
#
# The flake pins every upstream artifact by version, but the pins come in three
# different URL shapes (github: tag, release-tarball URL, and busybox's
# git+https ref+rev). This script hides that so routine operations are one
# command:
#
#   ./nix-dev.sh pins                     show each pin vs the latest upstream tag
#   ./nix-dev.sh bump <input> [<tag>]     rewrite a pin (default: latest tag) + relock
#   ./nix-dev.sh build                    nix build .#dockerImage
#   ./nix-dev.sh load                     build + stream into docker/podman (nix run .#load)
#   ./nix-dev.sh override <input> <path>  build+load the image with a LOCAL checkout of a
#                                         guest-tool flake (e.g. ../vpnguin) substituted in
#   ./nix-dev.sh size                     closure-size breakdown of the image's big pieces
#
# Run from anywhere inside the repo; it cds to the flake root itself.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE="$ROOT/flake.nix"

die() { echo "error: $*" >&2; exit 1; }

command -v nix >/dev/null 2>&1 || die "nix not found on PATH"

# input name -> upstream repo (owner/name) and pin shape.
#   github  : inputs.<name>.url = "github:<repo>/<tag>"
#   tarball : inputs.<name>.url = "https://github.com/<repo>/releases/download/<tag>/<asset>"
#   gitref  : inputs.<name>.url = "git+https://github.com/<repo>?ref=refs/tags/<tag>&rev=<sha>&submodules=1"
# fw2tar is pinned by raw rev (tracks a branch head, not releases) and nixpkgs
# by commit -- both intentionally excluded from bump; they still show in pins.
declare -A REPO SHAPE
REPO[penguin-qemu]=rehosting/qemu;          SHAPE[penguin-qemu]=github
REPO[console]=rehosting/console;            SHAPE[console]=github
REPO[guesthopper]=rehosting/guesthopper;    SHAPE[guesthopper]=github
REPO[vpnguin]=rehosting/vpnguin;            SHAPE[vpnguin]=github
REPO[libnvram]=rehosting/libnvram;          SHAPE[libnvram]=github
REPO[busybox]=rehosting/busybox;            SHAPE[busybox]=gitref
REPO[kernels]=rehosting/linux_builder;      SHAPE[kernels]=tarball
REPO[igloo-driver]=rehosting/igloo_driver;  SHAPE[igloo-driver]=tarball
REPO[penguin-tools]=rehosting/penguin-tools; SHAPE[penguin-tools]=tarball

BUMPABLE="penguin-qemu console busybox guesthopper vpnguin libnvram kernels igloo-driver penguin-tools"

current_pin() { # <input> -> the tag currently in flake.nix
  local name=$1 repo=${REPO[$1]} shape=${SHAPE[$1]}
  case $shape in
    github)  sed -n "s|.*\"github:$repo/\([^\"]*\)\".*|\1|p" "$FLAKE" ;;
    tarball) sed -n "s|.*github.com/$repo/releases/download/\([^/]*\)/.*|\1|p" "$FLAKE" ;;
    gitref)  sed -n "s|.*github.com/$repo?ref=refs/tags/\([^&]*\)&.*|\1|p" "$FLAKE" ;;
  esac
}

latest_tag() { # <input> -> newest v* tag upstream (semver sort)
  git ls-remote --tags "https://github.com/${REPO[$1]}" 'v*' 2>/dev/null \
    | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort -V | tail -n1
}

tag_rev() { # <input> <tag> -> commit sha of that tag (peeled if annotated)
  local out
  out=$(git ls-remote --tags "https://github.com/${REPO[$1]}" "refs/tags/$2" "refs/tags/$2^{}")
  [ -n "$out" ] || die "tag $2 not found on ${REPO[$1]}"
  # Prefer the peeled ^{} line (annotated tag -> commit); else the direct line.
  { grep '\^{}' <<<"$out" || head -n1 <<<"$out"; } | head -n1 | cut -f1
}

cmd_pins() {
  printf '%-14s %-28s %-14s %-14s %s\n' INPUT REPO PINNED LATEST ''
  for name in $BUMPABLE; do
    local cur latest mark=''
    cur=$(current_pin "$name")
    latest=$(latest_tag "$name" || true)
    [ -n "$latest" ] && [ "$cur" != "$latest" ] && mark='  <-- behind'
    printf '%-14s %-28s %-14s %-14s%s\n' "$name" "${REPO[$name]}" "${cur:-?}" "${latest:-?}" "$mark"
  done
  echo
  echo "(fw2tar and nixpkgs are pinned by commit, not tag -- bump those by hand.)"
}

cmd_bump() {
  local name=${1:-} tag=${2:-}
  [ -n "$name" ] || die "usage: nix-dev.sh bump <input> [<tag>]"
  [ -n "${REPO[$name]:-}" ] || die "unknown/unbumpable input '$name' (choose from: $BUMPABLE)"
  local repo=${REPO[$name]} shape=${SHAPE[$name]}
  local cur; cur=$(current_pin "$name")
  [ -n "$tag" ] || tag=$(latest_tag "$name")
  [ -n "$tag" ] || die "could not determine latest tag for $repo"
  if [ "$cur" = "$tag" ]; then echo "$name already at $tag"; return 0; fi

  case $shape in
    github)  sed -i "s|\"github:$repo/$cur\"|\"github:$repo/$tag\"|" "$FLAKE" ;;
    tarball) sed -i "s|github.com/$repo/releases/download/$cur/|github.com/$repo/releases/download/$tag/|" "$FLAKE" ;;
    gitref)
      local rev; rev=$(tag_rev "$name" "$tag")
      sed -i -e "s|\(github.com/$repo?ref=refs/tags/\)$cur&rev=[0-9a-f]*&|\1$tag\&rev=$rev\&|" "$FLAKE"
      ;;
  esac
  grep -q "$tag" "$FLAKE" || die "sed failed to rewrite the $name pin -- flake.nix format changed?"
  echo "$name: $cur -> $tag; relocking..."
  nix flake update "$name" --flake "$ROOT"
  echo "done. Review with: git -C $ROOT diff flake.nix flake.lock"
}

cmd_build() { exec nix build "$ROOT#dockerImage" "$@"; }
cmd_load()  { exec nix run "$ROOT#load" "$@"; }

cmd_override() {
  local name=${1:-} path=${2:-}
  [ -n "$name" ] && [ -n "$path" ] || die "usage: nix-dev.sh override <input> <path-to-local-checkout>"
  [ -d "$path" ] || die "no such directory: $path"
  path=$(cd "$path" && pwd)
  [ -e "$path/flake.nix" ] || die "$path has no flake.nix (override needs a flake input, e.g. vpnguin/console/busybox/guesthopper/penguin-qemu)"
  echo "Building the penguin image with $name taken from $path ..." >&2
  # Same stream-into-daemon path as `load`, hash-tagged so it can't shadow a
  # release image; the override applies to the whole build.
  local engine=docker
  command -v docker >/dev/null 2>&1 || { command -v podman >/dev/null 2>&1 && engine=podman || die "need docker or podman"; }
  nix build "$ROOT#dockerImageStreamHashed" --override-input "$name" "path:$path" -o "$ROOT/result-override"
  "$ROOT/result-override" | "$engine" load
  rm -f "$ROOT/result-override"
  echo "note: this image contains your LOCAL $name -- rebuild without override before comparing against CI." >&2
}

cmd_size() {
  echo "Building (or fetching) the image pieces to measure..." >&2
  nix build "$ROOT#iglooStatic" "$ROOT#pythonEnv" "$ROOT#penguinQemu" --no-link
  echo
  printf '%s\n' "closure sizes (NAR, includes all runtime deps):"
  for p in iglooStatic pythonEnv penguinQemu; do
    nix path-info -Sh "$ROOT#$p" | awk -v n="$p" '{printf "  %-14s %s %s\n", n, $(NF-1), $NF}'
  done
  echo
  echo "full image (builds the tarball if not cached):"
  nix build "$ROOT#dockerImage" --no-link && nix path-info -sh "$ROOT#dockerImage" | awk '{printf "  dockerImage    %s %s (compressed tarball)\n", $(NF-1), $NF}'
}

case "${1:-}" in
  pins)     shift; cmd_pins "$@" ;;
  bump)     shift; cmd_bump "$@" ;;
  build)    shift; cmd_build "$@" ;;
  load)     shift; cmd_load "$@" ;;
  override) shift; cmd_override "$@" ;;
  size)     shift; cmd_size "$@" ;;
  *) awk 'NR>1 { if (!/^#/) exit; sub(/^# ?/,""); print }' "$0"; exit 1 ;;
esac
