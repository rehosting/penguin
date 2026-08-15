#!/usr/bin/env bash
# nix-dev.sh -- day-to-day helper for penguin's Nix build.
#
# The flake pins every upstream artifact by version, but the pins come in three
# different URL shapes (github: tag, release-tarball URL, and busybox's
# git+https ref+rev). This script hides that so routine operations are one
# command:
#
#   ./nix-dev.sh doctor                   check the local setup (nix, flakes, cache, engine, disk)
#   ./nix-dev.sh pins                     show each pin vs the latest upstream tag
#   ./nix-dev.sh bump <input> [<tag>]     rewrite a pin (default: latest tag) + relock
#   ./nix-dev.sh build                    nix build .#dockerImage
#   ./nix-dev.sh load                     build + stream into docker/podman (nix run .#load)
#   ./nix-dev.sh override <input> <path> [<input> <path> ...]
#                                         build+load the image with LOCAL sources substituted
#                                         in. For a flake input that is a checkout with a
#                                         flake.nix (e.g. ../vpnguin); for a `flake = false`
#                                         input (igloo-driver, penguin-tools, libnvram,
#                                         musl-src...) a directory, a nix store path, or a
#                                         release tarball, matching the layout the fetcher
#                                         would have produced.
#   ./nix-dev.sh size                     closure-size breakdown of the image's big pieces
#
# Run from anywhere inside the repo; it cds to the flake root itself.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE="$ROOT/flake.nix"
LOCK="$ROOT/flake.lock"

die() { echo "error: $*" >&2; exit 1; }

# doctor must be able to run (and explain) when nix itself is missing, so only
# hard-require nix for every other subcommand.
if [ "${1:-}" != "doctor" ]; then
  command -v nix >/dev/null 2>&1 || die "nix not found on PATH (try: ./nix-dev.sh doctor)"
fi

# input name -> upstream repo (owner/name) and pin shape.
#   flake   : inputs.<name>.url = "github:<repo>"  -- NO ref in the URL. The
#             revision lives in flake.lock (the single pin), so `current_pin`
#             reads the lock, and `bump` is `nix flake update <input>`.
#   tarball : inputs.<name>.url = "https://github.com/<repo>/releases/download/<tag>/<asset>"
#             -- here the version IS part of the URL and cannot be dropped
#             without switching to `releases/latest/download/`, which would
#             erase which release we are on from both flake.nix and flake.lock.
#             So these keep an explicit version and `bump` rewrites the URL.
# nixpkgs is pinned by commit (deliberately, to match penguin-tools' pin so the
# two flakes share a closure) -- excluded from bump, bump it by hand.
declare -A REPO SHAPE
REPO[penguin-qemu]=rehosting/qemu;          SHAPE[penguin-qemu]=flake
REPO[console]=rehosting/console;            SHAPE[console]=flake
REPO[guesthopper]=rehosting/guesthopper;    SHAPE[guesthopper]=flake
REPO[vpnguin]=rehosting/vpnguin;            SHAPE[vpnguin]=flake
REPO[libnvram]=rehosting/libnvram;          SHAPE[libnvram]=flake
REPO[busybox]=rehosting/busybox;            SHAPE[busybox]=flake
REPO[kernels]=rehosting/linux_builder;      SHAPE[kernels]=tarball
REPO[igloo-driver]=rehosting/igloo_driver;  SHAPE[igloo-driver]=tarball
REPO[penguin-tools]=rehosting/penguin-tools; SHAPE[penguin-tools]=tarball
REPO[fw2tar]=rehosting/fw2tar;              SHAPE[fw2tar]=flake

BUMPABLE="penguin-qemu console busybox guesthopper vpnguin libnvram kernels igloo-driver penguin-tools fw2tar"

locked_rev() { # <input> -> the revision flake.lock currently pins
  python3 - "$LOCK" "$1" <<'EOF'
import json, sys
nodes = json.load(open(sys.argv[1]))["nodes"]
node = nodes.get(sys.argv[2], {})
print(node.get("locked", {}).get("rev", ""))
EOF
}

current_pin() { # <input> -> what we are on: a release tag if the locked rev is
                # one, else "<short-rev> (untagged)"; tarballs read the URL.
  local name=$1 repo=${REPO[$1]} shape=${SHAPE[$1]}
  case $shape in
    tarball) sed -n "s|.*github.com/$repo/releases/download/\([^/]*\)/.*|\1|p" "$FLAKE" ;;
    flake)
      local rev tag
      rev=$(locked_rev "$name")
      [ -n "$rev" ] || { echo "?"; return; }
      tag=$(tag_for_rev "$name" "$rev")
      if [ -n "$tag" ]; then echo "$tag"; else echo "${rev:0:9} (untagged)"; fi
      ;;
  esac
}

tag_for_rev() { # <input> <rev> -> the release tag pointing at <rev>, if any
  git ls-remote --tags "https://github.com/${REPO[$1]}" 'v*' 2>/dev/null \
    | sed 's|\^{}||' | awk -v r="$2" '$1 == r { sub(/.*refs\/tags\//, "", $2); print $2; exit }'
}

latest_tag() { # <input> -> newest v* RELEASE tag upstream (semver sort)
  # Skip prerelease tags (e.g. v0.0.94-pre.df8576ef7): they sort above the
  # release they precede, so leaving them in reports a stable pin as "behind"
  # and points a bump at an unreleased build.
  git ls-remote --tags "https://github.com/${REPO[$1]}" 'v*' 2>/dev/null \
    | grep -v '\^{}' | sed 's|.*refs/tags/||' | grep -v -- '-pre' | sort -V | tail -n1
}

tag_rev() { # <input> <tag> -> commit sha of that tag (peeled if annotated)
  local out
  out=$(git ls-remote --tags "https://github.com/${REPO[$1]}" "refs/tags/$2" "refs/tags/$2^{}")
  [ -n "$out" ] || die "tag $2 not found on ${REPO[$1]}"
  # Prefer the peeled ^{} line (annotated tag -> commit); else the direct line.
  { grep '\^{}' <<<"$out" || head -n1 <<<"$out"; } | head -n1 | cut -f1
}

cmd_pins() {
  # LOCKED is what we actually build: for flake inputs it is resolved from
  # flake.lock (shown as the release tag when the locked revision is one, else
  # the short revision marked untagged); for tarball inputs it is the version in
  # the URL. LATEST is the newest upstream release, so a lock sitting behind a
  # release -- or parked on an untagged commit -- is visible either way.
  printf '%-14s %-28s %-20s %-14s %s\n' INPUT REPO LOCKED LATEST ''
  for name in $BUMPABLE; do
    local cur latest mark=''
    cur=$(current_pin "$name")
    latest=$(latest_tag "$name" || true)
    [ -n "$latest" ] && [ "$cur" != "$latest" ] && mark='  <-- behind'
    printf '%-14s %-28s %-20s %-14s%s\n' "$name" "${REPO[$name]}" "${cur:-?}" "${latest:-?}" "$mark"
  done
  echo
  echo "(nixpkgs is pinned by commit in flake.nix, deliberately -- see the"
  echo " comment there; bump it in lockstep with penguin-tools.)"
}

cmd_bump() {
  local name=${1:-} tag=${2:-}
  [ -n "$name" ] || die "usage: nix-dev.sh bump <input> [<tag>]"
  [ -n "${REPO[$name]:-}" ] || die "unknown/unbumpable input '$name' (choose from: $BUMPABLE)"
  local repo=${REPO[$name]} shape=${SHAPE[$name]}
  local cur; cur=$(current_pin "$name")

  case $shape in
    flake)
      # The revision lives only in flake.lock, so bumping is a relock. With no
      # <tag>, take whatever the default branch is at now; with a <tag>, lock
      # that exact release.
      if [ -n "$tag" ]; then
        if [ "$cur" = "$tag" ]; then echo "$name already at $tag"; return 0; fi
        echo "$name: $cur -> $tag; relocking..."
        nix flake update "$name" --flake "$ROOT" --override-input "$name" "github:$repo/$tag"
      else
        echo "$name: $cur -> default-branch HEAD; relocking..."
        nix flake update "$name" --flake "$ROOT"
      fi
      ;;
    tarball)
      # Here the version is part of the URL, so it has to be rewritten.
      [ -n "$tag" ] || tag=$(latest_tag "$name")
      [ -n "$tag" ] || die "could not determine latest tag for $repo"
      if [ "$cur" = "$tag" ]; then echo "$name already at $tag"; return 0; fi
      sed -i "s|github.com/$repo/releases/download/$cur/|github.com/$repo/releases/download/$tag/|" "$FLAKE"
      grep -q "$tag" "$FLAKE" || die "sed failed to rewrite the $name pin -- flake.nix format changed?"
      echo "$name: $cur -> $tag; relocking..."
      nix flake update "$name" --flake "$ROOT"
      ;;
  esac
  echo "done. Review with: git -C $ROOT diff flake.nix flake.lock"
}

cmd_build() { exec nix build "$ROOT#dockerImage" "$@"; }
cmd_load()  { exec nix run "$ROOT#load" "$@"; }

# Inputs declared `flake = false` are fetched as opaque SOURCE TREES, not
# flakes, so they have no flake.nix and the "does it have a flake.nix" check
# below must not apply to them. Read the declaration out of flake.nix rather
# than keeping a second hand-maintained list here: a new `flake = false` input
# then works with no change to this script.
input_is_flake() { # <input> -> 0 if the flake.nix declaration is a real flake input
  # Matches the block `inputs.<name> = { ... };` and looks for `flake = false`
  # inside it. Both the one-line and multi-line forms are used in flake.nix.
  ! awk -v want="$1" '
    $0 ~ "^[[:space:]]*inputs\\." want "[[:space:]]*=" { inblock = 1 }
    inblock && /flake[[:space:]]*=[[:space:]]*false/  { found = 1 }
    inblock && /};/                                   { inblock = 0 }
    END { exit(found ? 0 : 1) }
  ' "$FLAKE"
}

input_declared() { # <input> -> 0 if flake.nix declares it at all
  grep -qE "^[[:space:]]*inputs\.$1[[:space:]]*=" "$FLAKE"
}

# Turn one <input> <path> pair into a `path:` flake reference nix can consume,
# extracting first if the user handed us a release tarball. Tarballs are
# unpacked to a temp dir recorded in OVERRIDE_TMPDIRS so the caller can clean
# up only AFTER the build has read them.
OVERRIDE_TMPDIRS=()
resolve_override_path() { # <input> <path> -> prints an absolute path
  local name=$1 path=$2

  if [ -d "$path" ]; then
    path=$(cd "$path" && pwd)
    if input_is_flake "$name"; then
      [ -e "$path/flake.nix" ] || die "$path has no flake.nix, but '$name' is a flake input.
  Point it at a checkout of the repo (e.g. ../vpnguin), or -- if you meant to
  substitute a built artifact -- note that '$name' is not a \`flake = false\` input."
    else
      # A `flake = false` input is consumed as a tree. An empty dir builds
      # "successfully" and silently produces an image missing that component,
      # which is the worst possible failure here, so refuse it.
      [ -n "$(ls -A "$path" 2>/dev/null)" ] || die "$path is empty; '$name' is consumed as a source tree and an empty tree would build a silently broken image"
    fi
    printf '%s\n' "$path"
    return
  fi

  if [ -f "$path" ]; then
    input_is_flake "$name" && die "'$name' is a flake input, so it needs a checkout directory, not the file $path"
    case "$path" in
      *.tar.gz|*.tgz|*.tar.xz|*.tar.bz2|*.tar) ;;
      *) die "don't know how to use $path for '$name' (expected a directory, a nix store path, or a release tarball)" ;;
    esac
    local tmp; tmp=$(mktemp -d)
    OVERRIDE_TMPDIRS+=("$tmp")
    tar -xf "$path" -C "$tmp" || die "failed to extract $path"
    # nix's tarball fetcher strips a single leading directory component, so an
    # extracted tree must be stripped the same way or every path inside the
    # input gains a level and the build fails deep in mk-igloo-static with a
    # confusing "no such file" instead of here.
    #
    # This rule cannot distinguish a wrapper directory from a tree that
    # genuinely has one top-level directory -- nix has the same ambiguity -- so
    # say which component was dropped rather than resolving it silently.
    local entries; entries=$(ls -A "$tmp")
    if [ "$(printf '%s\n' "$entries" | wc -l)" = 1 ] && [ -d "$tmp/$entries" ]; then
      echo "  (stripped the leading '$entries/' component, as nix's tarball fetcher would)" >&2
      printf '%s\n' "$tmp/$entries"
    else
      printf '%s\n' "$tmp"
    fi
    return
  fi

  die "no such file or directory: $path"
}

cmd_override() {
  [ $# -ge 2 ] && [ $(($# % 2)) -eq 0 ] \
    || die "usage: nix-dev.sh override <input> <path> [<input> <path> ...]"

  local -a args=() names=()
  while [ $# -gt 0 ]; do
    local name=$1 path=$2; shift 2
    input_declared "$name" || die "flake.nix declares no input named '$name'"
    local resolved; resolved=$(resolve_override_path "$name" "$path")
    echo "  $name <- $resolved" >&2
    args+=(--override-input "$name" "path:$resolved")
    names+=("$name")
  done

  echo "Building the penguin image with the above substituted in ..." >&2
  # Same stream-into-daemon path as `load`, hash-tagged so it can't shadow a
  # release image; the overrides apply to the whole build.
  local engine=docker
  command -v docker >/dev/null 2>&1 || { command -v podman >/dev/null 2>&1 && engine=podman || die "need docker or podman"; }
  # Clean up extracted tarballs however we exit, but not before the build has
  # read them.
  trap '[ ${#OVERRIDE_TMPDIRS[@]} -eq 0 ] || rm -rf "${OVERRIDE_TMPDIRS[@]}"' EXIT
  nix build "$ROOT#dockerImageStreamHashed" "${args[@]}" -o "$ROOT/result-override"
  "$ROOT/result-override" | "$engine" load
  rm -f "$ROOT/result-override"
  echo "note: this image contains your LOCAL ${names[*]} -- rebuild without override before comparing against CI." >&2
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

CACHE_URL="https://rehosting-tools.cachix.org"

cmd_doctor() {
  local fails=0 warns=0
  ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
  warn() { printf '  \033[33mwarn\033[0m  %s\n' "$*"; warns=$((warns+1)); }
  fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fails=$((fails+1)); }

  echo "nix:"
  if ! command -v nix >/dev/null 2>&1; then
    fail "nix not on PATH. Install: https://nixos.org/download (the multi-user daemon install)"
    echo; echo "1 failure -- fix the above, then re-run."; return 1
  fi
  ok "$(nix --version)"

  # Flakes + the nix-command CLI must be enabled (nix.conf or NIX_CONFIG).
  local feats; feats=$(nix config show experimental-features 2>/dev/null || true)
  case " $feats " in
    *" flakes "*) ok "flakes enabled" ;;
    *) fail "flakes not enabled. Add to ~/.config/nix/nix.conf:  experimental-features = nix-command flakes" ;;
  esac

  echo "binary cache (skips hours of local cross-toolchain builds):"
  # The flake asks for the rehosting-tools cache via nixConfig; that only takes
  # effect if (a) it's already a system-level substituter, (b) the user is
  # trusted (so --accept-flake-config works), or (c) the user has accepted and
  # saved it (trusted-settings.json). Any one of these is enough.
  local subs trusted_subs saved
  subs=$(nix config show substituters 2>/dev/null || true)
  trusted_subs=$(nix config show trusted-substituters 2>/dev/null || true)
  saved=""
  grep -qs "rehosting-tools.cachix.org" "${XDG_DATA_HOME:-$HOME/.local/share}/nix/trusted-settings.json" && saved=yes
  if [[ " $subs $trusted_subs " == *"rehosting-tools.cachix.org"* ]]; then
    ok "$CACHE_URL configured as a substituter"
  elif [ -n "$saved" ]; then
    ok "$CACHE_URL accepted via the flake's nixConfig (saved setting)"
  elif nix config show trusted-users 2>/dev/null | tr ' ' '\n' | grep -qx "$(id -un)"; then
    ok "you are a nix trusted user; pass --accept-flake-config (nix will offer to save it)"
  else
    warn "cache not reachable as configured: builds will compile cross toolchains locally (hours)."
    warn "  Fix (needs root once): add to /etc/nix/nix.conf and restart nix-daemon:"
    warn "    trusted-substituters = $CACHE_URL"
    warn "    trusted-public-keys = rehosting-tools.cachix.org-1:iNKSaFwG7MfGn6Fk7oTmIcLHqfffQ+cQIE5gWc6MlY0="
    warn "  or add your user to trusted-users and build with --accept-flake-config."
  fi

  echo "container engine:"
  if command -v docker >/dev/null 2>&1 && timeout 5 docker info >/dev/null 2>&1; then
    ok "docker daemon reachable"
  elif command -v podman >/dev/null 2>&1 && timeout 5 podman info >/dev/null 2>&1; then
    ok "podman reachable"
  elif command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
    fail "docker/podman installed but the daemon is not reachable (permissions? service down?)"
  else
    fail "neither docker nor podman found -- needed to run the penguin image"
  fi

  echo "host:"
  # The store fills up fast (each image closure is ~4 GiB; bumps accumulate).
  local nix_dir=/nix; [ -d /nix ] || nix_dir=$HOME
  local free_kb; free_kb=$(df -Pk "$nix_dir" 2>/dev/null | awk 'NR==2 {print $4}')
  if [ -n "$free_kb" ] && [ "$free_kb" -lt $((30 * 1024 * 1024)) ]; then
    warn "only $((free_kb / 1024 / 1024)) GiB free on $nix_dir -- image builds need ~10 GiB per iteration; consider: nix store gc"
  else
    ok "$((free_kb / 1024 / 1024)) GiB free on $nix_dir"
  fi
  if [ -e /dev/kvm ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
      ok "/dev/kvm accessible (x86_64 guests get KVM)"
    else
      warn "/dev/kvm exists but not accessible (add yourself to the kvm group); guests fall back to TCG"
    fi
  else
    warn "no /dev/kvm; x86_64 guests run under TCG (slower). Fine for non-x86 firmware."
  fi
  # A pyenv init re-prepends its shims on shell startup, shadowing the
  # devshell's python3 (the flake's shellHook works around it, but flag it).
  case ":$PATH:" in
    *":$HOME/.pyenv/shims:"*) warn "pyenv shims on PATH -- may shadow python3 in nix develop (the shellHook re-prepends, but be aware)" ;;
  esac

  echo
  if [ "$fails" -gt 0 ]; then
    echo "$fails failure(s), $warns warning(s) -- fix the failures, then re-run."
    return 1
  fi
  echo "all checks passed ($warns warning(s))."
}

case "${1:-}" in
  doctor)   shift; cmd_doctor "$@" ;;
  pins)     shift; cmd_pins "$@" ;;
  bump)     shift; cmd_bump "$@" ;;
  build)    shift; cmd_build "$@" ;;
  load)     shift; cmd_load "$@" ;;
  override) shift; cmd_override "$@" ;;
  size)     shift; cmd_size "$@" ;;
  *) awk 'NR>1 { if (!/^#/) exit; sub(/^# ?/,""); print }' "$0"; exit 1 ;;
esac
