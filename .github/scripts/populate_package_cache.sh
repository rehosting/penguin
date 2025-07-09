#!/bin/bash
# populate_package_cache.sh
# This script ensures all expected local packages are present in ./local_packages.
# Downloads or prints warnings for missing files, using logic from Dockerfile.

set -e

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

PACKAGE_CACHE_DIR="$(realpath ${SCRIPT_DIR}"/../../package_cache")"
mkdir -p "$PACKAGE_CACHE_DIR"
DOCKERFILE="$(realpath ${SCRIPT_DIR}"/../../Dockerfile")"


# Parse versions and token from Dockerfile
get_var() {
  grep -E "^ARG $1=" "$DOCKERFILE" | head -n1 | sed -E "s/ARG $1=\"?([^\"]*)\"?/\1/"
}

DOWNLOAD_TOKEN="$(get_var DOWNLOAD_TOKEN)"
PANDA_VERSION="$(get_var PANDA_VERSION)"
PANDANG_VERSION="$(get_var PANDANG_VERSION)"
RIPGREP_VERSION="$(get_var RIPGREP_VERSION)"
GLOW_VERSION="$(get_var GLOW_VERSION)"
GUM_VERSION="$(get_var GUM_VERSION)"
GUESTHOPPER_VERSION="$(get_var GUESTHOPPER_VERSION)"
VPN_VERSION="$(get_var VPN_VERSION)"
BUSYBOX_VERSION="$(get_var BUSYBOX_VERSION)"
LINUX_VERSION="$(get_var LINUX_VERSION)"
CONSOLE_VERSION="$(get_var CONSOLE_VERSION)"
HYPERFS_VERSION="$(get_var HYPERFS_VERSION)"
LIBNVRAM_VERSION="$(get_var LIBNVRAM_VERSION)"
MUSL_VERSION="$(get_var MUSL_VERSION)"

# Helper: download if missing
fetch_if_missing() {
  local url="$1"
  local out="$2"
  local pkg_name="$3"
  local pkg_version="$4"
  if [ ! -f "$out" ]; then
    echo "[INFO] Downloading $pkg_name version $pkg_version to $out ..."
    curl -L -v --retry 5 --retry-delay 5 -o "$out" "$url"
  fi
}

# Helper: use get_release.sh if missing
fetch_release_if_missing() {
  local owner="$1"
  local repo="$2"
  local version="$3"
  local out="$4"
  if [ ! -f "$out" ]; then
    echo "[INFO] Downloading $repo version $version to $out using get_release.sh ..."
    ./get_release.sh "$owner" "$repo" "$version" "$DOWNLOAD_TOKEN" > "$out"
  fi
}

# 1. pandare_22.04.deb
fetch_if_missing "https://github.com/panda-re/qemu/releases/download/${PANDA_VERSION}/pandare_22.04.deb" "$PACKAGE_CACHE_DIR/pandare_22.04-${PANDA_VERSION}.deb" "pandare_22.04.deb" "$PANDA_VERSION" &
# 2. pandare-plugins_22.04.deb
fetch_if_missing "https://github.com/panda-re/panda-ng/releases/download/v${PANDANG_VERSION}/pandare-plugins_22.04.deb" "$PACKAGE_CACHE_DIR/pandare-plugins_22.04-${PANDANG_VERSION}.deb" "pandare-plugins_22.04.deb" "$PANDANG_VERSION" &
# 3. ripgrep
fetch_if_missing "https://github.com/BurntSushi/ripgrep/releases/download/${RIPGREP_VERSION}/ripgrep_${RIPGREP_VERSION}-1_amd64.deb" "$PACKAGE_CACHE_DIR/ripgrep_${RIPGREP_VERSION}-1_amd64.deb" "ripgrep" "$RIPGREP_VERSION" &
# 4. glow
fetch_if_missing "https://github.com/charmbracelet/glow/releases/download/v${GLOW_VERSION}/glow_${GLOW_VERSION}_amd64.deb" "$PACKAGE_CACHE_DIR/glow_${GLOW_VERSION}_amd64.deb" "glow" "$GLOW_VERSION" &
# 5. gum
fetch_if_missing "https://github.com/charmbracelet/gum/releases/download/v${GUM_VERSION}/gum_${GUM_VERSION}_amd64.deb" "$PACKAGE_CACHE_DIR/gum_${GUM_VERSION}_amd64.deb" "gum" "$GUM_VERSION" &
# 6. guesthopper (get_release.sh)
fetch_release_if_missing rehosting guesthopper "$GUESTHOPPER_VERSION" "$PACKAGE_CACHE_DIR/guesthopper-${GUESTHOPPER_VERSION}.tar.gz" &
# 7. vpn (get_release.sh)
fetch_release_if_missing rehosting vpnguin "$VPN_VERSION" "$PACKAGE_CACHE_DIR/vpnguin-${VPN_VERSION}.tar.gz" &
# 8. busybox (get_release.sh)
fetch_release_if_missing rehosting busybox "$BUSYBOX_VERSION" "$PACKAGE_CACHE_DIR/busybox-${BUSYBOX_VERSION}.tar.gz" &
# 9. kernels (get_release.sh)
fetch_release_if_missing rehosting linux_builder "$LINUX_VERSION" "$PACKAGE_CACHE_DIR/kernels-${LINUX_VERSION}.tar.gz" &
# 10. console (get_release.sh)
fetch_release_if_missing rehosting console "$CONSOLE_VERSION" "$PACKAGE_CACHE_DIR/console-${CONSOLE_VERSION}.tar.gz" &
# 11. hyperfs (get_release.sh)
fetch_release_if_missing rehosting hyperfs "$HYPERFS_VERSION" "$PACKAGE_CACHE_DIR/hyperfs-${HYPERFS_VERSION}.tar.gz" &
# 12. libnvram (public tarball)
fetch_if_missing "https://github.com/rehosting/libnvram/archive/refs/tags/v${LIBNVRAM_VERSION}.tar.gz" "$PACKAGE_CACHE_DIR/libnvram-${LIBNVRAM_VERSION}.tar.gz" "libnvram" "$LIBNVRAM_VERSION" &
# 13. nmap (custom, not public)
if [ ! -f "$PACKAGE_CACHE_DIR/nmap.tar.gz" ]; then
  echo "[WARN] nmap.tar.gz is not public. Place it in $PACKAGE_CACHE_DIR if needed."
fi &
# 14. plugins (custom, not public)
if [ ! -f "$PACKAGE_CACHE_DIR/plugins.tar.gz" ]; then
  echo "[WARN] plugins.tar.gz is not public. Place it in $PACKAGE_CACHE_DIR if needed."
fi &
# 15. pandare2 wheel
fetch_if_missing "https://github.com/panda-re/panda-ng/releases/download/v${PANDANG_VERSION}/pandare2-${PANDANG_VERSION}-py3-none-any.whl" "$PACKAGE_CACHE_DIR/pandare2-${PANDANG_VERSION}-py3-none-any.whl" "pandare2 wheel" "$PANDANG_VERSION" &
# 16. pandare2.tar.gz (custom, not public)
if [ ! -f "$PACKAGE_CACHE_DIR/pandare2.tar.gz" ]; then
  echo "[WARN] pandare2.tar.gz is not public. Place it in $PACKAGE_CACHE_DIR if needed."
fi &
# 17. ltrace prototypes
fetch_if_missing "https://src.fedoraproject.org/repo/pkgs/ltrace/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2/${LTRACE_PROTOTYPES_HASH}/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2" "$PACKAGE_CACHE_DIR/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2" "ltrace prototypes" "$LTRACE_PROTOTYPES_VERSION" &
# 18. bios-loong64-8.1.bin
fetch_if_missing "https://github.com/wtdcode/DebianOnQEMU/releases/download/v2024.01.05/bios-loong64-8.1.bin" "$PACKAGE_CACHE_DIR/bios-loong64-8.1.bin" "bios-loong64-8.1.bin" "2024.01.05" &
# 19. llvm.sh
fetch_if_missing "https://apt.llvm.org/llvm.sh" "$PACKAGE_CACHE_DIR/llvm.sh" "llvm.sh" "latest" &
# 20. musl (public tarball)
fetch_if_missing "https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz" "$PACKAGE_CACHE_DIR/musl-${MUSL_VERSION}.tar.gz" "musl" "$MUSL_VERSION" &

wait

# Summary
ls -lh $PACKAGE_CACHE_DIR
