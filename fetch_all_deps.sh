#!/bin/bash
set -euo pipefail

# Path to Dockerfile
DOCKERFILE="$(dirname "$0")/Dockerfile"
GETRELEASE="$(realpath $(dirname "$0")/get_release.sh)"
LOCALPACKAGES="$(dirname "$0")/local_packages"

if [ ! -d "$LOCALPACKAGES" ]; then
  echo "Creating local_packages directory at $LOCALPACKAGES"
  mkdir -p "$LOCALPACKAGES"
fi

# Helper to extract ARG values from Dockerfile
get_arg() {
  grep -E "^ARG $1=" "$DOCKERFILE" | sed -E "s/^ARG $1=\"?([^\"]*)\"?.*/\1/"
}

# Parse versions from Dockerfile
LINUX_VERSION="$(get_arg LINUX_VERSION)"
BUSYBOX_VERSION="$(get_arg BUSYBOX_VERSION)"
CONSOLE_VERSION="$(get_arg CONSOLE_VERSION)"
LIBNVRAM_VERSION="$(get_arg LIBNVRAM_VERSION)"
VPN_VERSION="$(get_arg VPN_VERSION)"
HYPERFS_VERSION="$(get_arg HYPERFS_VERSION)"
GUESTHOPPER_VERSION="$(get_arg GUESTHOPPER_VERSION)"
LTRACE_PROTOTYPES_VERSION="$(get_arg LTRACE_PROTOTYPES_VERSION)"
LTRACE_PROTOTYPES_HASH="$(get_arg LTRACE_PROTOTYPES_HASH)"
MUSL_VERSION="$(get_arg MUSL_VERSION)"
PANDA_VERSION="$(get_arg PANDA_VERSION)"
PANDANG_VERSION="$(get_arg PANDANG_VERSION)"
RIPGREP_VERSION="$(get_arg RIPGREP_VERSION)"
GLOW_VERSION="$(get_arg GLOW_VERSION)"
GUM_VERSION="$(get_arg GUM_VERSION)"
DEBIANONQEMU_VERSION="$(get_arg DEBIANONQEMU_VERSION)"

TOKEN=$(get_arg CLONE_TOKEN)

# Download all dependencies directly to local_packages in parallel
bash $GETRELEASE $LOCALPACKAGES/kernels-latest.tar.gz rehosting linux_builder v${LINUX_VERSION} ${TOKEN} kernels-latest.tar.gz &
bash $GETRELEASE $LOCALPACKAGES/busybox-latest.tar.gz rehosting busybox v${BUSYBOX_VERSION} ${TOKEN} busybox-latest.tar.gz &
bash $GETRELEASE $LOCALPACKAGES/console.tar.gz rehosting console v${CONSOLE_VERSION} ${TOKEN} console.tar.gz &
bash $GETRELEASE $LOCALPACKAGES/libnvram-latest.tar.gz rehosting libnvram v${LIBNVRAM_VERSION} ${TOKEN} source.tar.gz &
bash $GETRELEASE $LOCALPACKAGES/vpn.tar.gz rehosting vpnguin v${VPN_VERSION} ${TOKEN} vpn.tar.gz &
bash $GETRELEASE $LOCALPACKAGES/hyperfs.tar.gz rehosting hyperfs v${HYPERFS_VERSION} ${TOKEN} hyperfs.tar.gz &
bash $GETRELEASE $LOCALPACKAGES/guesthopper.tar.gz rehosting guesthopper v${GUESTHOPPER_VERSION} ${TOKEN} guesthopper.tar.gz &
bash $GETRELEASE $LOCALPACKAGES/pandare.deb panda-re qemu ${PANDA_VERSION} ${TOKEN} pandare_22.04.deb &
bash $GETRELEASE $LOCALPACKAGES/pandare-plugins.deb panda-re panda-ng v${PANDANG_VERSION} ${TOKEN} pandare-plugins_22.04.deb &
bash $GETRELEASE $LOCALPACKAGES/ripgrep.deb BurntSushi ripgrep ${RIPGREP_VERSION} ${TOKEN} ripgrep_${RIPGREP_VERSION}-1_amd64.deb &
bash $GETRELEASE $LOCALPACKAGES/glow.deb charmbracelet glow v${GLOW_VERSION} ${TOKEN} glow_${GLOW_VERSION}_amd64.deb &
bash $GETRELEASE $LOCALPACKAGES/gum.deb charmbracelet gum v${GUM_VERSION} ${TOKEN} gum_${GUM_VERSION}_amd64.deb &
bash $GETRELEASE $LOCALPACKAGES/bios-loong64-8.1.bin wtdcode DebianOnQEMU ${DEBIANONQEMU_VERSION} ${TOKEN} bios-loong64-8.1.bin &

# Ltrace prototype tarball
curl -sSL -o $LOCALPACKAGES/ltrace-prototypes.tar.bz2 "https://src.fedoraproject.org/repo/pkgs/ltrace/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2/${LTRACE_PROTOTYPES_HASH}/ltrace-${LTRACE_PROTOTYPES_VERSION}.tar.bz2" &

# Musl headers (download only, do not build)
curl -sSL -o $LOCALPACKAGES/musl-${MUSL_VERSION}.tar.gz "https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz" &

wait
echo "All dependencies downloaded and available in local_packages"
