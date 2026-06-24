# Assemble /igloo_static, mirroring the penguin Dockerfile.
#
# Sources (release tarballs, top-level dir stripped by the nix tarball fetcher):
#   kernels       -> /igloo_static/kernels/<ver>/   (bzImage/vmlinux/zImage + osi/cosi)
#   igloo-driver  -> /igloo_static/kernels/<ver>/   (igloo.ko.<arch>, merged in)
#   penguin-tools -> /igloo_static/                 (closures, dylibs, sysroots,
#                                                    <arch>/, guesthopper, vpn, libnvram)
#   guest-utils   -> /igloo_static/guest-utils      (repo source; Dockerfile COPY)
#
# Then the symlink staging from Dockerfile lines 612-638 (utils.source, arch-name
# compat renames, the flat vpn/console link dirs, and utils.bin/<tool>.<arch>).
#
# NOT yet included (follow-ups before the full image; each is its own concern):
#   - musl-headers (built from musl source, Dockerfile 135-146)
#   - ltrace prototype .conf files (Dockerfile 177-190)
#   - send_hypercall native helper (cross_builder, Dockerfile 192-196)
#   - the sysroot header/-lgcc_s linking (Dockerfile 444-464, needs musl-headers)
# The exact byte-structure here must be golden-diffed against the Docker image's
# /igloo_static before this is trusted for the runtime image.
{
  pkgs,
  kernels,
  igloo-driver,
  penguin-tools,
  guestUtils,
}:

pkgs.runCommand "igloo-static"
  {
    nativeBuildInputs = with pkgs.buildPackages; [ coreutils ];
  }
  ''
    set -euo pipefail
    mkdir -p "$out/igloo_static/kernels"

    # Kernels + the matching igloo.ko.<arch> driver blobs share per-version dirs.
    cp -a ${kernels}/.      "$out/igloo_static/kernels/"
    chmod -R u+w "$out/igloo_static/kernels"
    cp -a ${igloo-driver}/. "$out/igloo_static/kernels/"

    # penguin-tools provides the rest of /igloo_static (closures/dylibs/sysroots/
    # per-arch tool dirs/guesthopper/vpn/libnvram + its own compat symlinks).
    # `cp -a src/.` stamps the source dir's 0555 mode onto igloo_static, so make
    # it writable again before adding more into it.
    cp -a ${penguin-tools}/. "$out/igloo_static/"
    chmod -R u+w "$out/igloo_static"

    # guest-utils source tree (scripts + native sources), Dockerfile COPY.
    cp -a ${guestUtils} "$out/igloo_static/guest-utils"
    chmod -R u+w "$out/igloo_static/guest-utils"
    cd "$out/igloo_static"

    # --- Dockerfile 612-615: utils.source (shell drop-in helpers) -------------
    mkdir -p utils.source
    if [ -d guest-utils/scripts ]; then
      for file in guest-utils/scripts/*; do
        [ -e "$file" ] || continue
        ln -s "/igloo_static/$file" "utils.source/$(basename "$file").all"
      done
    fi

    # --- Dockerfile 616-620: legacy arch-name compat renames ------------------
    # No-ops with penguin-tools (it already uses the canonical penguinNames), but
    # kept for byte-parity with the current image.
    for pair in loongarch:loongarch64 ppc64:powerpc64 ppc:powerpc arm64:aarch64; do
      s="''${pair%%:*}"; d="''${pair##*:}"
      if [ -d "$s" ]; then mkdir -p "$d" && cp -a "$s"/. "$d"/ && rm -rf "$s"; fi
    done

    # --- Dockerfile 621: aarch64 vpn aliases armel's (legacy) -----------------
    [ -e armel/vpn ] && ln -sf /igloo_static/armel/vpn /igloo_static/aarch64/vpn || true

    # --- Dockerfile 622-638: utils.bin + flat vpn/console link dirs -----------
    mkdir -p utils.bin vpn console
    for arch in aarch64 armel loongarch64 mipsel mips64eb mips64el mipseb \
                powerpc powerpcle powerpc64 powerpc64le riscv32 riscv64 x86_64; do
      if [ -x "$arch/python/bin/python3" ]; then
        printf '%s\n' '#!/igloo/utils/sh' 'exec /igloo/utils/python/bin/python3 "$@"' > "$arch/python3"
        chmod 0755 "$arch/python3"
      fi
      [ -d "$arch" ] || continue
      for file in "$arch"/*; do
        [ -e "$file" ] || continue
        base="$(basename "$file")"
        case "$base" in
          *vpn*)     ln -sf "/igloo_static/$file" "vpn/vpn.$arch" ;;
          *console*) ln -sf "/igloo_static/$file" "console/console.$arch" ;;
          *)         ln -sf "/igloo_static/$file" "utils.bin/$base.$arch" ;;
        esac
      done
    done
  ''
