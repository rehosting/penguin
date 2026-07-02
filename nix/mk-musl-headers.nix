# Per-arch musl headers, mirroring Dockerfile 135-146:
#   make ARCH=<arch> prefix=/musl-headers/<arch> install-headers
# `install-headers` only copies/generates headers (no compiler), but musl
# generates alltypes.h/syscall.h/version.h into the build tree, so the source
# must be writable. Output: $out/musl-headers/<arch>/include/...
{ pkgs, src }:

let
  archs = [
    "arm" "aarch64" "mips" "mips64" "mipsn32" "powerpc" "powerpc64"
    "riscv32" "riscv64" "loongarch64" "x86_64" "i386"
  ];
in
pkgs.runCommand "musl-headers"
  {
    nativeBuildInputs = with pkgs.buildPackages; [ gnumake coreutils ];
  }
  ''
    cp -a ${src} src && chmod -R u+w src && cd src
    for arch in ${pkgs.lib.concatStringsSep " " archs}; do
      make ARCH="$arch" DESTDIR="$out" prefix="/musl-headers/$arch" install-headers
    done
  ''
