# The PANDA-QEMU fork, staged as the /usr/local overlay it occupies in the
# image (Dockerfile: `tar xzf penguin-qemu.tar.gz -C /usr/local`).
#
# THIS IS THE qemu SEAM. Today `src` is the prebuilt release tarball (its root
# is the set of dirs that belong under /usr/local: bin/ include/ lib/ share/).
# When the qemu/ repo grows its own flake, the caller swaps the `penguin-qemu`
# flake input for `github:rehosting/qemu` and passes that package's output here
# instead -- nothing else in this flake needs to change.
{ pkgs, src }:

pkgs.runCommand "penguin-qemu" { } ''
  mkdir -p "$out/usr/local"
  cp -a ${src}/. "$out/usr/local/"
''
