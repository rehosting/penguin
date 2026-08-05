# The PANDA-QEMU fork, staged as the /usr/local overlay it occupies in the
# image (Dockerfile: `tar xzf penguin-qemu.tar.gz -C /usr/local`).
#
# THIS IS THE qemu SEAM. `src` is the qemu flake's `penguin-qemu` package output
# (built from source): a tree whose root holds the dirs that belong under
# /usr/local (bin/ include/ lib/ share/), identical in layout to the old
# prebuilt release tarball. Its ELF files carry /nix/store rpaths, so copying
# them preserves the references and nix pulls the qemu runtime closure into the
# image automatically.
{ pkgs, src }:

pkgs.runCommand "penguin-qemu" { } ''
  mkdir -p "$out/usr/local"
  cp -a ${src}/. "$out/usr/local/"
''
