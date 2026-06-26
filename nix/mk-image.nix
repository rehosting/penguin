# The penguin runtime image (rehosting/penguin), mirroring the Dockerfile's
# final `penguin` stage.
#
# Unlike the sealed fw2tar/penguin-tools images (built from `scratch`), penguin
# is an interactive analysis tool: it runs guest firmware, shells out
# constantly, compiles init.d dropins at runtime, and users exec into it and
# expect a normal userland (+ apt). So this image is layered on top of the same
# ubuntu:22.04 base the Dockerfile used (dockerTools.buildLayeredImage with
# `fromImage`), with all the heavy components (python env, the qemu fork,
# /igloo_static, the extraction stack, clang) supplied by Nix on top. The
# Ubuntu base provides the FHS glibc userland, coreutils, and apt; the Nix
# layers provide everything the Dockerfile previously apt-installed or built.
#
# The firmware-extraction stack (fw2tar, unblob, binwalk, the extractor
# backends) is kept co-located per project decision and sourced from fw2tar's
# already-nixified `extractionBundle` (a cross-flake input) rather than
# re-derived here.
{
  pkgs,
  pythonEnv, # includes penguin + pengutils + all runtime deps
  iglooStatic, # $out/igloo_static
  penguinQemu, # $out/usr/local (qemu fork)
  vhostDeviceVsock,
  extractionBundle, # fw2tar.extractionBundle: fw2tar/unblob/binwalk + backends
  pypluginsSrc, # the pyplugins/ tree
  docsSrc, # the docs/ tree
  wrapperSrc, # the host ./penguin wrapper script
  resourcesSrc, # src/resources (banner.sh, penguin_install[.local])
}:

let
  lib = pkgs.lib;

  # The ubuntu:22.04 base layer (same base the Dockerfile used). Pinned by
  # digest so the build is reproducible; refresh both fields together with
  # `nix run nixpkgs#nix-prefetch-docker -- --image-name ubuntu --image-tag 22.04`.
  ubuntuBase = pkgs.dockerTools.pullImage {
    imageName = "ubuntu";
    imageDigest = "sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d";
    hash = "sha256-L5hEr4S/AnNswxQc0dqDf85QZtEvQtVfes4r9n4q6mc=";
    finalImageName = "ubuntu";
    finalImageTag = "22.04";
  };

  # clang-20 / ld.lld: penguin's dropin_compile.py invokes `clang-20
  # -fuse-ld=lld` as a *cross* compiler (`--target=<arch>-linux-musl...
  # --sysroot=/igloo_static/sysroots/<arch>`) for every guest arch. It must be
  # the UNWRAPPED clang: nixpkgs' cc-wrapper'd clang force-injects the host
  # glibc dev include/lib paths (-idirafter .../glibc-*-dev/include), which
  # shadow the musl sysroot headers and make `#include <fcntl.h>` pull host
  # glibc -> `gnu/stubs-32.h not found`. clang-unwrapped honors --target/
  # --sysroot like a plain cross clang. (ld.lld still comes from llvm.lld.)
  llvm = pkgs.llvmPackages_20;

  # Overlay package: everything that must live at a specific absolute path
  # (/usr/local/..., /pyplugins, /docs, /etc). penguinQemu also populates
  # /usr/local, so these can't be created by extraCommands on top of the
  # read-only merged content tree -- they must be a *content* themselves, so
  # buildEnv unions them with qemu's /usr/local. Symlink targets are store-
  # absolute (the store is in the image), matching how penguin resolves them.
  overlay = pkgs.runCommand "penguin-overlay" { } ''
    mkdir -p "$out/usr/local/bin" "$out/usr/local/src" "$out/etc"

    # clang-20: dropin_compile.py invokes it by that exact name (-fuse-ld=lld;
    # ld.lld comes from llvm.lld on PATH).
    ln -s ${llvm.clang-unwrapped}/bin/clang "$out/usr/local/bin/clang-20"
    # vhost-device-vsock at the Dockerfile path (also on PATH).
    ln -s ${vhostDeviceVsock}/bin/vhost-device-vsock "$out/usr/local/bin/vhost-device-vsock"

    # rootshell helper (Dockerfile: telnet localhost 4321).
    printf '%s\n%s\n' '#!/bin/sh' 'telnet localhost 4321' > "$out/usr/local/bin/rootshell"
    chmod +x "$out/usr/local/bin/rootshell"

    # Host-facing wrapper + install helpers (users copy these out to the host).
    cp ${wrapperSrc}                          "$out/usr/local/src/penguin_wrapper"
    cp ${resourcesSrc}/banner.sh              "$out/usr/local/bin/banner.sh"
    cp ${resourcesSrc}/penguin_install        "$out/usr/local/bin/penguin_install"
    cp ${resourcesSrc}/penguin_install.local  "$out/usr/local/bin/penguin_install.local"
    chmod +x "$out/usr/local/bin/banner.sh" "$out/usr/local/bin/penguin_install" "$out/usr/local/bin/penguin_install.local"

    # penguin source trees penguin discovers at runtime.
    mkdir -p "$out/pyplugins" "$out/docs"
    cp -a ${pypluginsSrc}/. "$out/pyplugins/"
    cp -a ${docsSrc}/.      "$out/docs/"

    # Banner on interactive shells (Dockerfile parity).
    printf '%s\n' '[ ! -z "$TERM" ] && [ -z "$NOBANNER" ] && /usr/local/bin/banner.sh' > "$out/etc/bash.bashrc"
  '';

  contents = [
    overlay
    pythonEnv
    iglooStatic
    penguinQemu
    vhostDeviceVsock
    extractionBundle
    llvm.clang
    llvm.lld
    # gen_image.py runs `mke2fs -t ext4 -d <tarball>` to build+populate the
    # guest ext4 image directly from the rootfs tarball. nixpkgs e2fsprogs
    # (1.47.3) is already built --with-libarchive, so this needs no custom build
    # (the Dockerfile's e2fsprogs_builder stage is obsolete). qemu-img comes from
    # penguinQemu.
    pkgs.e2fsprogs
    pkgs.bashInteractive
    pkgs.coreutils
    pkgs.findutils
    pkgs.gnugrep
    pkgs.gnused
    pkgs.gawk
    pkgs.gnutar
    pkgs.gzip
    pkgs.which
    pkgs.binutils # nm / readelf (symbols.py via shutil.which)
    pkgs.graphviz # dot (graph rendering)
    pkgs.fakeroot
    pkgs.pigz
    pkgs.nmap
    pkgs.glow
    pkgs.gum
    pkgs.ripgrep
    pkgs.vim
    pkgs.inetutils # telnet (rootshell helper)
    pkgs.sudo
    # /etc/passwd + /etc/group with a root entry (tools that getpwuid()).
    pkgs.dockerTools.fakeNss
  ];

  # Only genuinely-new writable dirs no content provides; everything at a fixed
  # path lives in `overlay` above (so it merges via buildEnv, not on top of the
  # read-only content tree).
  extraCommands = ''
    mkdir -p tmp && chmod 1777 tmp
    mkdir -p root && chmod 0777 root
    # qemu writes its `snapshot=on` drive overlay to a temp file under /var/tmp
    # (qemu's get_tmp_filename), so the image needs a *writable* /var/tmp or the
    # guest fails to launch: "Could not open temporary file
    # '/var/tmp/vl.XXXXXX': No such file". fakeNss provides /var/empty, so
    # buildEnv collapses `var` into a symlink into the read-only store --
    # mkdir'ing into it fails ("Permission denied"). Replace the symlink with a
    # real, writable dir; recreate var/empty (fakeNss's nobody home) alongside
    # the writable tmp. (cp -a from the store would preserve its read-only mode,
    # so recreate fresh instead.)
    rm -rf var
    mkdir -p var/empty var/tmp && chmod 1777 var/tmp
  '';

  config = {
    Cmd = [ "/usr/local/bin/banner.sh" ];
    Env = [
      # Nix-provided tools live under /usr/local/bin and the merged /bin; the
      # ubuntu base's userland (apt, dpkg, etc.) is in /usr/bin and /sbin.
      "PATH=/usr/local/bin:/bin:/usr/bin:/sbin:/usr/sbin"
      "HOME=/root"
      "TMPDIR=/tmp"
      "TZ=America/New_York"
      "LC_ALL=C.UTF-8"
      "LANG=C.UTF-8"
      "PIP_ROOT_USER_ACTION=ignore"
      # qemu fork ships shared libs under /usr/local/lib.
      "LD_LIBRARY_PATH=/usr/local/lib"
    ];
  };
  # Pre-merge all contents into one root. With this many packages, several
  # provide /sbin (some as a dir, some as a symlink), which buildLayeredImage's
  # per-path merge rejects ("sbin: File exists"). buildEnv with ignoreCollisions
  # resolves it into a single conflict-free tree.
  rootEnv = pkgs.buildEnv {
    name = "penguin-root";
    ignoreCollisions = true;
    paths = contents;
  };
in
pkgs.dockerTools.buildLayeredImage {
  name = "rehosting/penguin";
  tag = "latest";
  # Layer the Nix contents on top of the ubuntu:22.04 base (FHS userland + apt).
  fromImage = ubuntuBase;
  contents = [ rootEnv ];
  inherit extraCommands config;
}
