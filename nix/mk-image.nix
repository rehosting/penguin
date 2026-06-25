# The penguin runtime image (rehosting/penguin), mirroring the Dockerfile's
# final `penguin` stage. Built with dockerTools.buildLayeredImage like
# fw2tar/flake.nix.
#
# The firmware-extraction stack (fw2tar, unblob, binwalk, the extractor
# backends) is kept co-located per project decision and sourced from fw2tar's
# already-nixified `extractionBundle` (a cross-flake input) rather than
# re-derived here. The custom mke2fs-with-libarchive build is not yet included.
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

  # clang-20 / ld.lld: penguin's dropin_compile.py invokes `clang-20
  # -fuse-ld=lld` to compile per-project init.d/*.c. nixpkgs names the binary
  # `clang`; provide a `clang-20` alias (+ lld for ld.lld).
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
    ln -s ${llvm.clang}/bin/clang "$out/usr/local/bin/clang-20"
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
  '';

  config = {
    Cmd = [ "/usr/local/bin/banner.sh" ];
    Env = [
      "PATH=/usr/local/bin:/bin"
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
  contents = [ rootEnv ];
  inherit extraCommands config;
}
