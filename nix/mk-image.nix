# The penguin runtime image (rehosting/penguin), mirroring the Dockerfile's
# final `penguin` stage. Built with dockerTools.buildLayeredImage like
# fw2tar/flake.nix.
#
# DEFERRED (own follow-up): the firmware-extraction stack -- fw2tar, binwalk,
# unblob, cramfs, custom e2fsprogs and the ~40 apt extractor backends. penguin
# only *runs* rehostings from a pre-made fs.tar.gz; extraction is a separate
# co-located concern best sourced from fw2tar's already-nixified `extractionTools`
# closure. This image therefore covers the `penguin run/explore/...` path; add
# the extractor closure before it fully replaces the Docker image.
{
  pkgs,
  pythonEnv, # includes penguin + pengutils + all runtime deps
  iglooStatic, # $out/igloo_static
  penguinQemu, # $out/usr/local (qemu fork)
  vhostDeviceVsock,
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

  contents = [
    pythonEnv
    iglooStatic
    penguinQemu
    vhostDeviceVsock
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

  extraCommands = ''
    # Writable scratch + HOME (minimal image ships neither).
    mkdir -p tmp && chmod 1777 tmp
    mkdir -p root && chmod 0777 root

    # clang-20 alias on PATH (dropin_compile.py calls it by that exact name).
    mkdir -p usr/local/bin
    ln -sf ${llvm.clang}/bin/clang usr/local/bin/clang-20

    # vhost-device-vsock at the path the Dockerfile installs it (also on PATH).
    ln -sf ${vhostDeviceVsock}/bin/vhost-device-vsock usr/local/bin/vhost-device-vsock

    # rootshell helper (Dockerfile: telnet localhost 4321).
    printf '%s\n%s\n' '#!/bin/sh' 'telnet localhost 4321' > usr/local/bin/rootshell
    chmod +x usr/local/bin/rootshell

    # penguin source trees penguin discovers at runtime.
    mkdir -p pyplugins docs
    cp -a ${pypluginsSrc}/. pyplugins/
    cp -a ${docsSrc}/. docs/

    # Host-facing wrapper + install helpers (users copy these out to the host).
    mkdir -p usr/local/src
    cp ${wrapperSrc} usr/local/src/penguin_wrapper
    cp ${resourcesSrc}/banner.sh            usr/local/bin/banner.sh
    cp ${resourcesSrc}/penguin_install       usr/local/bin/penguin_install
    cp ${resourcesSrc}/penguin_install.local usr/local/bin/penguin_install.local
    chmod +x usr/local/bin/banner.sh usr/local/bin/penguin_install usr/local/bin/penguin_install.local

    # Banner on interactive shells (Dockerfile parity).
    mkdir -p etc
    printf '%s\n' '[ ! -z "$TERM" ] && [ -z "$NOBANNER" ] && /usr/local/bin/banner.sh' >> etc/bash.bashrc
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
in
pkgs.dockerTools.buildLayeredImage {
  name = "rehosting/penguin";
  tag = "latest";
  inherit contents extraCommands config;
}
