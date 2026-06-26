{
  description = "Penguin: configuration-based firmware rehosting framework";

  nixConfig = {
    extra-substituters = [ "https://rehosting-tools.cachix.org" ];
    extra-trusted-public-keys = [
      "rehosting-tools.cachix.org-1:iNKSaFwG7MfGn6Fk7oTmIcLHqfffQ+cQIE5gWc6MlY0="
    ];
  };

  # Pinned to the same nixpkgs commit as penguin-tools so the two flakes share a
  # store closure (and Cachix hits).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/b6067cc0127d4db9c26c79e4de0513e58d0c40c9";

  # --- Prebuilt release artifacts, pinned by flake.lock ----------------------
  # Each is a release tarball consumed as an opaque source tree (no flake of its
  # own); flake.lock records the narHash. These replace the Dockerfile
  # `get_release.sh` downloads (asset URLs: .../releases/download/v<ver>/<asset>).

  # The PANDA-QEMU fork. THIS IS THE qemu SEAM: it's now the qemu repo's own
  # flake (built from source), pinned by release tag. We consume the flake's
  # `penguin-qemu` package output (not a fetchurl of the tarball): the Nix-built
  # libqemu-system-*.so / qemu-img carry rpaths into /nix/store, so the package
  # output drags its closure (glibc/pixman/libfdt/glib/slirp) into the image --
  # a plain tarball would leave those dangling. It pins the same nixpkgs as us
  # (follows), so the closure is shared, and ships CFFI env modules built
  # against this flake's CPython (3.13) so they match penguin's interpreter.
  inputs.penguin-qemu = {
    url = "github:rehosting/qemu/v0.0.11";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.kernels = {
    url = "https://github.com/rehosting/linux_builder/releases/download/v3.5.33-beta/kernels-latest.tar.gz";
    flake = false;
  };
  inputs.igloo-driver = {
    url = "https://github.com/rehosting/igloo_driver/releases/download/v0.0.82/igloo_driver.tar.gz";
    flake = false;
  };
  inputs.penguin-tools = {
    url = "https://github.com/rehosting/penguin-tools/releases/download/v0.0.14/penguin-tools.tar.gz";
    flake = false;
  };

  # musl source (headers only -- install-headers, no compiler). Dockerfile builds
  # per-arch headers into /igloo_static/musl-headers/<arch>.
  inputs.musl-src = {
    url = "https://musl.libc.org/releases/musl-1.2.5.tar.gz";
    flake = false;
  };
  # ltrace prototype .conf files (the etc/ tree); fetched from Fedora's pkg store
  # because ltrace.org drops old versions. Path embeds the upstream md5.
  inputs.ltrace-src = {
    url = "https://src.fedoraproject.org/repo/pkgs/ltrace/ltrace-0.7.91.tar.bz2/9db3bdee7cf3e11c87d8cc7673d4d25b/ltrace-0.7.91.tar.bz2";
    flake = false;
  };
  # vhost-device: the host-side vsock device backend penguin runs alongside qemu
  # (Dockerfile rust_builder builds --bin vhost-device-vsock, static).
  inputs.vhost-device = {
    url = "github:rust-vmm/vhost-device/vhost-device-vsock-v0.2.0";
    flake = false;
  };
  # fw2tar (already nixified): penguin co-locates the firmware-extraction stack
  # in its image and sources it from fw2tar's extractionBundle rather than
  # re-deriving fw2tar/unblob/binwalk/extractor backends. fw2tar pins its own
  # nixpkgs (unstable); we follow it for its closure, not ours.
  inputs.fw2tar.url = "github:rehosting/fw2tar/2160c6d9d0f5c4cd250e92f380d4280610b242ed";

  outputs =
    {
      self,
      nixpkgs,
      penguin-qemu,
      kernels,
      igloo-driver,
      penguin-tools,
      musl-src,
      ltrace-src,
      vhost-device,
      fw2tar,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          lib = pkgs.lib;

          # ---- Penguin core Python environment ----------------------------
          # The post-prune dependency set (angr/symex and the 13 unused
          # packages are gone). Firmware-extraction Python backends (binwalk
          # fork, unblob, jefferson, ubi_reader, yaffshiv, vmlinux-to-elf,
          # python-magic) are intentionally NOT here -- they belong to the
          # extraction stack, which is sourced from fw2tar's closure (deferred).
          #
          # python3 (nixpkgs default) rather than the Dockerfile's 3.10; bump
          # down only if a dep refuses to build.
          py = pkgs.python3;

          # The three core deps not packaged in nixpkgs.
          pydantic-partial = py.pkgs.callPackage ./nix/pydantic-partial.nix { };
          junit-xml = py.pkgs.callPackage ./nix/junit-xml.nix { };
          dwarffi = py.pkgs.callPackage ./nix/dwarffi.nix { };

          # Penguin's own packages (Dockerfile: pip install -e /pengutils, /pkg).
          pengutils = py.pkgs.callPackage ./nix/pengutils.nix {
            src = lib.fileset.toSource {
              root = ./pengutils;
              fileset = ./pengutils;
            };
          };
          penguin = py.pkgs.callPackage ./nix/penguin.nix {
            src = lib.fileset.toSource {
              root = ./src;
              fileset = ./src;
            };
          };

          # ---- The qemu seam + /igloo_static --------------------------------
          # The qemu flake's `penguin-qemu` output is the unpacked tree
          # (bin/include/lib/share) -- same layout the prebuilt tarball had, so
          # mk-penguin-qemu.nix stages it identically; its store-path rpaths pull
          # the qemu runtime closure into the image.
          penguinQemu = import ./nix/mk-penguin-qemu.nix {
            inherit pkgs;
            src = penguin-qemu.packages.${system}.penguin-qemu;
          };

          muslHeaders = import ./nix/mk-musl-headers.nix {
            inherit pkgs;
            src = musl-src;
          };

          vhostDeviceVsock = pkgs.callPackage ./nix/vhost-device-vsock.nix {
            src = vhost-device;
          };

          # ---- Guest native helpers (send_hypercall etc.), cross-built -------
          nativeArchs = import ./nix/native-archs.nix;
          nativeSrc = lib.fileset.toSource {
            root = ./guest-utils/native;
            fileset = ./guest-utils/native;
          };
          mkMuslCrossPkgs =
            archSpec:
            import nixpkgs {
              inherit system;
              config.allowUnsupportedSystem = true;
              crossSystem = archSpec.muslCrossSystem;
            };
          mkNativeHelpers =
            archName: archSpec:
            import ./nix/mk-native-helpers.nix {
              crossPkgs = mkMuslCrossPkgs archSpec;
              src = nativeSrc;
              extraCFlags = archSpec.extraCFlags or [ ];
            };
          nativeHelpers = lib.mapAttrs mkNativeHelpers nativeArchs;
          # Assemble into out/<arch>/<bin>, the layout the Docker cross_builder
          # COPYs into /igloo_static/.
          nativeHelpersTree = pkgs.runCommand "penguin-native-helpers-tree" { } (
            lib.concatStringsSep "\n" (
              lib.mapAttrsToList (archName: drv: ''
                mkdir -p "$out/${archName}"
                cp -a ${drv}/. "$out/${archName}/"
              '') nativeHelpers
            )
          );

          iglooStatic = import ./nix/mk-igloo-static.nix {
            inherit
              pkgs
              kernels
              igloo-driver
              penguin-tools
              muslHeaders
              nativeHelpersTree
              ;
            guestUtils = lib.fileset.toSource {
              root = ./guest-utils;
              fileset = ./guest-utils;
            };
            ltraceSrc = ltrace-src;
            ltraceNvramConf = ./src/resources/ltrace_nvram.conf;
          };

          pythonEnv = py.withPackages (ps: [
            ps.coloredlogs
            ps.ipython
            ps.levenshtein
            ps.jinja2
            ps.lxml
            ps.lz4
            ps.pydantic
            ps.pyelftools
            ps.pyyaml
            ps.pyvis
            ps.jsonschema
            ps.click
            ps.art
            ps.setuptools
            ps.sqlalchemy
            ps.jc
            ps.ujson
            ps.cxxfilt
            ps.pdoc
            ps.ratarmountcore
            ps.yamlcore
            ps.networkx
            ps.rich # pengutils dep
            # Runtime for the qemu fork's CFFI API-mode env modules
            # (_penguin_qemu_env_*.so import _cffi_backend) + penguin's qemu
            # compat layer.
            ps.cffi
            pydantic-partial
            junit-xml
            dwarffi
            pengutils
            penguin
          ]);

          dockerImage = import ./nix/mk-image.nix {
            inherit pkgs pythonEnv iglooStatic penguinQemu vhostDeviceVsock;
            extractionBundle = fw2tar.packages.${system}.extractionBundle;
            pypluginsSrc = lib.fileset.toSource {
              root = ./pyplugins;
              fileset = ./pyplugins;
            };
            docsSrc = lib.fileset.toSource {
              root = ./docs;
              fileset = ./docs;
            };
            wrapperSrc = ./penguin;
            resourcesSrc = ./src/resources;
          };
        in
        {
          inherit pythonEnv penguinQemu iglooStatic muslHeaders nativeHelpersTree penguin pengutils vhostDeviceVsock dockerImage;
          nativeHelper-x86_64 = nativeHelpers.x86_64;
          default = pythonEnv;
        }
      );
    };
}
