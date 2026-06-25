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

  # The PANDA-QEMU fork. THIS IS THE qemu SEAM: today it's the prebuilt release
  # tarball (contents extract under /usr/local). When the qemu/ repo grows its
  # own flake, swap this single input for `url = "github:rehosting/qemu"` (and
  # build penguinQemu from `penguin-qemu.packages.<system>...`) without touching
  # the rest of this flake.
  inputs.penguin-qemu = {
    url = "https://github.com/rehosting/qemu/releases/download/v0.0.10/penguin-qemu.tar.gz";
    flake = false;
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
          penguinQemu = import ./nix/mk-penguin-qemu.nix {
            inherit pkgs;
            src = penguin-qemu;
          };

          muslHeaders = import ./nix/mk-musl-headers.nix {
            inherit pkgs;
            src = musl-src;
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
            pydantic-partial
            junit-xml
            dwarffi
            pengutils
            penguin
          ]);
        in
        {
          inherit pythonEnv penguinQemu iglooStatic muslHeaders nativeHelpersTree penguin pengutils;
          nativeHelper-x86_64 = nativeHelpers.x86_64;
          default = pythonEnv;
        }
      );
    };
}
