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
    url = "github:rehosting/qemu/v0.0.12";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.kernels = {
    url = "https://github.com/rehosting/linux_builder/releases/download/v3.5.33-beta/kernels-latest.tar.gz";
    flake = false;
  };
  inputs.igloo-driver = {
    url = "https://github.com/rehosting/igloo_driver/releases/download/v0.0.85/igloo_driver.tar.gz";
    flake = false;
  };
  # v0.0.25 is the slimmed penguin-tools: it no longer ships the forked guest
  # tools (console/busybox/guesthopper/vpnguin) or libnvram -- penguin stages
  # those from their own flakes (see below). It provides just the debug-tool
  # closures + drop-in musl sysroots.
  inputs.penguin-tools = {
    url = "https://github.com/rehosting/penguin-tools/releases/download/v0.0.25/penguin-tools.tar.gz";
    flake = false;
  };

  # Forked guest utilities that build themselves (their own flakes cross-build
  # every guest arch). penguin consumes each directly and stages its
  # /igloo_static fragment, so a tool change no longer needs a penguin-tools
  # re-release -- just bump the pinned tag here. `follows nixpkgs` keeps the
  # cross toolchains + rust closures shared through Cachix (no duplicate
  # closures). Pinned to version tags (reproducible); bump on a new tool release.
  inputs.console = {
    url = "github:rehosting/console/v1.0.9";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  # busybox is fetched via git+https (not the github: tarball) because the repo
  # still carries a vestigial `include/libhc` submodule gitlink (the flake gets
  # libhc from its own input, so the submodule is unused). A codeload tarball
  # packs that gitlink in a way our CI registry proxy repacks differently from a
  # plain fetch, giving an environment-dependent narHash. A real git checkout
  # with submodules=1 is content-deterministic and avoids that mismatch. The rev
  # is v0.0.20's commit; pinned explicitly so the tag ref can't drift.
  inputs.busybox = {
    url = "git+https://github.com/rehosting/busybox?ref=refs/tags/v0.0.20&rev=34a9307c35b7d1b5e1672d86bd6b26877c2f0639&submodules=1";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.guesthopper = {
    url = "github:rehosting/guesthopper/v1.0.23";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  # vpnguin v1.0.29 carries the owned-interface datapaths matching penguin's
  # vpn.py (WAN bridge / --own-iface). This pin is what fixes the old skew where
  # penguin-tools deliberately held vpnguin at v1.0.26 (4-field) behind penguin.
  inputs.vpnguin = {
    url = "github:rehosting/vpnguin/v1.0.29";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  # libnvram: source only -- penguin compiles nvram.c into lib_inject per
  # project (clang-20), so we just need the .c/.h tree, not a build. Consumed
  # directly here rather than routed through penguin-tools.
  inputs.libnvram = {
    url = "github:rehosting/libnvram/e013c0686facbb62df09b30d0d5b92dd75fd4d58";
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
  # re-deriving fw2tar/unblob/binwalk/extractor backends. We make fw2tar (and,
  # via fw2tar, unblob) follow our nixpkgs so the extraction stack shares the
  # same CPython/glibc as penguin instead of shipping duplicate interpreters.
  inputs.fw2tar = {
    url = "github:rehosting/fw2tar/b9e72b0dd8475715eb5d6cb85ac60ee0d1f2d7e5";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      penguin-qemu,
      kernels,
      igloo-driver,
      penguin-tools,
      console,
      busybox,
      guesthopper,
      vpnguin,
      libnvram,
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

          # Package version (penguin reads penguin/version.txt at runtime for
          # `penguin --version`). The version is tag-derived (setuptools_scm
          # style, e.g. 3.0.47.dev21+g<rev>), but a pure Nix flake cannot see
          # git *tags* -- only self.rev -- so the value is computed where the
          # tags live and injected via PENGUIN_OVERRIDE_VERSION (read here with
          # builtins.getEnv, which needs --impure; "" in pure eval):
          #   * release: the publish workflow passes the bumped semver;
          #   * ./penguin --build and CI: pass `git describe`-derived version.
          # The fallback below is only hit by a bare `nix build` with no
          # injected version -- it mirrors the old Dockerfile's
          # setuptools_scm-produced-nothing case (0.0.0.dev0), tagged with the
          # commit for traceability.
          overrideVersion = builtins.getEnv "PENGUIN_OVERRIDE_VERSION";
          gitRev = self.shortRev or self.dirtyShortRev or "unknown";
          penguinVersion = if overrideVersion != "" then overrideVersion else "0.0.0.dev0+g${gitRev}";

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

          # Penguin's full runtime dependency set, the single source of truth
          # shared by both the penguin package (so its subprocess'd console
          # scripts' wrappers carry these) and pythonEnv (the interpreter the
          # image runs). Over-declaring here is harmless; under-declaring breaks
          # gen_config/gen_image when penguin shells out to them.
          penguinRuntimeDeps = (
            with py.pkgs;
            [
              coloredlogs
              ipython
              levenshtein
              jinja2
              lxml
              lz4
              pydantic
              pyelftools
              pyyaml
              pyvis
              jsonschema
              click
              art
              setuptools
              sqlalchemy
              jc
              ujson
              cxxfilt
              pdoc
              ratarmountcore
              yamlcore
              networkx
              rich
              cffi
              # pyplugins/testing/vpn_test.py imports requests directly. The old
              # Docker image only had it transitively (via poetry, now pruned),
              # so declare it explicitly.
              requests
              # keystone is imported unconditionally by the essential core plugin
              # pyplugins/core/live_image.py; capstone backs apis/unwind.py
              # (guarded). Both are core to the rehosting assembler/disassembler.
              keystone-engine
              capstone
            ]
          )
          # ratarmountcore[full]: penguin reads the firmware rootfs tarball at
          # runtime via ratarmountcore (portal iterator / hypercall handler).
          # The bare package ships no compression backends, so opening the gzip
          # fs.tar.gz fails ("unrecognized format" -> StaticFS never loads ->
          # the run produces no .ran). The Docker image installed
          # ratarmountcore[full]; mirror that with its optional-dependency set.
          ++ py.pkgs.ratarmountcore.optional-dependencies.full
          ++ [
            pydantic-partial
            junit-xml
            dwarffi
            pengutils
          ];

          penguin = py.pkgs.callPackage ./nix/penguin.nix {
            src = lib.fileset.toSource {
              root = ./src;
              fileset = ./src;
            };
            dependencies = penguinRuntimeDeps;
            version = penguinVersion;
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
              inherit archName;
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

          # Forked guest tools that now build themselves. Their dists are the
          # /igloo_static fragment each tool owns; mk-igloo-static.nix `cp -a`s
          # them in AFTER penguin-tools, so they win over any stale copy still
          # shipped in the penguin-tools tarball during the transition. Always
          # sourced from the x86_64-linux cross-build (guest binaries are
          # host-independent; the real build host + CI is x86_64-linux, matching
          # penguin-tools' own x86_64-only flake).
          toolDists = [
            console.packages.x86_64-linux.dist
            busybox.packages.x86_64-linux.dist
            guesthopper.packages.x86_64-linux.dist
            vpnguin.packages.x86_64-linux.dist
          ];

          iglooStatic = import ./nix/mk-igloo-static.nix {
            inherit
              pkgs
              kernels
              igloo-driver
              penguin-tools
              toolDists
              libnvram
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

          # The interpreter the image runs: the shared runtime deps plus penguin
          # itself. cffi (in penguinRuntimeDeps) also backs the qemu fork's CFFI
          # API-mode env modules (_penguin_qemu_env_*.so import _cffi_backend).
          pythonEnv = py.withPackages (_ps: penguinRuntimeDeps ++ [ penguin ]);

          # The docs toolchain (pyplugins/docgen/doc_generator.py imports sphinx
          # in-process and shells out to sphinx-apidoc + pdflatex). The docs
          # image is the runtime image plus these sphinx packages in the *same*
          # interpreter and a LaTeX toolchain on PATH -- mirroring the sphinx/
          # texlive set the old Dockerfile docs stage pip/apt-installed.
          docsPythonEnv = py.withPackages (
            ps:
            penguinRuntimeDeps
            ++ [ penguin ]
            ++ (with ps; [
              sphinx
              sphinx-rtd-theme
              myst-parser
              sphinx-copybutton
              furo
              linkify-it-py
              sphinx-prompt
              sphinxemoji
              sphinx-notfound-page
              sphinx-last-updated-by-git
              sphinx-autobuild
            ])
          );

          # Shared across the runtime and docs images; only pythonEnv/tag/
          # extraContents differ between them.
          mkImage =
            args:
            import ./nix/mk-image.nix (
              {
                inherit pkgs iglooStatic penguinQemu vhostDeviceVsock;
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
              }
              // args
            );

          dockerImage = mkImage { inherit pythonEnv; };

          # Streaming variant of the runtime image (same layers, not realised as
          # a .tar.gz in the store). The output is a script that emits the image
          # tarball to stdout -- e.g. `nix run .#dockerImageStream | docker load`
          # or pipe straight to a registry push in CI.
          dockerImageStream = mkImage {
            inherit pythonEnv;
            stream = true;
          };

          # The release docs image (rehosting/penguin:docs): the runtime image
          # plus the in-image sphinx toolchain and a LaTeX engine for the PDF
          # build. texlive scheme-medium provides pdflatex + latexmk + the
          # latex-extra/fonts packages the old Dockerfile docs stage apt-installed.
          docsImage = mkImage {
            pythonEnv = docsPythonEnv;
            tag = "docs";
            extraContents = [ pkgs.texliveMedium ];
          };
        in
        {
          inherit pythonEnv penguinQemu iglooStatic muslHeaders nativeHelpersTree penguin pengutils vhostDeviceVsock dockerImage dockerImageStream docsImage;
          nativeHelper-x86_64 = nativeHelpers.x86_64;
          default = pythonEnv;
        }
      );

      # Host-side dev shell for the `--pydev`-style loop: the assembled penguin
      # Python interpreter (all runtime deps + the penguin/pengutils/pyplugins
      # packages) with the *live worktree* sources layered on top via PYTHONPATH
      # so edits take effect without a rebuild. This is for host tooling --
      # imports, linting, gen_docs, config schema -- NOT emulation (PANDA-QEMU,
      # igloo_static and the guest tools only run inside the image).
      #
      # The shellHook re-prepends the interpreter to PATH *after* rc files run,
      # so it wins against a pyenv `init` that re-prepends ~/.pyenv/shims on
      # shell startup (otherwise the shim shadows this python3).
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          pythonEnv = self.packages.${system}.pythonEnv;
        in
        {
          default = pkgs.mkShell {
            packages = [ pythonEnv ];
            shellHook = ''
              export PATH="${pythonEnv}/bin:$PATH"
              export PYTHONPATH="$PWD/src:$PWD/pengutils:$PWD/pyplugins''${PYTHONPATH:+:$PYTHONPATH}"
              hash -r
              # penguin/__init__.py opens version.txt at import; it is generated
              # at build time (gitignored) and absent from the live worktree, so
              # importing from src/ would crash. Drop a dev placeholder if missing.
              if [ -f "$PWD/src/penguin/__init__.py" ] && [ ! -f "$PWD/src/penguin/version.txt" ]; then
                echo "0.0.0.dev0+devshell" > "$PWD/src/penguin/version.txt"
              fi
              echo "penguin devshell: $(python3 --version) @ ${pythonEnv}/bin/python3"
              echo "  live sources on PYTHONPATH: src/ pengutils/ pyplugins/"
            '';
          };
        }
      );
    };
}
