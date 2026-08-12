{
  description = "Penguin: configuration-based firmware rehosting framework";

  nixConfig = {
    extra-substituters = [ "https://rehosting-tools.cachix.org" ];
    extra-trusted-public-keys = [
      "rehosting-tools.cachix.org-1:iNKSaFwG7MfGn6Fk7oTmIcLHqfffQ+cQIE5gWc6MlY0="
    ];
  };

  # The one input pinned by hand rather than left to flake.lock, deliberately:
  # it must be the SAME commit penguin-tools pins, or the two flakes stop sharing
  # a store closure (and Cachix hits). Tracking a channel branch would let them
  # drift apart on any update, so this is pinned until penguin-tools moves too.
  # Everything else records its revision in flake.lock and is bumped with
  # `nix flake update <input>` (see ./nix-dev.sh).
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
  # NOTE: bumping this is behaviour-changing (emulator). flake.lock holds the
  # revision; move it deliberately, never as part of a bulk update.
  inputs.penguin-qemu = {
    url = "github:rehosting/qemu";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.kernels = {
    url = "https://github.com/rehosting/linux_builder/releases/download/v3.6.5/kernels-latest.tar.gz";
    flake = false;
  };
  inputs.igloo-driver = {
    url = "https://github.com/rehosting/igloo_driver/releases/download/v0.0.94/igloo_driver.tar.gz";
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
  # re-release -- just relock here. `follows nixpkgs` keeps the cross toolchains
  # + rust closures shared through Cachix (no duplicate closures).
  #
  # No ref in the URL: flake.lock already records the exact revision, so writing
  # the tag here too was a second, hand-maintained pin of the same thing. Bump
  # with `nix flake update <input>` (or ./nix-dev.sh bump <input>), which is also
  # what lets dependabot-style automation work. `./nix-dev.sh pins` still reports
  # each locked revision against the newest upstream *release*, so you can see
  # when a lock sits behind a tag or on an untagged commit.
  inputs.console = {
    url = "github:rehosting/console";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  # This needed a `git+https…&submodules=1` workaround until busybox v0.0.22:
  # the repo carried
  # a vestigial `include/libhc` submodule gitlink (unused -- the flake gets libhc
  # from its own input), and a codeload tarball packed that gitlink in a way our
  # CI registry proxy repacked differently from a plain fetch, so the narHash was
  # environment-dependent. busybox#14 removed the gitlink, so the tarball is
  # deterministic again and the workaround is retired.
  inputs.busybox = {
    url = "github:rehosting/busybox";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.guesthopper = {
    url = "github:rehosting/guesthopper";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  # vpnguin v1.0.29 carries the owned-interface datapaths matching penguin's
  # vpn.py (WAN bridge / --own-iface). This pin is what fixes the old skew where
  # penguin-tools deliberately held vpnguin at v1.0.26 (4-field) behind penguin.
  inputs.vpnguin = {
    url = "github:rehosting/vpnguin";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  # libnvram: source only -- penguin compiles nvram.c into lib_inject per
  # project (clang-20), so we just need the .c/.h tree, not a build. Consumed
  # directly here rather than routed through penguin-tools.
  inputs.libnvram = {
    url = "github:rehosting/libnvram";
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
  # fw2tar's own lock is what selects the extractor set, so relocking this input
  # also moves unblob: the currently locked revision (v2.0.24) is where the
  # cpio/jffs2/arpy, ext-permission and cramfs-on-opposite-endian fixes came in.
  # Extraction behaviour changes here -- validate against the corpus when
  # bumping, don't assume it's inert.
  inputs.fw2tar = {
    url = "github:rehosting/fw2tar";
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

          # Creation timestamp stamped into the image config. dockerTools
          # defaults it to the epoch, which is reproducible but reports every
          # release as 56 years old in `docker images` / registry UIs.
          #
          # self.lastModifiedDate is the HEAD commit's date, so this stays a
          # pure function of the source (same commit -> same image) while
          # meaning something to a user. It is also the commit date for a *dirty*
          # tree, so local rebuilds don't churn the image derivation between
          # commits.
          imageCreated =
            let
              d = self.lastModifiedDate; # "YYYYMMDDHHMMSS", UTC
              at = start: len: builtins.substring start len d;
            in
            "${at 0 4}-${at 4 2}-${at 6 2}T${at 8 2}:${at 10 2}:${at 12 2}Z";

          # Standard OCI annotations. The Dockerfile set no LABELs at all, so
          # `docker inspect rehosting/penguin` reported `Labels: null` and a
          # pulled image carried nothing tying it back to the commit that built
          # it -- `revision` is the one that makes a user-reported image
          # reproducible on our side. These live in the config blob, so they add
          # a few hundred bytes and leave every layer digest untouched.
          imageLabels = {
            "org.opencontainers.image.title" = "penguin";
            "org.opencontainers.image.description" =
              "Configuration-based firmware rehosting framework";
            "org.opencontainers.image.source" = "https://github.com/rehosting/penguin";
            "org.opencontainers.image.url" = "https://github.com/rehosting/penguin";
            "org.opencontainers.image.documentation" = "https://docs.rehosti.ng/";
            "org.opencontainers.image.licenses" = "GPL-2.0-or-later";
            "org.opencontainers.image.vendor" = "MIT Lincoln Laboratory";
            "org.opencontainers.image.created" = imageCreated;
            "org.opencontainers.image.version" = penguinVersion;
            # Full rev, not the short one used for the version string: this is
            # what someone pastes back to us from `docker inspect`.
            "org.opencontainers.image.revision" = self.rev or self.dirtyRev or "unknown";
          };

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

          # The two core deps not packaged in nixpkgs. (junit-xml IS in nixpkgs,
          # at the same 1.9 we need, so it comes from py.pkgs below rather than
          # a local derivation.)
          pydantic-partial = py.pkgs.callPackage ./nix/pydantic-partial.nix { };
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
            py.pkgs.junit-xml
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

          # Forked guest tools that build themselves. Their dists are the
          # /igloo_static fragment each tool owns; mk-igloo-static.nix `cp -a`s
          # them in AFTER penguin-tools. penguin-tools no longer ships these
          # tools (dropped as of v0.0.25), so the ordering is a defensive
          # belt-and-suspenders rather than a live override. Always sourced from
          # the x86_64-linux cross-build (guest binaries are host-independent;
          # the real build host + CI is x86_64-linux, matching penguin-tools'
          # own x86_64-only flake).
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

          # The same interpreter plus the test runner, for checks.unit-tests.
          # src/pyproject.toml's [test] extra is penguinRuntimeDeps + pytest, so
          # reuse the runtime list instead of restating it.
          testPythonEnv = py.withPackages (
            ps:
            penguinRuntimeDeps
            ++ [ penguin ]
            ++ (with ps; [
              pytest
              pytest-asyncio
            ])
          );

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
                created = imageCreated;
                labels = imageLabels;
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

          # Streaming image tagged by the *nix build* rather than `latest`:
          # `tag = null` makes dockerTools derive the tag from the image's
          # layer-closure hash, so each distinct build loads as a unique,
          # reproducible `rehosting/penguin:<hash>` (same inputs -> same tag,
          # any change -> new tag). This backs `nix run .#load` (and the default
          # `nix run`), which streams it straight into the local docker/podman
          # daemon -- no `:latest` collision, no multi-GB tarball in the store.
          dockerImageStreamHashed = mkImage {
            inherit pythonEnv;
            stream = true;
            tag = null;
          };

          # The portable image (rehosting/penguin:portable): identical contents,
          # but with the Nix closure relocated out of /nix so it survives on a
          # host that bind-mounts its own /nix over the container's -- which the
          # pwn.college dojo platform does unconditionally. See the "Portable
          # variant" comment in nix/mk-image.nix for the mechanism and the
          # trade-off (one large layer instead of 115).
          portableImage = mkImage {
            inherit pythonEnv;
            portable = true;
            tag = "portable";
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
          inherit pythonEnv testPythonEnv penguinQemu iglooStatic muslHeaders nativeHelpersTree penguin pengutils vhostDeviceVsock dockerImage dockerImageStream dockerImageStreamHashed docsImage portableImage;
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
      # `nix flake check` -> run the host-side test suite reproducibly, in the
      # sandbox, on the same interpreter the image ships (3.13).
      #
      # The enum-boundary tests need a real igloo.ko ISF. It comes from the
      # igloo-driver *flake input* -- the exact release the image stages -- so
      # the suite neither downloads it at test time nor searches the store for
      # it. That is what lets this run as a pure derivation at all.
      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          inherit (self.packages.${system}) testPythonEnv;
          # Layout inside the extracted igloo_driver.tar.gz: <kver>/igloo.ko.<arch>.json.xz
          # (the tarball's single top-level dir is stripped by the nix fetcher).
          # Keep the kver/arch in sync with _ISF_KVER/_ISF_ARCH in
          # src/penguin/testing/harness.py.
          iglooKoIsf = "${igloo-driver}/6.13/igloo.ko.armel.json.xz";
          # conftest.py puts the repo root on sys.path so tests can
          # `import pyplugins.<...>`; pyplugins/ is deliberately not packaged.
          testTree = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./tests/unit
              ./pengutils
              ./pyplugins
            ];
          };
        in
        {
          unit-tests = pkgs.runCommand "penguin-unit-tests"
            {
              nativeBuildInputs = [ testPythonEnv ];
              PENGUIN_TEST_IGLOO_KO_ISF = iglooKoIsf;
            }
            ''
              cp -r ${testTree}/. .
              chmod -R u+w .
              # Fail loudly rather than silently skipping the ISF-backed tests:
              # the whole point of wiring the flake input in is that they run.
              test -f "$PENGUIN_TEST_IGLOO_KO_ISF" \
                || { echo "ISF missing: $PENGUIN_TEST_IGLOO_KO_ISF" >&2; exit 1; }
              mkdir -p "$out"
              python3 -m pytest tests/unit pengutils -q \
                --junitxml="$out/unit-test-results.xml"
            '';
        }
      );

      # `nix run` -> build the penguin image and load it into the local
      # docker/podman daemon, tagged by the nix build (see
      # dockerImageStreamHashed). Streams the image straight into `<engine>
      # load` -- no `:latest` collision and no multi-GB tarball realised in the
      # store. `nix run .#load` is explicit; a bare `nix run` is the same (this
      # is apps.default, distinct from packages.default = the dev pythonEnv, so
      # `nix build` is unaffected).
      apps = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          streamHashed = self.packages.${system}.dockerImageStreamHashed;
          loadScript = pkgs.writeShellScript "penguin-nix-load" ''
            set -eu
            engine=docker
            if ! command -v docker >/dev/null 2>&1; then
              if command -v podman >/dev/null 2>&1; then
                engine=podman
              else
                echo "error: --load needs docker or podman on PATH; found neither" >&2
                exit 1
              fi
            fi
            echo "Streaming penguin image into $engine (tagged by nix build hash)..." >&2
            # `<engine> load` prints "Loaded image: <name>:<tag>" on stdout; the
            # streamer's layer progress goes to stderr. Capture the ref so we can
            # echo a copy-pasteable run line with the resolved hash tag.
            ref="$(${streamHashed} | "$engine" load | sed -n 's/^Loaded image: //p' | head -n1)"
            echo "" >&2
            if [ -n "$ref" ]; then
              echo "Loaded $ref" >&2
              echo "Run it with, e.g.:  ./penguin --image $ref run <project>" >&2
            else
              echo "Image loaded (see $engine output above for the tag)." >&2
            fi
          '';
          loadApp = {
            type = "app";
            program = "${loadScript}";
          };
        in
        {
          load = loadApp;
          default = loadApp;
        }
      );

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
