# Cross-compile the guest-utils/native/*.c helpers for one guest arch, mirroring
# guest-utils/native/Makefile. Output: $out/<binary> per source file.
#
# We drive the cross stdenv's $CC directly rather than the upstream Makefile,
# whose per-arch CC/CFLAGS are keyed off bespoke triple names that don't match
# nixpkgs' config strings (same rationale as penguin-tools/mk-guest-c-tool.nix).
#
# The Makefile is NOT uniformly static -- three helpers MUST be dynamic so the
# guest's runtime dynamic loader honors them:
#   * test_nvram, uprobes_test, proc_mtd_dynamic -> dynamic, with an explicit
#     `--dynamic-linker=/igloo/dylibs/ld-musl-<arch>.so.1` (proc_mtd_dynamic
#     also links -ldl). These rely on LD_PRELOAD / dlsym at runtime; a *static*
#     binary ignores LD_PRELOAD entirely, so e.g. lib_inject.so's constructor
#     never fires and dlsym("nvram_get") finds nothing. (This is exactly the
#     basic_target lib_inject.d regression: a static test_nvram silently drops
#     the LD_PRELOAD'd lib_inject.so.)
#   * test_executable -> static but NOT stripped (Makefile filters out -s).
#   * everything else -> `-s -static`.
# `archName` is the Makefile/penguin arch name (e.g. "armel") used to form the
# guest loader path; it must match what penguin stages under /igloo/dylibs.
{
  crossPkgs,
  src, # the guest-utils/native source tree
  archName,
  extraCFlags ? [ ],
}:

let
  lib = crossPkgs.lib;
  extra = lib.concatStringsSep " " extraCFlags;
  dynLinker = "-Wl,--dynamic-linker=/igloo/dylibs/ld-musl-${archName}.so.1";
in
crossPkgs.stdenv.mkDerivation {
  pname = "penguin-native-helpers";
  version = "0";
  inherit src;

  dontConfigure = true;

  # Match upstream's bare musl-gcc: no nixpkgs cc-wrapper hardening. In
  # particular -fstack-protector pulls __stack_chk_fail_local from
  # libssp_nonshared, which isn't resolvable for the dynamic powerpc build
  # ("undefined reference to __stack_chk_fail_local"); the forced -pie/-fPIE
  # also diverges from the Makefile. Disabling all hardening reproduces the
  # plain `<triple>-musl-gcc <flags>` invocation.
  hardeningDisable = [ "all" ];

  # Compile every .c in the tree (matches the Makefile's ALL_CS wildcard). The
  # sources #include the sibling headers (hypercall.h, portal_call.h), so build
  # from the unpacked source dir. Per-binary flags mirror the Makefile rules.
  buildPhase = ''
    runHook preBuild
    mkdir -p out
    for c in *.c; do
      name="$(basename "$c" .c)"
      bin="out/$name"
      case "$name" in
        test_nvram|uprobes_test)
          echo "CC (dynamic) $c -> $bin"
          $CC -O2 -s ${extra} ${dynLinker} "$c" -o "$bin"
          ;;
        proc_mtd_dynamic)
          echo "CC (dynamic, -ldl) $c -> $bin"
          $CC -O2 -s ${extra} ${dynLinker} "$c" -o "$bin" -ldl
          ;;
        test_executable)
          echo "CC (static, unstripped) $c -> $bin"
          $CC -O2 -static ${extra} "$c" -o "$bin"
          ;;
        *)
          echo "CC (static) $c -> $bin"
          $CC -O2 -s -static ${extra} "$c" -o "$bin"
          ;;
      esac
    done
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    cp out/* "$out/"
    runHook postInstall
  '';

  dontStrip = true;
  dontPatchELF = true;
}
