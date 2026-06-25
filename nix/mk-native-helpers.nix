# Cross-compile the guest-utils/native/*.c helpers as static binaries for one
# guest arch, mirroring guest-utils/native/Makefile (each .c -> one binary with
# `-s -static` + the arch -march flag). Output: $out/<binary> per source file.
#
# We drive the cross stdenv's $CC directly rather than the upstream Makefile,
# whose per-arch CC/CFLAGS are keyed off bespoke triple names that don't match
# nixpkgs' config strings (same rationale as penguin-tools/mk-guest-c-tool.nix).
{
  crossPkgs,
  src, # the guest-utils/native source tree
  extraCFlags ? [ ],
}:

let
  lib = crossPkgs.lib;
  cflags = lib.concatStringsSep " " ([ "-O2" "-s" "-static" ] ++ extraCFlags);
in
crossPkgs.stdenv.mkDerivation {
  pname = "penguin-native-helpers";
  version = "0";
  inherit src;

  dontConfigure = true;

  # Compile every .c in the tree (matches the Makefile's ALL_CS wildcard). The
  # sources #include the sibling headers (hypercall.h, portal_call.h), so build
  # from the unpacked source dir.
  buildPhase = ''
    runHook preBuild
    mkdir -p out
    for c in *.c; do
      bin="out/$(basename "$c" .c)"
      echo "CC $c -> $bin"
      $CC ${cflags} "$c" -o "$bin"
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
