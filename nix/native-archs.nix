# Cross matrix for the guest-utils/native/*.c helpers (send_hypercall etc.),
# keyed by the OUTPUT directory name the Docker image uses (Makefile ARCHS) so
# the result drops into /igloo_static/<arch>/ directly.
#
# muslCrossSystem mirrors penguin-tools/src/archs.nix where the arch overlaps
# (those cross toolchains are already built + cached in rehosting-tools.cachix);
# extraCFlags carries the Makefile's per-arch -march flags.
#
# powerpc (32 BE), powerpcle (32 LE) and riscv32 are NOT in penguin-tools' set,
# so their cross toolchains are not pre-cached and build from source on first
# run. The riscv32-musl gcc build is memory-hungry and can be OOM-killed when
# many cross-gccs compile concurrently ("all-gcc Error 2"); it succeeds once the
# others are cached / built serially, and the artifacts cache afterward.
{
  x86_64 = {
    muslCrossSystem = { config = "x86_64-linux-musl"; };
  };
  armel = {
    muslCrossSystem = { config = "armv7l-linux-musleabi"; };
  };
  aarch64 = {
    muslCrossSystem = { config = "aarch64-linux-musl"; };
  };
  # -march comes from gcc.arch on the cross system (matching penguin-tools);
  # do NOT also pass -mips32r3/-mips64r2 in CFLAGS -- gcc rejects the conflict.
  mipseb = {
    muslCrossSystem = { config = "mips-linux-musl"; gcc.arch = "mips32r2"; };
  };
  mipsel = {
    muslCrossSystem = { config = "mipsel-linux-musl"; gcc.arch = "mips32r2"; };
  };
  mips64eb = {
    muslCrossSystem = { config = "mips64-linux-musl"; gcc.arch = "mips64r2"; gcc.abi = "64"; };
  };
  mips64el = {
    muslCrossSystem = { config = "mips64el-linux-musl"; gcc.arch = "mips64r2"; gcc.abi = "64"; };
  };
  powerpc = {
    muslCrossSystem = { config = "powerpc-linux-musl"; };
  };
  powerpcle = {
    muslCrossSystem = { config = "powerpcle-linux-musl"; };
  };
  powerpc64 = {
    muslCrossSystem = { config = "powerpc64-linux-musl"; gcc.abi = "elfv2"; };
  };
  powerpc64le = {
    muslCrossSystem = { config = "powerpc64le-linux-musl"; };
  };
  riscv32 = {
    muslCrossSystem = { config = "riscv32-linux-musl"; };
  };
  riscv64 = {
    muslCrossSystem = { config = "riscv64-linux-musl"; };
  };
  loongarch64 = {
    muslCrossSystem = { config = "loongarch64-linux-musl"; };
  };
}
