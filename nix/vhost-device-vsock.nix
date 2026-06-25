# Host-side vhost-user vsock device backend (rust-vmm/vhost-device), the single
# `vhost-device-vsock` binary penguin launches next to qemu. Mirrors the Docker
# rust_builder: build just that bin, statically linked.
{
  lib,
  rustPlatform,
  src,
}:

rustPlatform.buildRustPackage {
  pname = "vhost-device-vsock";
  version = "0.2.0";
  inherit src;

  cargoLock = {
    lockFile = "${src}/Cargo.lock";
  };

  # Workspace repo -- build only the vsock backend binary.
  buildAndTestSubdir = "vhost-device-vsock";

  # The Dockerfile builds this with crt-static for a portable binary on the
  # rust:1.86 (glibc) image, but fully-static glibc linking fails under nixpkgs
  # (collect2/ld). In the Nix image the binary's dynamic deps are in the closure,
  # so a normal dynamic build is correct here.

  # The workspace's other crates' tests need extra fixtures/privileges; we only
  # need the binary.
  doCheck = false;

  meta = {
    description = "vhost-user vsock device backend";
    homepage = "https://github.com/rust-vmm/vhost-device";
    license = lib.licenses.asl20;
    mainProgram = "vhost-device-vsock";
  };
}
