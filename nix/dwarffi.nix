{
  lib,
  stdenv,
  buildPythonPackage,
  fetchurl,
  autoPatchelfHook,
  msgspec,
}:

# dwarffi is a Rust/abi3 extension published by rehosting. Building from sdist
# would require maturin + a vendored cargo fetch; instead consume the upstream
# manylinux2014 abi3 wheel and patchelf it onto the nix runtime (standard nix
# binary-wheel pattern). abi3 means the cp310 wheel works on any >=3.10 python.
let
  version = "0.0.38";
  wheels = {
    "x86_64-linux" = {
      file = "dwarffi-${version}-cp310-abi3-manylinux2014_x86_64.whl";
      url = "https://files.pythonhosted.org/packages/b0/85/471f8a8c4afda41f97ec78a7c8e77796d2ad85b9cde88896100202fd1bc1/dwarffi-0.0.38-cp310-abi3-manylinux2014_x86_64.whl";
      hash = "sha256-WI5EmoAiBCb9ofTlQvtF2XJrO7nSjpZOZssaUrSNTUQ=";
    };
    "aarch64-linux" = {
      file = "dwarffi-${version}-cp310-abi3-manylinux2014_aarch64.whl";
      url = "https://files.pythonhosted.org/packages/ed/df/3005dd1fc4db91f2d8be55dba716e4c8082cf4d7b1d6745ac4143065553c/dwarffi-0.0.38-cp310-abi3-manylinux2014_aarch64.whl";
      hash = "sha256-Ev/rPhG5zf1Cc6G3iBTdiUdOk6dXDnjQXteQ5yMW8TM=";
    };
  };
  wheel = wheels.${stdenv.hostPlatform.system} or (throw "dwarffi: unsupported system ${stdenv.hostPlatform.system}");
in
buildPythonPackage {
  pname = "dwarffi";
  inherit version;
  format = "wheel";

  src = fetchurl {
    inherit (wheel) url hash;
  };

  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib ];
  dependencies = [ msgspec ];

  pythonImportsCheck = [ "dwarffi" ];

  meta = {
    description = "Parse ISF files and access kernel symbols and types";
    homepage = "https://github.com/rehosting/dwarffi";
    license = lib.licenses.mit;
  };
}
