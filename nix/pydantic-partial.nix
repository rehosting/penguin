{
  lib,
  buildPythonPackage,
  fetchPypi,
  uv-build,
  pydantic,
}:

buildPythonPackage rec {
  pname = "pydantic-partial";
  version = "0.10.2";
  pyproject = true;

  src = fetchPypi {
    inherit version;
    pname = "pydantic_partial";
    hash = "sha256-jb/JhDyMqFTFbDaKJ24qYdn2W+79He7lxN2O19dENf0=";
  };

  build-system = [ uv-build ];
  dependencies = [ pydantic ];

  doCheck = false;

  pythonImportsCheck = [ "pydantic_partial" ];

  meta = {
    description = "Create partial models from pydantic models";
    homepage = "https://github.com/team23/pydantic-partial";
    license = lib.licenses.mit;
  };
}
