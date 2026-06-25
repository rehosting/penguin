# The pengutils package (Dockerfile: pip install -e /pengutils). Declares only
# sqlalchemy + rich in setup.cfg; the rest of its runtime imports are satisfied
# by the shared pythonEnv it's installed into.
{
  lib,
  buildPythonPackage,
  setuptools,
  sqlalchemy,
  rich,
  src,
}:

buildPythonPackage {
  pname = "pengutils";
  version = "0.1";
  pyproject = true;
  inherit src;

  build-system = [ setuptools ];
  dependencies = [ sqlalchemy rich ];

  # The real import surface is validated in the assembled env, not here (would
  # otherwise need pengutils' full transitive set as build inputs).
  pythonImportsCheck = [ ];
  doCheck = false;

  meta = {
    description = "Pengutils plugins and utilities for IGLOO";
    homepage = "https://github.com/rehosting/penguin";
    license = lib.licenses.mit;
  };
}
