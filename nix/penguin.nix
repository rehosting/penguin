# The penguin package (Dockerfile: pip install -e /pkg). setup.cfg declares only
# pyyaml/jsonschema/jinja2, but penguin's CLI shells out to its other console
# scripts (gen_config, gen_image, ...) as separate processes, and a console
# script's Nix wrapper only sees the package's *declared* dependencies -- not
# the surrounding pythonEnv. So `dependencies` must carry penguin's full runtime
# import set (incl. pengutils); the flake passes it in, shared with pythonEnv as
# the single source of truth.
#
# version.txt was produced by setuptools_scm at image build under the Dockerfile.
# Here `version` is threaded in from the flake (flake.nix penguinVersion): the
# release semver via PENGUIN_OVERRIDE_VERSION, else a git-derived version from
# the flake's `self`. We write it into version.txt in preBuild (for setup.py) and
# postInstall (for the runtime open(version.txt) in penguin/__init__.py).
{
  lib,
  buildPythonPackage,
  python,
  setuptools,
  src,
  version ? "0.0.0+unknown",
  # Full runtime dependency set (passed explicitly from the flake).
  dependencies ? [ ],
}:

buildPythonPackage {
  pname = "penguin";
  inherit version src;
  pyproject = true;

  build-system = [ setuptools ];
  inherit dependencies;

  # setup.py reads penguin/version.txt at build; penguin also reads it at runtime
  # (open'd relative to __file__). package_data doesn't ship it, so write it both
  # into the source (for setup.py) and into the installed package (for runtime).
  preBuild = ''
    echo "${version}" > penguin/version.txt
  '';
  postInstall = ''
    echo "${version}" > "$out"/${python.sitePackages}/penguin/version.txt
    # penguin resolves dirname(dirname(__file__))/resources/... (defaults.py,
    # config_patchers.py), i.e. a `resources/` sibling of the package. In the
    # Docker editable install that's /pkg/resources; replicate it here.
    cp -r resources "$out"/${python.sitePackages}/resources
  '';

  pythonImportsCheck = [ ];
  doCheck = false;

  meta = {
    description = "Automated IGLOO firmware rehosting";
    homepage = "https://github.com/rehosting/penguin";
    license = lib.licenses.mit;
    mainProgram = "penguin";
  };
}
