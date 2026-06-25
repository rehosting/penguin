# The penguin package (Dockerfile: pip install -e /pkg). setup.cfg declares only
# pyyaml/jsonschema/jinja2; penguin's broader runtime imports (pydantic, click,
# coloredlogs, ...) are satisfied by the shared pythonEnv it installs into.
#
# version.txt is normally produced by setuptools_scm at image build (Dockerfile
# version_generator stage). Here we write it in preBuild from `version` -- a
# follow-up can thread the real git-derived version through a flake arg.
{
  lib,
  buildPythonPackage,
  python,
  setuptools,
  pyyaml,
  jsonschema,
  jinja2,
  src,
  version ? "0.0.1+nix",
}:

buildPythonPackage {
  pname = "penguin";
  inherit version src;
  pyproject = true;

  build-system = [ setuptools ];
  dependencies = [ pyyaml jsonschema jinja2 ];

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
