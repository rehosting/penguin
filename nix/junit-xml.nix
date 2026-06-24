{
  lib,
  buildPythonPackage,
  fetchPypi,
  setuptools,
  six,
}:

buildPythonPackage rec {
  pname = "junit-xml";
  version = "1.9";
  pyproject = true;

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-3hagUZkNTiWjmCst2eidZxBnVIcYhmQW+uwU2d5W258=";
  };

  build-system = [ setuptools ];
  dependencies = [ six ];

  # No upstream test suite shipped in the sdist.
  doCheck = false;

  pythonImportsCheck = [ "junit_xml" ];

  meta = {
    description = "Creates JUnit XML test result documents";
    homepage = "https://github.com/kyrus/python-junit-xml";
    license = lib.licenses.mit;
  };
}
