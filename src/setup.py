from setuptools import setup
import os

# Package metadata lives in pyproject.toml; this shim only supplies the
# dynamic version. version.txt is generated during the container build, so
# fall back to a dev version when it is absent (source / editable installs).
version = "0.0.1"
_version_file = os.path.join(os.path.dirname(__file__), "penguin", "version.txt")
if os.path.exists(_version_file):
    with open(_version_file) as f:
        version = f.read().strip() or version

setup(version=version)
