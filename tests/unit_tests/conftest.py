import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# `penguin/__init__.py` reads version.txt at import time. It is generated during
# the container build; when running these unit tests from a source checkout it
# may be absent. Create a dev placeholder so `import penguin` works either way.
_version_file = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../src/penguin/version.txt")
)
if not os.path.exists(_version_file):
    try:
        with open(_version_file, "w") as _f:
            _f.write("0.0.0+dev\n")
    except OSError:
        pass
