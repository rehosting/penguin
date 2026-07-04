import os
import sys

# `penguin` and `pengutils` are expected to be importable as installed
# (editable) packages: `pip install -e src -e pengutils`. See the pytest CI
# job and tests/unit/README.
#
# `pyplugins/` is deliberately *not* packaged (plugins are loaded by path at
# runtime), so the repo root still has to be on sys.path for the tests that
# `import pyplugins.<...>` directly.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
