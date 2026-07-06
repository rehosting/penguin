import os
import sys

import pytest

# `penguin` and `pengutils` are expected to be importable as installed
# (editable) packages: `pip install -e src -e pengutils`. See the pytest CI
# job and tests/unit/README.
#
# `pyplugins/` is deliberately *not* packaged (plugins are loaded by path at
# runtime), so the repo root still has to be on sys.path for the tests that
# `import pyplugins.<...>` directly.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


@pytest.fixture(scope="session")
def igloo_ko_isf():
    """Path to a real ``igloo.ko`` ISF for the Dockerfile-pinned driver release.

    Resolves (and, if needed, downloads once to a local cache) via
    :func:`penguin.testing.resolve_igloo_ko_isf`; skips the test when offline with
    nothing cached. Pass it to ``load_pyplugin(..., real_isf=<this>)`` so the real
    ``hyper.consts`` builds against real enum values through ``dwarffi``.
    """
    from penguin.testing import resolve_igloo_ko_isf
    path = resolve_igloo_ko_isf()
    if not path:
        pytest.skip("no igloo.ko ISF available (offline; set "
                    "PENGUIN_TEST_IGLOO_KO_ISF or PENGUIN_TEST_ISF_CACHE)")
    return path
