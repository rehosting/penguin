"""Regression coverage for the dual-ABI lib_inject preload wiring.

Both writers of ``/etc/ld.so.preload`` (``penguin.penguin_prep`` and the
``interventions.nvram2`` intervention) must write the **bare soname**
``lib_inject.so`` rather than the absolute ``/igloo/dylibs/lib_inject.so``
path.  The absolute path is symlinked to the *default* ABI, so on a mixed
32/64-bit target (e.g. an aarch64 platform that also runs 32-bit ARM daemons)
it pins the 64-bit class -- 32-bit processes then hit ``wrong ELF class
ELFCLASS64: ignored`` and get no interception.  A slashless entry is
class-filtered by the loader and resolves per-ABI via the ``lib_inject.so``
symlinks placed next to each ``libc.so``, matching the env
``LD_PRELOAD=lib_inject.so`` mechanism.

``add_lib_inject_all_abis`` normally shells out to clang to build a ``.so``
per ABI (impossible host-side without the toolchain image), so we stub the
per-ABI builder and exercise only the static-file wiring.
"""
import importlib
from pathlib import Path

import pytest

from penguin.testing import load_module

REPO_ROOT = Path(__file__).resolve().parents[2]
NVRAM2 = REPO_ROOT / "pyplugins" / "interventions" / "nvram2.py"

# aarch64 is genuinely multi-ABI: default (64-bit) + soft_float/hard_float
# (32-bit ARM), which is exactly the mixed-ABI case this guards.
MULTI_ABI_ARCH = "aarch64"


def _base_conf():
    return {"core": {"arch": MULTI_ABI_ARCH}, "static_files": {}}


def _penguin_prep(monkeypatch):
    mod = importlib.import_module("penguin.penguin_prep")
    # Skip the clang build; we only care about the static-file wiring.
    monkeypatch.setattr(mod, "add_lib_inject_for_abi", lambda *a, **k: None)
    return mod, lambda conf: mod.add_lib_inject_all_abis(conf)


def _nvram2(monkeypatch):
    # nvram2's Plugin class body resolves `plugins.<name>` at import, so it
    # can't be plain-imported; load it through the pyplugin harness (null
    # plugins bound) and stub the per-ABI clang build.
    mod, _mgr = load_module(str(NVRAM2))
    monkeypatch.setattr(mod, "add_lib_inject_for_abi", lambda *a, **k: None)
    return mod, lambda conf: mod.add_lib_inject_all_abis(conf, cache_dir=None)


WRITERS = {"penguin_prep": _penguin_prep, "nvram2": _nvram2}


@pytest.mark.parametrize("writer", WRITERS.values(), ids=WRITERS.keys())
def test_ld_so_preload_is_bare_soname(monkeypatch, writer):
    _mod, call = writer(monkeypatch)

    conf = _base_conf()
    call(conf)

    preload = conf["static_files"]["/etc/ld.so.preload"]
    assert preload["contents"] == "lib_inject.so\n", (
        "ld.so.preload must be the bare soname so the loader resolves it "
        "per-ABI; an absolute path pins the default (64-bit) ABI and breaks "
        "32-bit daemons on a mixed 32/64-bit target"
    )
    # A slash-bearing entry would be pinned to one class rather than resolved
    # per-process, defeating dual-ABI injection.
    assert "/" not in preload["contents"].strip()

    # The /igloo/dylibs symlink itself is still needed by /igloo/utils binaries.
    symlink = conf["static_files"]["/igloo/dylibs/lib_inject.so"]
    assert symlink["type"] == "symlink"
    assert symlink["target"] == "/igloo/lib_inject_default.so"
