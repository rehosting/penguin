"""
Tests for the shared_dir / core_dumps config split:

- schema normalization of core.shared_dir and core.core_dumps
  (bool | str | dict shorthands -> canonical dicts), and
- the env mapping in pyplugins/core/core.py that turns those into the guest
  env vars consumed by source.d/40_mount_shared_dir.sh, including the legacy
  "shared_dir implies core dumps" fallback.
"""

import importlib.util
import os

import pytest

from penguin.penguin_config import structure

CORE_PY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../pyplugins/core/core.py")
)


def _load_core_module():
    spec = importlib.util.spec_from_file_location("core_plugin", CORE_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core_mod = _load_core_module()
env_for = core_mod.shared_dir_and_core_dump_env


def _core(**kw):
    kw.setdefault("version", 2)
    return structure.Core(**kw).model_dump(exclude_none=True)


# --- schema normalization -------------------------------------------------

def test_shared_dir_bool_true_defaults():
    assert _core(shared_dir=True)["shared_dir"] == {"path": "shared"}


def test_shared_dir_false_disables():
    assert "shared_dir" not in _core(shared_dir=False)


def test_shared_dir_string_is_path_shorthand():
    assert _core(shared_dir="mydir")["shared_dir"] == {"path": "mydir"}


def test_shared_dir_dict_passthrough():
    sd = _core(shared_dir={"path": "x", "host_path": "/data", "msize": 131072})
    assert sd["shared_dir"] == {"path": "x", "host_path": "/data", "msize": 131072}


def test_shared_dir_rejects_unknown_key():
    with pytest.raises(Exception):
        _core(shared_dir={"bogus": 1})


def test_core_dumps_bool_true_defaults():
    assert _core(core_dumps=True)["core_dumps"] == {"lock": True}


def test_core_dumps_string_is_pattern_shorthand():
    cd = _core(core_dumps="/p/core.%p")["core_dumps"]
    assert cd == {"lock": True, "pattern": "/p/core.%p"}


def test_core_dumps_dict_lock_off():
    assert _core(core_dumps={"lock": False})["core_dumps"] == {"lock": False}


def test_core_dumps_false_disables():
    assert "core_dumps" not in _core(core_dumps=False)


# --- env mapping ----------------------------------------------------------

def test_env_both_unset():
    env, deprecated = env_for(None, None)
    assert env == {}
    assert deprecated is False


def test_env_shared_dir_only_is_legacy_core_dumps():
    # shared_dir set, core_dumps unset -> mount + implicit (deprecated) dumps
    env, deprecated = env_for({"path": "shared"}, None)
    assert env == {"SHARED_DIR": "1", "CORE_DUMPS": "1", "CORE_DUMPS_LOCK": "1"}
    assert deprecated is True


def test_env_core_dumps_only_no_shared_dir():
    # core dumps without a shared_dir: mount still comes up, not deprecated
    env, deprecated = env_for(None, {"lock": True})
    assert env == {"SHARED_DIR": "1", "CORE_DUMPS": "1", "CORE_DUMPS_LOCK": "1"}
    assert deprecated is False


def test_env_explicit_core_dumps_false_wins_over_shared_dir():
    # explicit disable beats the legacy implicit-enable
    env, deprecated = env_for({"path": "shared"}, None)
    assert deprecated is True  # sanity: implicit path
    env2, deprecated2 = env_for({"path": "shared"}, False)
    assert env2 == {"SHARED_DIR": "1"}
    assert "CORE_DUMPS" not in env2
    assert deprecated2 is False


def test_env_lock_off_omits_lock():
    env, _ = env_for(None, {"lock": False})
    assert env["CORE_DUMPS"] == "1"
    assert "CORE_DUMPS_LOCK" not in env


def test_env_pattern_passed_through():
    env, _ = env_for(None, {"lock": True, "pattern": "/c/core.%p.%t"})
    assert env["CORE_DUMP_PATTERN"] == "/c/core.%p.%t"


def test_env_msize_passed_through():
    env, _ = env_for({"path": "shared", "msize": 131072}, True)
    assert env["SHARED_MSIZE"] == "131072"
