"""
Unit tests for the pyplugin side of the pseudofile model expansion.

These cover behavior that the schema tests (test_config.py) can't reach:

  * the @register_model registry — the low-friction "expand models in Python"
    path that backs `model: custom` in YAML;
  * the init-time provenance tagging in PseudofilesTailored, which marks every
    synthesized stub `provenance: default` so it self-reports at runtime.

Both run on the host: registry.py is dependency-free, and pseudofile_patches.py
imports only `penguin.*` (resolved via the conftest version.txt shim). The
*runtime* halves — custom models served in a live guest, and default hits
landing in pseudofiles_failures.yaml — are emulator-only and live in the
test_target fixture, not here.
"""

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
PYPLUGINS = os.path.join(REPO_ROOT, "pyplugins")
if PYPLUGINS not in sys.path:
    sys.path.insert(0, PYPLUGINS)


def _load(mod_name, rel_path):
    spec = importlib.util.spec_from_file_location(
        mod_name, os.path.join(REPO_ROOT, rel_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# @register_model registry (Workstream 3: easy Python extension)
# --------------------------------------------------------------------------- #
@pytest.fixture
def registry():
    # Fresh module per test so registrations don't leak between cases.
    sys.modules.pop("hyperfile.models.registry", None)
    return _load("hyperfile.models.registry", "pyplugins/hyperfile/models/registry.py")


def test_register_and_get_model_roundtrip(registry):
    @registry.register_model("read", "my_sensor")
    class MySensorRead:
        pass

    assert registry.get_model("read", "my_sensor") is MySensorRead


def test_register_model_decorator_returns_class_unchanged(registry):
    # must behave as a transparent decorator (class still usable directly)
    class Base:
        pass

    decorated = registry.register_model("write", "w1")(Base)
    assert decorated is Base


def test_get_model_unknown_name_returns_none(registry):
    assert registry.get_model("read", "does_not_exist") is None


def test_get_model_unknown_domain_returns_none(registry):
    # lookups on an unknown domain are a quiet None, not a raise
    assert registry.get_model("nope", "x") is None


def test_register_model_unknown_domain_raises(registry):
    with pytest.raises(ValueError):
        registry.register_model("bogus_domain", "x")


def test_registry_covers_all_mixin_domains(registry):
    # every domain the docs promise must accept a registration
    for domain in ("read", "write", "poll", "lseek", "mmap", "open", "release", "ioctl"):
        @registry.register_model(domain, f"probe_{domain}")
        class _Probe:
            pass

        assert registry.get_model(domain, f"probe_{domain}") is _Probe


# --------------------------------------------------------------------------- #
# Provenance tagging at init (Workstream 5: observability)
# --------------------------------------------------------------------------- #
class _FakeFinder:
    def __init__(self, pseudofiles):
        self.pseudofiles = pseudofiles


class _FakePlugins:
    def __init__(self, pseudofiles):
        self.PseudofileFinder = _FakeFinder(pseudofiles)


def _run_tailored_patch(pseudofiles):
    pfp = _load("init.pseudofile_patches", "pyplugins/init/pseudofile_patches.py")
    inst = pfp.PseudofilesTailored.__new__(pfp.PseudofilesTailored)
    inst.plugins = _FakePlugins(pseudofiles)
    return inst.patch(None)  # ctx is unused by patch()


def test_tailored_patch_tags_dev_node_default_on_all_domains():
    out = _run_tailored_patch({"dev": ["/dev/discovered"]})
    node = out["pseudofiles"]["/dev/discovered"]
    assert node["read"] == {"model": "zero", "provenance": "default"}
    assert node["write"] == {"model": "discard", "provenance": "default"}
    # /dev nodes also get a default ioctl, tagged on the wildcard handler
    assert node["ioctl"]["*"]["provenance"] == "default"
    assert node["ioctl"]["*"]["model"] == "return_const"


def test_tailored_patch_proc_node_has_no_ioctl():
    out = _run_tailored_patch({"proc": ["/proc/discovered"]})
    node = out["pseudofiles"]["/proc/discovered"]
    assert node["read"]["provenance"] == "default"
    assert node["write"]["provenance"] == "default"
    assert "ioctl" not in node  # ioctl default is /dev-only


def test_tailored_patch_skips_critical_dev_nodes():
    pfp = _load("init.pseudofile_patches", "pyplugins/init/pseudofile_patches.py")
    critical = pfp.CRITICAL_DEV_NODES[0]
    out = _run_tailored_patch({"dev": [critical, "/dev/ok"]})
    pf = out["pseudofiles"]
    assert critical not in pf          # refused
    assert "/dev/ok" in pf             # normal node still modeled


def test_tailored_patch_empty_returns_none():
    # nothing discovered -> no patch emitted (don't write an empty section)
    assert _run_tailored_patch({}) is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
