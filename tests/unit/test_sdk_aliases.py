"""
Unit tests for SDK-aware lib_inject alias patches.

The SDK-keyed alias groups in ``penguin.defaults`` (atheros_broadcom, realtek,
netgear_acos, zyxel_or_edimax, ralink) are emitted as one *named, disabled*
patch per group (``sdk.<group>``) rather than flattened into the always-on
tailored-alias patch. A disabled patch is a candidate in the config search, not
a fact baked into the initial config. These tests assert exactly that split:

- each ``sdk.<group>`` patch is emitted disabled and carries only the group's
  aliases that the target actually exports;
- a group whose symbols the target does not export emits no patch at all;
- the always-on ``lib_inject.dynamic_models`` patch carries the generic aliases
  and *none* of the SDK-group symbols (the behavior change we intend).
"""

import tempfile
import unittest
from pathlib import Path

from penguin.defaults import (
    atheros_broadcom,
    generic_lib_aliases,
    ralink,
    realtek,
    sdk_lib_aliases,
)
from penguin.init_plugin import InitPlugin, cached_analysis
from penguin.init_runner import discover_init_plugins

from test_init_runner import run_plugins  # shared InitPluginRunner harness

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_DIR = REPO_ROOT / "pyplugins" / "init"

# A symbol export set spanning three SDK groups, the generic set, and one
# genuinely-unmodeled nvram symbol. netgear_acos and zyxel_or_edimax are
# deliberately absent so their patches should not materialize.
EXPORTED = {
    # realtek
    "apmib_get", "apmib_set",
    # ralink
    "nvram_bufget", "nvram_bufset",
    # atheros_broadcom
    "nvram_nget", "nvram_nset",
    # generic (base_names / base_aliases)
    "nvram_get", "nvram_set", "nvram_load",
    # not modeled anywhere
    "nvram_frobnicate",
}


class LibrarySymbols(InitPlugin):
    """Stand-in for the real LibrarySymbols analysis: hands the lib_inject
    patches a fixed exported-symbol set instead of scanning a rootfs. Must be
    named ``LibrarySymbols`` so sibling access (``self.plugins.LibrarySymbols``)
    resolves to it rather than auto-loading the real analysis."""

    @cached_analysis
    def library_info(self) -> dict:
        return {"symbols": {"/lib/libc.so.0": {s: 0 for s in EXPORTED}}}


def _builtin(name):
    classes = {c.__name__: c for c in discover_init_plugins([BUILTIN_DIR])}
    return classes[name]


def _run():
    lib_inject_classes = [
        _builtin(n)
        for n in (
            "LibInjectTailoredAliases",
            "SdkAtherosBroadcomAliases",
            "SdkRealtekAliases",
            "SdkNetgearAcosAliases",
            "SdkZyxelOrEdimaxAliases",
            "SdkRalinkAliases",
        )
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _, patches, _ = run_plugins([LibrarySymbols, *lib_inject_classes], tmp)
    return patches


class TestSdkAliasPatches(unittest.TestCase):
    def setUp(self):
        self.patches = _run()

    def _expected(self, table):
        return {s: table[s] for s in table if s in EXPORTED}

    def test_matched_sdk_patches_named_disabled_and_scoped(self):
        cases = {
            "sdk.realtek": realtek,
            "sdk.ralink": ralink,
            "sdk.atheros_broadcom": atheros_broadcom,
        }
        for name, table in cases.items():
            self.assertIn(name, self.patches, f"{name} should be emitted")
            data, enabled = self.patches[name]
            self.assertFalse(enabled, f"{name} must be disabled by default")
            self.assertEqual(data, {"lib_inject": {"aliases": self._expected(table)}})

    def test_unmatched_sdk_groups_emit_no_patch(self):
        # No netgear_acos / zyxel_or_edimax symbols were exported.
        self.assertNotIn("sdk.netgear_acos", self.patches)
        self.assertNotIn("sdk.zyxel_or_edimax", self.patches)

    def test_every_sdk_group_has_a_discoverable_patch_class(self):
        # Guards the defaults.py grouping against a group gaining no patch class:
        # every SDK group must have a discoverable init plugin emitting
        # sdk.<group>, disabled by default.
        patch_names = {
            c.patch_name: c
            for c in discover_init_plugins([BUILTIN_DIR])
            if (c.patch_name or "").startswith("sdk.")
        }
        for group in sdk_lib_aliases:
            name = f"sdk.{group}"
            self.assertIn(name, patch_names, f"no patch class emits {name}")
            self.assertFalse(
                patch_names[name].enabled, f"{name} must be disabled by default"
            )

    def test_tailored_patch_is_generic_only_and_enabled(self):
        data, enabled = self.patches["lib_inject.dynamic_models"]
        self.assertTrue(enabled, "the generic tailored-alias patch stays enabled")
        aliases = data["lib_inject"]["aliases"]

        # Generic symbols land here.
        self.assertEqual(aliases["nvram_get"], generic_lib_aliases["nvram_get"])
        self.assertEqual(aliases["nvram_set"], generic_lib_aliases["nvram_set"])
        self.assertEqual(aliases["nvram_load"], generic_lib_aliases["nvram_load"])

        # No SDK-group symbol leaks into the always-on patch.
        sdk_symbols = set().union(*(t.keys() for t in sdk_lib_aliases.values()))
        self.assertEqual(sdk_symbols & set(aliases), set())

        # A truly-unmodeled symbol is aliased nowhere.
        self.assertNotIn("nvram_frobnicate", aliases)


if __name__ == "__main__":
    unittest.main()
