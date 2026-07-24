"""
Regression tests for patch_config (penguin.common) discriminated-union merges.

A patch that switches a pseudofile's read/write *model* (a discriminated-union
variant) must override the base wholesale. The old field-by-field merge rebuilt
the base variant class with the patch's discriminator value -- e.g. constructing
the 'zero' Read variant with model='stateful' -- which failed schema validation.
This bit any SDK-profile boot tier that upgraded a PseudofileFinder-auto-detected
node (read:zero / write:discard) to read-after-write.
"""

import logging
import unittest

from penguin.common import patch_config
from penguin.penguin_config import structure

log = logging.getLogger("test_config_merge")


def _merge(base_pf, patch_pf):
    base = structure.Patch(**{"pseudofiles": {"/dev/x": base_pf}})
    patch = structure.Patch(**{"pseudofiles": {"/dev/x": patch_pf}})
    merged = patch_config(log, base, patch, "profile.boot")
    return merged.pseudofiles.root["/dev/x"]


class TestPseudofileVariantOverride(unittest.TestCase):
    def test_read_model_switch_zero_to_stateful(self):
        # Auto-detected read:zero (with provenance) -> profile read:stateful.
        pf = _merge(
            {"read": {"model": "zero", "provenance": "default"}},
            {"read": {"model": "stateful"}},
        )
        self.assertEqual(pf.read.root.model, "stateful")

    def test_write_model_switch_discard_to_return_const(self):
        pf = _merge(
            {"write": {"model": "discard", "provenance": "default"}},
            {"write": {"model": "return_const", "const": 0}},
        )
        self.assertEqual(pf.write.root.model, "return_const")
        self.assertEqual(pf.write.root.const, 0)

    def test_same_variant_still_field_merges(self):
        # Same variant (const_buf) on both sides must still merge fields, not
        # wholesale-replace: the base's untouched fields survive.
        pf = _merge(
            {"read": {"model": "const_buf", "val": "old"}},
            {"read": {"model": "const_buf", "val": "new"}},
        )
        self.assertEqual(pf.read.root.model, "const_buf")
        self.assertEqual(pf.read.root.val, "new")


if __name__ == "__main__":
    unittest.main()
