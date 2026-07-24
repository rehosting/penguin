"""
Tests for init plugin discovery: built-ins under pyplugins/init, project-local
plugins.d extension/shadowing, CLI disable filtering, and the basename
uniqueness constraint of the recursive plugin-path glob.
"""

import tempfile
import textwrap
import unittest
from collections import Counter
from pathlib import Path

from penguin.init_runner import discover_init_plugins

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_DIR = REPO_ROOT / "pyplugins" / "init"

# Every built-in init plugin expected to be discoverable. Keep in sync with
# pyplugins/init/ — this also guards against a move/rename silently dropping
# a plugin from discovery.
EXPECTED_BUILTINS = {
    # analyses
    "ArchId", "InitFinder", "EnvFinder", "PseudofileFinder", "InterfaceFinder",
    "ClusterCollector", "LibrarySymbols", "KernelVersionFinder",
    # patchers
    "BasePatch", "RootShell", "DynamicExploration", "SingleShotFICD",
    "SingleShot", "ManualInteract", "NetdevsDefault", "NetdevsTailored",
    "PseudofilesExpert", "PseudofilesTailored", "LinksysHack",
    "LibInjectSymlinks", "LibInjectStringIntrospection",
    "LibInjectTailoredAliases", "LibInjectFixedAliases",
    "SdkAtherosBroadcomAliases",
    "SdkZyxelOrEdimaxAliases", "SdkRalinkAliases",
    "SdkFinder", "BroadcomHndProfile", "BroadcomHndMtdProfile",
    "BroadcomHndBootProfile", "AsuswrtBootProfile", "AsuswrtWanProfile",
    "QualcommQsdkProfile", "QualcommQsdkBootProfile",
    "MediatekRalinkBootProfile", "RealtekRtl819xProfile",
    "RealtekRtl819xBootProfile", "AvmFritzosProfile", "AvmFritzosBootProfile",
    "NetgearAcosProfile", "ForceWWW",
    "GenerateMissingDirs", "GenerateReferencedDirs", "GenerateShellMounts",
    "GenerateMissingFiles", "DeleteFiles", "KernelModules",
    "ShimStopBins", "ShimNoModules", "ShimBusybox", "ShimCrypto",
    "NvramLibraryRecovery", "NvramConfigRecovery", "NvramConfigRecoveryWild",
    "NvramDefaults", "NvramFirmAEFileSpecific",
}


class TestDiscovery(unittest.TestCase):
    def test_builtins_discovered(self):
        classes = discover_init_plugins([BUILTIN_DIR])
        names = {c.__name__ for c in classes}
        self.assertEqual(names, EXPECTED_BUILTINS)

    def test_base_classes_not_discovered(self):
        names = {c.__name__ for c in discover_init_plugins([BUILTIN_DIR])}
        self.assertNotIn("InitPlugin", names)
        self.assertNotIn("Plugin", names)

    def test_disable_filters_plugins(self):
        classes = discover_init_plugins([BUILTIN_DIR], disable=["arch_id", "RootShell"])
        names = {c.__name__ for c in classes}
        self.assertNotIn("ArchId", names)
        self.assertNotIn("RootShell", names)
        self.assertIn("InitFinder", names)

    def test_project_local_plugin_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugins_d = Path(tmp, "plugins.d")
            plugins_d.mkdir()
            Path(plugins_d, "my_vendor.py").write_text(textwrap.dedent("""
                from penguin.init_plugin import InitContext, InitPlugin

                class MyVendorPatch(InitPlugin):
                    patch_name = "vendor.custom"

                    def patch(self, ctx: InitContext) -> dict:
                        return {"nvram": {"vendor_key": "1"}}
            """))
            classes = discover_init_plugins([BUILTIN_DIR, plugins_d])
        names = {c.__name__ for c in classes}
        self.assertIn("MyVendorPatch", names)
        self.assertTrue(EXPECTED_BUILTINS <= names)

    def test_project_local_plugin_shadows_builtin(self):
        builtin = {c.__name__: c for c in discover_init_plugins([BUILTIN_DIR])}
        with tempfile.TemporaryDirectory() as tmp:
            plugins_d = Path(tmp, "plugins.d")
            plugins_d.mkdir()
            Path(plugins_d, "custom_netdevs.py").write_text(textwrap.dedent("""
                from penguin.init_plugin import InitContext, InitPlugin

                class NetdevsDefault(InitPlugin):
                    patch_name = "netdevs.default"
                    order = 60

                    def patch(self, ctx: InitContext) -> dict:
                        return {"netdevs": ["myeth0"]}
            """))
            classes = discover_init_plugins([BUILTIN_DIR, plugins_d])
        winners = [c for c in classes if c.__name__ == "NetdevsDefault"]
        self.assertEqual(len(winners), 1)
        # The project-local class wins over the built-in one
        self.assertIsNot(winners[0], builtin["NetdevsDefault"])

    def test_broken_plugin_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugins_d = Path(tmp, "plugins.d")
            plugins_d.mkdir()
            Path(plugins_d, "broken.py").write_text("this is not python !!!")
            classes = discover_init_plugins([BUILTIN_DIR, plugins_d])
        self.assertTrue(EXPECTED_BUILTINS <= {c.__name__ for c in classes})


class TestPluginPathConstraints(unittest.TestCase):
    def test_pyplugins_basenames_unique(self):
        """The plugin manager's recursive plugin_path glob raises when a name
        resolves to multiple files, so basenames must stay unique across all
        of pyplugins/ (except __init__.py)."""
        counts = Counter(
            p.name
            for p in (REPO_ROOT / "pyplugins").rglob("*.py")
            if p.name != "__init__.py" and "__pycache__" not in p.parts
        )
        dupes = {name: n for name, n in counts.items() if n > 1}
        self.assertEqual(dupes, {}, f"duplicate plugin basenames: {dupes}")


if __name__ == "__main__":
    unittest.main()
