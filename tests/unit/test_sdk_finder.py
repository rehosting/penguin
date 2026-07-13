"""
Unit tests for SDK-profile detection (SdkFinder) and the confidence-gated
profile patch (BroadcomHndProfile).

SdkFinder scores each catalog profile's fingerprint against static analyses that
already run (InterfaceFinder, ClusterCollector, LibrarySymbols). A profile patch
is emitted ENABLED (baked into the initial config) only when the fingerprint
corroborates at >= enable_if.min_signals; below that it is DISABLED (a search
candidate); with no signal at all it is not emitted.

These tests stub the three analyses and drive the real broadcom_hnd catalog
entry through the InitPluginRunner harness.
"""

import tempfile
import unittest
from pathlib import Path

from penguin.init_plugin import InitPlugin, cached_analysis
from penguin.init_runner import discover_init_plugins

from test_init_runner import run_plugins  # shared InitPluginRunner harness

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_DIR = REPO_ROOT / "pyplugins" / "init"


def _builtin(name):
    return {c.__name__: c for c in discover_init_plugins([BUILTIN_DIR])}[name]


def make_analysis_stubs(interfaces=(), executables=(), files=(), symbols=()):
    """Build stub InitPlugin classes named exactly like the real analyses, so
    sibling access (self.plugins.<Name>) resolves to these instead of loading
    the real (rootfs-scanning) analyses. `files` feeds ClusterCollector.files
    for `kind: file` fingerprints such as a kernel module."""
    ifaces, exes, fs, syms = list(interfaces), list(executables), list(files), list(symbols)

    class InterfaceFinder(InitPlugin):
        @cached_analysis
        def interfaces(self):
            return {"commands": ifaces} if ifaces else None

    class ClusterCollector(InitPlugin):
        @cached_analysis
        def clusters(self):
            return {"files": fs, "executables": exes, "executable_hashes": []}

    class LibrarySymbols(InitPlugin):
        @cached_analysis
        def library_info(self):
            return {"symbols": {"/lib/libc.so.0": {s: 0 for s in syms}}}

    return [InterfaceFinder, ClusterCollector, LibrarySymbols]


def run(interfaces=(), executables=(), files=(), symbols=(), profile_classes=("BroadcomHndProfile",)):
    classes = make_analysis_stubs(interfaces, executables, files, symbols) + [
        _builtin("SdkFinder"),
        *[_builtin(c) for c in profile_classes],
    ]
    with tempfile.TemporaryDirectory() as tmp:
        runner, patches, _ = run_plugins(classes, tmp)
    return runner, patches


class TestSdkFinder(unittest.TestCase):
    def _match(self, runner):
        finder = runner.manager.plugins["SdkFinder"]
        return finder.verdict("broadcom_hnd")

    def test_full_fingerprint_enables_profile(self):
        # vlan1+et (interface) + rtkswitch (executable) + nvram_get (symbol) = 3 signals.
        runner, patches = run(
            interfaces=["vlan1", "et", "br0"],
            executables=["rtkswitch", "httpd"],
            symbols=["nvram_get", "malloc"],
        )
        v = self._match(runner)
        self.assertIsNotNone(v)
        self.assertEqual(v["score"], 3)
        self.assertTrue(v["enabled"])

        data, enabled = patches["sdk.broadcom_hnd"]
        self.assertTrue(enabled, "3 signals >= min_signals -> baked into initial config")
        # The bundle is emitted intact.
        self.assertIn("vlan1", data["netdevs"])
        self.assertEqual(data["nvram"]["IpAddr_Lan"], "192.168.1.1")
        self.assertIn("/dev/rtkswitch", data["pseudofiles"])

    def test_single_signal_emits_disabled_candidate(self):
        # Only the interface signal fires -> score 1 < min_signals(2) -> disabled.
        runner, patches = run(interfaces=["vlan1"])
        v = self._match(runner)
        self.assertEqual(v["score"], 1)
        self.assertFalse(v["enabled"])

        data, enabled = patches["sdk.broadcom_hnd"]
        self.assertFalse(enabled, "1 signal -> disabled search candidate, not baseline")
        self.assertIn("vlan1", data["netdevs"])  # bundle still materialized on disk

    def test_two_signals_enable(self):
        # interface + symbol, no rtkswitch executable -> score 2 == threshold -> enabled.
        runner, patches = run(interfaces=["et"], symbols=["acosNvramConfig_get"])
        v = self._match(runner)
        self.assertEqual(v["score"], 2)
        self.assertTrue(v["enabled"])
        self.assertTrue(patches["sdk.broadcom_hnd"][1])

    def test_no_signal_emits_no_patch(self):
        # A non-Broadcom target: nothing in the fingerprint fires.
        runner, patches = run(
            interfaces=["eth0", "wlan0"],
            executables=["busybox"],
            symbols=["printf"],
        )
        self.assertIsNone(self._match(runner))
        self.assertNotIn("sdk.broadcom_hnd", patches)


class TestBroadcomNvramFold(unittest.TestCase):
    """SDK-specific nvram defaults are gated behind the profile fingerprint
    instead of being shipped to every target by the always-on nvram.04_defaults."""

    def test_broadcom_macs_not_in_generic_defaults(self):
        from penguin.config_patchers import NvramHelper

        defaults = NvramHelper._get_default_nvram_values()
        # Broadcom-specific keys moved into the broadcom_hnd profile.
        self.assertNotIn("et0macaddr", defaults)
        self.assertNotIn("0:macaddr", defaults)
        # Netgear ACOS keys moved into the netgear_acos profile.
        self.assertNotIn("sku_name", defaults)
        self.assertNotIn("time_zone_x", defaults)
        self.assertNotIn("usb_info_dev0", defaults)
        self.assertNotIn("wla_ap_isolate_1", defaults)
        # A genuinely generic key is still shipped to all targets.
        self.assertIn("lan_ipaddr", defaults)

    def test_broadcom_macs_in_profile_bundle(self):
        _, patches = run(interfaces=["vlan1", "et"], symbols=["nvram_get"])
        nvram = patches["sdk.broadcom_hnd"][0]["nvram"]
        self.assertEqual(nvram["et0macaddr"], "00:11:22:33:44:50")
        self.assertIn("0:macaddr", nvram)


class TestNetgearAcosProfile(unittest.TestCase):
    """The netgear_acos profile subsumes the retired sdk.netgear_acos alias
    group: fingerprint + ACOS nvram defaults + the WAN_ith_CONFIG_GET shim."""

    def _run(self, **kw):
        return run(profile_classes=("NetgearAcosProfile",), **kw)

    def _match(self, runner):
        return runner.manager.plugins["SdkFinder"].verdict("netgear_acos")

    def test_acos_symbol_plus_lib_enables(self):
        # acosNvramConfig_get (symbol) + libacos_shared.so (file) = 2 signals.
        runner, patches = self._run(
            symbols=["acosNvramConfig_get", "nvram_get"],
            files=["libacos_shared.so"],
        )
        v = self._match(runner)
        self.assertEqual(v["score"], 2)
        self.assertTrue(v["enabled"])

        data, enabled = patches["sdk.netgear_acos"]
        self.assertTrue(enabled)
        # The ACOS nvram cluster (formerly always-on) rides the profile bundle...
        self.assertEqual(data["nvram"]["time_zone_x"], "0")
        self.assertIn("usb_info_dev101", data["nvram"])
        # ...and the alias subsumed from the retired Slice-0 group.
        self.assertEqual(data["lib_inject"]["aliases"]["WAN_ith_CONFIG_GET"],
                         "libinject_WAN_ith_CONFIG_GET")

    def test_broadcom_target_does_not_fire_acos(self):
        runner, patches = self._run(interfaces=["vlan1", "et"], symbols=["nvram_get"])
        self.assertIsNone(self._match(runner))
        self.assertNotIn("sdk.netgear_acos", patches)


class TestFidelityTiers(unittest.TestCase):
    """The catalog exposes fidelity-tiered bundles (bundles.<tier>). Tier 0
    (libinject) ships; a tier with no bundle (e.g. the reserved `mtd`) emits no
    patch even when the fingerprint fires."""

    def test_libinject_tier_is_emitted(self):
        _, patches = run(interfaces=["vlan1", "et"], symbols=["nvram_get"])
        data, enabled = patches["sdk.broadcom_hnd"]
        self.assertTrue(enabled)
        self.assertIn("netdevs", data)  # sourced from bundles.libinject

    def test_unbuilt_tier_emits_no_patch(self):
        # Drive _profile_patch directly for the reserved mtd tier: the fingerprint
        # corroborates but broadcom_hnd defines no bundles.mtd -> no patch.
        profile_cls = _builtin("BroadcomHndProfile")
        _profile_patch = profile_cls.patch.__globals__["_profile_patch"]

        classes = make_analysis_stubs(interfaces=["vlan1", "et"], symbols=["nvram_get"]) + [
            _builtin("SdkFinder"),
            profile_cls,
        ]
        with tempfile.TemporaryDirectory() as tmp:
            runner, _, _ = run_plugins(classes, tmp)
        finder = runner.manager.plugins["SdkFinder"]
        profile = runner.manager.plugins["BroadcomHndProfile"]
        # Sanity: the profile did fire for Tier 0.
        self.assertIsNotNone(finder.verdict("broadcom_hnd"))
        self.assertIsNone(_profile_patch(profile, "broadcom_hnd", tier="mtd"))


class TestQualcommQsdkProfile(unittest.TestCase):
    def _run(self, **kw):
        return run(profile_classes=("QualcommQsdkProfile",), **kw)

    def _match(self, runner):
        return runner.manager.plugins["SdkFinder"].verdict("qualcomm_qsdk")

    def test_ssdk_module_plus_nvram_symbol_enables(self):
        # qca-ssdk.ko (file) + get_nvram_space (symbol) = 2 signals -> enabled.
        runner, patches = self._run(
            files=["qca-ssdk.ko", "libnvram.so"],
            symbols=["get_nvram_space", "nvram_xfr"],
        )
        v = self._match(runner)
        self.assertEqual(v["score"], 2)
        self.assertTrue(v["enabled"])

        data, enabled = patches["sdk.qualcomm_qsdk"]
        self.assertTrue(enabled)
        # The DT_NEEDED libnvram shim + uClibc-eager aliases are emitted;
        # device-specific model seeding is NOT in the SDK profile.
        self.assertEqual(data["static_files"]["/usr/lib/libnvram.so"]["type"], "shim")
        self.assertEqual(data["lib_inject"]["aliases"]["get_nvram_space"],
                         "libinject_nvram_get_nvramspace")
        self.assertNotIn("nvram", data)

    def test_ssdk_module_alone_is_disabled_candidate(self):
        # Only the qca-ssdk.ko file signal fires -> score 1 -> disabled candidate.
        runner, patches = self._run(files=["qca-ssdk.ko"])
        v = self._match(runner)
        self.assertEqual(v["score"], 1)
        self.assertFalse(v["enabled"])
        self.assertFalse(patches["sdk.qualcomm_qsdk"][1])

    def test_broadcom_target_does_not_fire_qualcomm(self):
        # et/rtkswitch/nvram_get (Broadcom) must not trip the Qualcomm profile.
        runner, patches = self._run(
            interfaces=["vlan1", "et"], executables=["rtkswitch"], symbols=["nvram_get"],
        )
        self.assertIsNone(self._match(runner))
        self.assertNotIn("sdk.qualcomm_qsdk", patches)


if __name__ == "__main__":
    unittest.main()
