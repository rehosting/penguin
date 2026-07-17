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
        # ethswctl (executable) + libbcmcrypto.so (file) + wl_probe (symbol) = 3
        # signals, all Broadcom-HND-exclusive after the fingerprint hardening.
        runner, patches = run(
            executables=["ethswctl", "httpd"],
            files=["libbcmcrypto.so"],
            symbols=["wl_probe", "malloc"],
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
        # Only the file signal fires -> score 1 < min_signals(2) -> disabled.
        runner, patches = run(files=["dhd.ko"])
        v = self._match(runner)
        self.assertEqual(v["score"], 1)
        self.assertFalse(v["enabled"])

        data, enabled = patches["sdk.broadcom_hnd"]
        self.assertFalse(enabled, "1 signal -> disabled search candidate, not baseline")
        self.assertIn("vlan1", data["netdevs"])  # bundle still materialized on disk

    def test_two_signals_enable(self):
        # executable + symbol, no file -> score 2 == threshold -> enabled.
        runner, patches = run(executables=["ethswctl"], symbols=["wl_probe"])
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
        _, patches = run(executables=["ethswctl"], symbols=["wl_probe"])
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
        _, patches = run(executables=["ethswctl"], symbols=["wl_probe"])
        data, enabled = patches["sdk.broadcom_hnd"]
        self.assertTrue(enabled)
        self.assertIn("netdevs", data)  # sourced from bundles.libinject

    def test_unbuilt_tier_emits_no_patch(self):
        # Drive _profile_patch directly for a tier the profile does not define:
        # the fingerprint corroborates but there is no bundles.<tier> -> no patch.
        profile_cls = _builtin("BroadcomHndProfile")
        _profile_patch = profile_cls.patch.__globals__["_profile_patch"]

        classes = make_analysis_stubs(executables=["ethswctl"], symbols=["wl_probe"]) + [
            _builtin("SdkFinder"),
            profile_cls,
        ]
        with tempfile.TemporaryDirectory() as tmp:
            runner, _, _ = run_plugins(classes, tmp)
        finder = runner.manager.plugins["SdkFinder"]
        profile = runner.manager.plugins["BroadcomHndProfile"]
        # Sanity: the profile did fire for Tier 0.
        self.assertIsNotNone(finder.verdict("broadcom_hnd"))
        self.assertIsNone(_profile_patch(profile, "broadcom_hnd", tier="nonexistent_tier"))


class TestBroadcomMtdTier(unittest.TestCase):
    """The Tier-1 `mtd` bundle: a data-faithful CFE-envram backing store for the
    vendor `envrams` daemon, emitted as the DISABLED `sdk.broadcom_hnd.mtd`
    candidate (additive to, not a replacement of, the libinject tier)."""

    def _run(self, **kw):
        return run(profile_classes=("BroadcomHndMtdProfile",), **kw)

    def test_mtd_candidate_disabled_even_on_full_fingerprint(self):
        # Full Broadcom fingerprint fires, but a non-default tier is always a
        # disabled candidate you promote -- never baked in automatically.
        _, patches = self._run(executables=["ethswctl"], symbols=["wl_probe"])
        data, enabled = patches["sdk.broadcom_hnd.mtd"]
        self.assertFalse(enabled, "mtd tier is opt-in: emitted disabled")

    def test_envram_packed_into_nvm_blob(self):
        _, patches = self._run(executables=["ethswctl"], symbols=["wl_probe"])
        data, _ = patches["sdk.broadcom_hnd.mtd"]
        # The `envram` key is consumed (packed), not left in the patch.
        self.assertNotIn("envram", data)
        blob = data["static_files"]["/rom/etc/nvram.nvm"]["contents"]
        self.assertIsInstance(blob, bytes)
        # Vendor envram format: NUL-terminated key=value, double-NUL terminated.
        self.assertIn(b"et0macaddr=00:11:22:33:44:50\x00", blob)
        self.assertTrue(blob.endswith(b"\x00\x00"))
        # The known consumer key (mfg_set_base_macaddr does `envram get et0macaddr`).
        entries = [e for e in blob.split(b"\x00") if e]
        self.assertTrue(any(e.startswith(b"et0macaddr=") for e in entries))

    def test_mount_shim_present(self):
        _, patches = self._run(executables=["ethswctl"], symbols=["wl_probe"])
        data, _ = patches["sdk.broadcom_hnd.mtd"]
        shim = data["static_files"]["/rom/etc/init.d/hndnvram.sh"]
        self.assertEqual(shim["mode"], 0o755)
        # mount_ubi becomes a no-op success that stages the pre-seeded blob.
        self.assertIn("mount_ubi", shim["contents"])
        self.assertIn("/mnt/nvram", shim["contents"])

    def test_pack_envram_format(self):
        _pack_envram = _builtin("BroadcomHndMtdProfile").patch.__globals__["_pack_envram"]
        blob = _pack_envram({"a": "1", "b": "x:y"})
        self.assertEqual(blob, b"a=1\x00b=x:y\x00\x00")


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

    def test_uclibc_alone_does_not_fire_qualcomm(self):
        # ld-uClibc.so.0 is on any uClibc firmware (e.g. Realtek RTL819x); it was
        # dropped from the fingerprint so it can no longer false-fire Qualcomm.
        runner, patches = self._run(files=["ld-uClibc.so.0"])
        self.assertIsNone(self._match(runner))
        self.assertNotIn("sdk.qualcomm_qsdk", patches)


class TestRealtekRtl819xProfile(unittest.TestCase):
    def _run(self, **kw):
        return run(profile_classes=("RealtekRtl819xProfile",), **kw)

    def _match(self, runner):
        return runner.manager.plugins["SdkFinder"].verdict("realtek_rtl819x")

    def test_apmib_lib_plus_symbol_enables(self):
        # apmib.so (file) + apmib_get/set (symbol) = 2 signals -> enabled.
        runner, patches = self._run(
            files=["apmib.so"], symbols=["apmib_get", "apmib_set"],
        )
        v = self._match(runner)
        self.assertEqual(v["score"], 2)
        self.assertTrue(v["enabled"])

        data, enabled = patches["sdk.realtek_rtl819x"]
        self.assertTrue(enabled)
        # Graduated sdk.realtek: the apmib_get/set aliases ride in the bundle.
        self.assertEqual(data["lib_inject"]["aliases"]["apmib_get"], "libinject_apmib_get")
        self.assertEqual(data["lib_inject"]["aliases"]["apmib_set"], "libinject_apmib_set")

    def test_apmib_lib_alone_is_disabled_candidate(self):
        # Only the apmib.so file signal fires -> score 1 -> disabled candidate.
        runner, patches = self._run(files=["apmib.so"])
        v = self._match(runner)
        self.assertEqual(v["score"], 1)
        self.assertFalse(v["enabled"])
        self.assertFalse(patches["sdk.realtek_rtl819x"][1])

    def test_boot_tier_is_disabled_candidate(self):
        # The silicon boot tier (flash MTD + RTL8367 switch) is always a DISABLED
        # candidate, additive to the auto-enabled libinject tier.
        runner, patches = run(
            profile_classes=("RealtekRtl819xProfile", "RealtekRtl819xBootProfile"),
            files=["apmib.so"], executables=["iwcontrol"], symbols=["apmib_get"],
        )
        self.assertTrue(patches["sdk.realtek_rtl819x"][1])       # libinject: enabled
        self.assertIn("sdk.realtek_rtl819x.boot", patches)
        self.assertFalse(patches["sdk.realtek_rtl819x.boot"][1])  # boot: disabled candidate
        boot = patches["sdk.realtek_rtl819x.boot"][0]
        self.assertIn("/dev/mtd", boot["pseudofiles"])

    def test_broadcom_target_does_not_fire_realtek(self):
        # et/nvram_get (Broadcom) must not trip the Realtek profile.
        runner, patches = self._run(interfaces=["vlan1", "et"], symbols=["nvram_get"])
        self.assertIsNone(self._match(runner))
        self.assertNotIn("sdk.realtek_rtl819x", patches)


if __name__ == "__main__":
    unittest.main()
