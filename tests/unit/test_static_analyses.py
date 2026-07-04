import tempfile
import types
import unittest
from pathlib import Path

from penguin.init_plugin import InitContext
from penguin.plugin_manager import _import_plugin_classes

REPO_ROOT = Path(__file__).resolve().parents[2]
PseudofileFinder = dict(
    _import_plugin_classes(str(REPO_ROOT / "pyplugins/init/pseudofile_finder.py"))
)["PseudofileFinder"]
PseudofilesTailored = dict(
    _import_plugin_classes(str(REPO_ROOT / "pyplugins/init/pseudofile_patches.py"))
)["PseudofilesTailored"]
InterfaceFinder = dict(
    _import_plugin_classes(str(REPO_ROOT / "pyplugins/init/interface_finder.py"))
)["InterfaceFinder"]
EnvFinder = dict(
    _import_plugin_classes(str(REPO_ROOT / "pyplugins/init/env_finder.py"))
)["EnvFinder"]
LibrarySymbols = dict(
    _import_plugin_classes(str(REPO_ROOT / "pyplugins/init/library_symbols.py"))
)["LibrarySymbols"]


def make_plugin(cls, extracted_dir):
    """Instantiate an init plugin against an extracted-fs dir, without the
    plugin manager (enough for exercising its cached analyses)."""
    plugin = cls.__new__(cls)
    plugin.ctx = InitContext(
        fs_archive=Path(extracted_dir, "unused.tar.gz"),
        extracted_fs=extracted_dir,
        proj_dir=extracted_dir,
        static_dir=Path(extracted_dir, "static"),
        patch_dir=Path(extracted_dir, "static_patches"),
    )
    return plugin


class TestPseudofileFinder(unittest.TestCase):
    def test_does_not_model_proc_sys_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "cat /proc/sys\n"
                "cat /proc/sys/\n"
                "cat /proc/sys/kernel/hostname\n"
                "cat /proc/vendor_knob\n"
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        self.assertNotIn("/proc/sys", result["proc"])
        self.assertNotIn("/proc/sys/kernel/hostname", result["proc"])
        self.assertIn("/proc/vendor_knob", result["proc"])

    def test_does_not_model_static_dev_convenience_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "ls /dev/pts/\n"
                "ls /dev/fd/\n"
                "ls /dev/shm/\n"
                "cat /dev/vendor_knob\n"
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        self.assertNotIn("/dev/pts", result["dev"])
        self.assertNotIn("/dev/pts/.placeholder", result["dev"])
        self.assertNotIn("/dev/fd", result["dev"])
        self.assertNotIn("/dev/fd/.placeholder", result["dev"])
        self.assertNotIn("/dev/shm", result["dev"])
        self.assertIn("/dev/vendor_knob", result["dev"])

    def test_drops_glued_paths_under_critical_devices(self):
        """penguin#830: a greedy scrape glues strings into a path nested under
        /dev/null; modeling it recreates /dev/null as a directory. Drop it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mimic packed binary strings with no separators between them.
            Path(tmpdir, "blob.bin").write_bytes(
                b"/dev/null/dev/ptmx/dev/ptsSSH_FX_OKhmac\x00"
                b"/dev/watchdog\x00"
                b"/dev/vendor_knob\x00"
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        # Nothing under or equal to /dev/null may be modeled.
        self.assertFalse(
            [d for d in result["dev"] if d.startswith("/dev/null")],
            result["dev"],
        )
        # Real custom devices survive.
        self.assertIn("/dev/vendor_knob", result["dev"])

    def test_drops_children_of_leaf_device_nodes(self):
        """Any /dev/<leaf>/child forces <leaf> to become a directory, clobbering
        a real device node - not just /dev/null. Only known /dev directories may
        contain children."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "echo x > /dev/null/x\n"
                "cat /dev/ttyS0/garbage\n"
                "cat /dev/watchdog/foo\n"
                "dd of=/dev/mtdblock0/bar\n"
                "cat /dev/net/tun\n"          # legit: /dev/net is a directory
                "cat /dev/vendor_knob\n"      # legit: single-component leaf
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        for bad in ("/dev/null/x", "/dev/ttyS0/garbage", "/dev/watchdog/foo",
                    "/dev/mtdblock0/bar"):
            self.assertNotIn(bad, result["dev"])
        self.assertIn("/dev/net/tun", result["dev"])
        self.assertIn("/dev/vendor_knob", result["dev"])

    def test_drops_well_known_and_block_devices(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "cat /dev/rtc0\n"
                "cat /dev/watchdog0\n"
                "dd if=/dev/sda1\n"
                "dd if=/dev/mmcblk0p1\n"
                "cat /dev/fb0\n"
                "logger -f /dev/log\n"
                "cat /dev/vendor_knob\n"
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        for dev in ("/dev/rtc0", "/dev/watchdog0", "/dev/sda1",
                    "/dev/mmcblk0p1", "/dev/fb0", "/dev/log"):
            self.assertNotIn(dev, result["dev"])
        self.assertIn("/dev/vendor_knob", result["dev"])

    def test_drops_binfmt_misc_mount_children(self):
        """penguin#830: a scraped sysctl under the binfmt_misc fs mount crashes
        register_sysctl() on old kernels; never model children of fs mounts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "blob.bin").write_bytes(
                b"/proc/sys/fs/binfmt_misc/WSLInterop/signal\x00"
                b"/proc/vendor_knob\x00"
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        self.assertFalse(
            [p for p in result["proc"] if "binfmt_misc" in p],
            result["proc"],
        )
        self.assertIn("/proc/vendor_knob", result["proc"])

    def test_drops_glued_sysctls(self):
        """penguin#830: greedy scrapes glue trailing bytes onto real sysctls
        (hostname->hostname2006). Drop the mid-component extensions, keep real
        (even novel vendor) sysctls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "blob.bin").write_bytes(
                b"/proc/sys/kernel/hostname2006\x00"
                b"/proc/sys/net/core/somaxconnabi\x00"
                b"/proc/sys/net/ipv6flush\x00"
                b"/proc/sys/net/vendor_knob\x00"   # real novel sysctl - keep
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        self.assertNotIn("/proc/sys/kernel/hostname2006", result["proc"])
        self.assertNotIn("/proc/sys/net/core/somaxconnabi", result["proc"])
        self.assertNotIn("/proc/sys/net/ipv6flush", result["proc"])
        self.assertIn("/proc/sys/net/vendor_knob", result["proc"])

    def test_drops_per_interface_conf_sysctls(self):
        """The kernel provides net/ipv[46]/conf|neigh/<iface>/* for every real
        interface; never model them (any iface name, incl. unexpanded vars)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "rc.net").write_text(
                "echo 1 > /proc/sys/net/ipv4/conf/br0/forwarding\n"
                "echo 0 > /proc/sys/net/ipv4/conf/wan/rp_filter\n"
                "echo 1 > /proc/sys/net/ipv6/conf/lan/disable_ipv6\n"
                "echo 0 > /proc/sys/net/ipv4/neigh/eth1/retrans_time\n"
                "cat /proc/sys/net/vendor_knob\n"
            )

            result = make_plugin(PseudofileFinder, tmpdir).pseudofiles

        self.assertFalse(
            [p for p in result["proc"]
             if "/conf/" in p or "/neigh/" in p],
            result["proc"],
        )
        self.assertIn("/proc/sys/net/vendor_knob", result["proc"])


class TestPseudofilesTailored(unittest.TestCase):
    def test_never_models_critical_node_children(self):
        """Backstop: even if a bad path reaches the patcher, it must not model a
        critical device or a child under one."""
        plugin = PseudofilesTailored.__new__(PseudofilesTailored)
        plugin.plugins = types.SimpleNamespace(
            PseudofileFinder=types.SimpleNamespace(
                pseudofiles={
                    "dev": [
                        "/dev/null",
                        "/dev/null/dev/ptmx",
                        "/dev/vendor_knob",
                    ],
                    "proc": [],
                }
            )
        )

        out = plugin.patch(ctx=None)
        modeled = set(out["pseudofiles"])
        self.assertNotIn("/dev/null", modeled)
        self.assertFalse([p for p in modeled if p.startswith("/dev/null/")])
        self.assertIn("/dev/vendor_knob", modeled)


class TestInterfaceFinder(unittest.TestCase):
    def test_excludes_command_keywords_and_placeholders(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "ifconfig interface [up|down]\n"   # 'interface' is a doc placeholder
                "ip link set eth0 up\n"            # 'set' is a sub-command keyword
                "ifconfig eth0 up\n"               # eth0 is real
            )

            result = make_plugin(InterfaceFinder, tmpdir).interfaces or {}

        found = set(result.get("commands", []))
        self.assertNotIn("interface", found)
        self.assertNotIn("set", found)
        self.assertIn("eth0", found)

    def test_keeps_named_bridges_drops_bare_and_veth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "ifconfig br-lan up\n"     # real bridge - keep
                "ifconfig veth0 up\n"      # container veth - drop
            )

            result = make_plugin(InterfaceFinder, tmpdir).interfaces or {}

        found = set(result.get("commands", []))
        self.assertIn("br-lan", found)
        self.assertNotIn("veth0", found)

    def test_captures_device_after_ip_subcommand(self):
        """`ip link set eth0 up` must surface eth0, not the 'set' keyword."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "script.sh").write_text(
                "ip link set eth0 up\n"
                "ip addr show wlan1\n"
            )

            result = make_plugin(InterfaceFinder, tmpdir).interfaces or {}

        found = set(result.get("commands", []))
        self.assertIn("eth0", found)
        self.assertIn("wlan1", found)
        self.assertNotIn("set", found)
        self.assertNotIn("show", found)


class TestEnvFinder(unittest.TestCase):
    def _run(self, tmpdir):
        plugin = make_plugin(EnvFinder, tmpdir)
        plugin.plugins = types.SimpleNamespace(
            InitFinder=types.SimpleNamespace(inits=[])
        )
        return plugin.env

    def test_ignores_well_known_kernel_params(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # The finder captures the first KEY= that follows a /proc/cmdline
            # reference on a line, so give each key its own reference.
            Path(tmpdir, "rcS").write_text(
                "grep /proc/cmdline root=/dev/mtdblock1\n"
                "grep /proc/cmdline console=ttyS0\n"
                "grep /proc/cmdline vendor_mode=fast\n"
            )

            env = self._run(tmpdir)

        # Standard kernel params must not be surfaced as discovered knobs...
        self.assertNotIn("root", env)
        self.assertNotIn("console", env)
        # ...but a real vendor-specific knob still is.
        self.assertIn("vendor_mode", env)


class TestLibrarySymbolsNvram(unittest.TestCase):
    def test_rejects_pointer_walk_garbage(self):
        """When the NVRAM pointer walk runs off the table it reads toolchain
        banners and control-char keys - reject those, keep real defaults."""
        plausible = LibrarySymbols._plausible_nvram
        # real defaults survive
        self.assertTrue(plausible("ASUS_EULA", "0"))
        self.assertTrue(plausible("wl0_ssid", "ASUS"))
        self.assertTrue(plausible("_hidden", ""))
        # garbage from over-walking the table
        self.assertFalse(plausible("*nvram", "GCC: (Buildroot 2012.02) 4.5.3"))
        self.assertFalse(plausible("-1", "aeabi"))
        self.assertFalse(plausible(".swap", "x"))
        self.assertFalse(plausible("{", "x"))
        self.assertFalse(plausible("\x057-A", "A0"))
        self.assertFalse(plausible("\x17", "A0"))
        # real-looking key paired with a toolchain-banner value is still bogus
        self.assertFalse(plausible("enabled", "GCC: (Buildroot 2012.02) 4.5.3"))


if __name__ == "__main__":
    unittest.main()
