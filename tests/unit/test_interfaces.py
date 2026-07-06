"""In-place harness coverage for the Interfaces analysis plugin
(pyplugins/analysis/interfaces.py), driven host-side with no PANDA/guest.

This plugin sits *behind the FFI-enum boundary*: it does
``from apis.syscalls import ValueFilter``, which transitively builds the
``hyper.consts`` enum tables at import. We load it with ``real_isf=`` — the real
published driver ISF read through ``dwarffi`` — so the import succeeds against real
enum values and the plugin's host-side logic (interface-name validation/dedup, the
exec parser for ip/ifconfig, and the ioctl-return generator handler) can be
exercised.
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
INTERFACES = str(REPO_ROOT / "pyplugins" / "analysis" / "interfaces.py")


class _Mem:
    """plugins.mem double: read_str returns the interface string under test."""
    def __init__(self, s=""):
        self.s = s

    def read_str(self, addr):
        yield from ()
        return self.s


class _Sys:
    def __init__(self, retval):
        self.retval = retval


def _load(tmp_path, isf, netdevs=None, mem=None):
    return load_pyplugin(
        INTERFACES, outdir=tmp_path, real_isf=isf,
        args={"conf": {"netdevs": netdevs or []}},
        doubles={"mem": mem or _Mem()},
    )


def _lines(path):
    return [ln for ln in path.read_text().splitlines() if ln]


# --- the plugin imports at all (boundary crossed) --------------------------- #
def test_plugin_loads_behind_enum_boundary(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert type(lp.plugin).__name__ == "Interfaces"
    # both log files are created empty at init
    assert (tmp_path / "iface.log").exists()
    assert (tmp_path / "iface_ioctl.log").exists()


# --- handle_interface: validation + dedup + logging ------------------------- #
def test_handle_interface_logs_new_valid_iface(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.handle_interface("eth0")
    lp.plugin.handle_interface("eth0")           # dedup
    assert _lines(tmp_path / "iface.log") == ["eth0"]


def test_handle_interface_skips_known_and_ignored(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, netdevs=["eth1"])
    lp.plugin.handle_interface("eth1")           # already an added netdev
    lp.plugin.handle_interface("lo")             # ignored
    lp.plugin.handle_interface("")               # empty
    lp.plugin.handle_interface("bad name!!")     # fails the name regex
    assert _lines(tmp_path / "iface.log") == []


# --- failing_ioctl: dedup + logging ----------------------------------------- #
def test_failing_ioctl_logs_and_dedupes(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.failing_ioctl(0x8910, "eth0", -19)
    lp.plugin.failing_ioctl(0x8910, "eth0", -19)   # dedup on (ioctl, iface)
    assert _lines(tmp_path / "iface_ioctl.log") == ["0x8910,eth0,-19"]


# --- exec parser: ip / ifconfig --------------------------------------------- #
def test_exec_parses_ip_dev_and_ifconfig(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.dispatch("exec_event", {"procname": "/sbin/ip",
                               "argv": ["ip", "link", "set", "dev", "eth2", "up"]})
    lp.dispatch("exec_event", {"procname": "/sbin/ifconfig",
                               "argv": ["ifconfig", "eth3"]})
    # our own interface-adding helpers are ignored
    lp.dispatch("exec_event", {"procname": "/igloo/utils/ip",
                               "argv": ["ip", "dev", "eth9"]})
    assert _lines(tmp_path / "iface.log") == ["eth2", "eth3"]


# --- after_ioctl: the portal-generator syscall handler ---------------------- #
def test_after_ioctl_missing_interface(tmp_path, igloo_ko_isf):
    mem = _Mem("eth4")
    lp = _load(tmp_path, igloo_ko_isf, mem=mem)
    # rv == -ENODEV -> a missing interface is recorded, and the ioctl is logged
    lp.dispatch_syscall("ioctl", None, None, _Sys(retval=-19), 3, 0x8910, 0x1000,
                        on_return=True)
    assert _lines(tmp_path / "iface.log") == ["eth4"]
    assert _lines(tmp_path / "iface_ioctl.log") == ["0x8910,eth4,-19"]
