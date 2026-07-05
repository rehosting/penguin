"""In-place harness coverage for the KmodTracker intervention plugin
(pyplugins/interventions/kmods.py), driven host-side with no PANDA/guest.

The syscall handlers (init_module/finit_module) are portal generators reaching
into ``plugins.osi`` (out of scope for the cheap harness), but the decision
logic they lean on — name extraction, allow/deny classification, and the
modules.log writer — is plain host logic and is what we drive here.
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
KMODS = REPO_ROOT / "pyplugins" / "interventions" / "kmods.py"


def test_extract_module_name_strips_path_and_ko(tmp_path):
    lp = load_pyplugin(str(KMODS), outdir=tmp_path)
    assert lp.plugin._extract_module_name("/lib/modules/foo.ko") == "foo"
    assert lp.plugin._extract_module_name("bar") == "bar"
    assert lp.plugin._extract_module_name("") is None


def test_allow_and_deny_classification(tmp_path):
    lp = load_pyplugin(str(KMODS), outdir=tmp_path,
                       args={"allowlist": ["wireguard"], "denylist": ["evil"]})
    assert lp.plugin.is_allowed("/lib/wireguard.ko") is True
    assert lp.plugin.is_allowed("/lib/other.ko") is False
    assert lp.plugin.is_denied("/lib/evil.ko") is True
    assert lp.plugin.is_denied("/lib/wireguard.ko") is False
    # Empty path is neither allowed nor denied.
    assert lp.plugin.is_allowed("") is False and lp.plugin.is_denied("") is False


def test_track_kmod_appends_to_modules_log(tmp_path):
    lp = load_pyplugin(str(KMODS), outdir=tmp_path)
    lp.plugin.track_kmod("/lib/modules/a.ko")
    lp.plugin.track_kmod("/lib/modules/b.ko")
    rows = (tmp_path / "modules.log").read_text().splitlines()
    assert rows == ["/lib/modules/a.ko", "/lib/modules/b.ko"]


def test_defaults_empty_lists(tmp_path):
    lp = load_pyplugin(str(KMODS), outdir=tmp_path)
    assert lp.plugin.allowlist == [] and lp.plugin.denylist == []
    assert lp.plugin.is_allowed("/lib/anything.ko") is False


# --- generator syscall handlers, driven through the harness pump --------------

class _OSI:
    """Generator doubles for the sibling ``plugins.osi`` calls kmods makes."""
    def __init__(self, args=None, fd_name=None):
        self._args = args or []
        self._fd_name = fd_name

    def get_args(self, pid=None):
        yield from ()
        return list(self._args)

    def get_fds(self):
        yield from ()
        return []

    def get_fd_name(self, fd):
        yield from ()
        return self._fd_name


class _Sys:
    def __init__(self):
        self.retval = None
        self.skip_syscall = False


def test_init_module_blocks_unlisted_module_by_default(tmp_path):
    osi = _OSI(args=["insmod", "/lib/modules/foo.ko"])
    lp = load_pyplugin(str(KMODS), outdir=tmp_path, doubles={"osi": osi})
    sc = _Sys()
    lp.dispatch_syscall("init_module", None, None, sc, 0, 0, 0, on_return=False)
    assert sc.skip_syscall is True and sc.retval == 0
    assert (tmp_path / "modules.log").read_text().splitlines() == ["/lib/modules/foo.ko"]


def test_init_module_allows_allowlisted_module(tmp_path):
    osi = _OSI(args=["insmod", "/lib/wireguard.ko"])
    lp = load_pyplugin(str(KMODS), outdir=tmp_path,
                       args={"allowlist": ["wireguard"]}, doubles={"osi": osi})
    sc = _Sys()
    lp.dispatch_syscall("init_module", None, None, sc, 0, 0, 0, on_return=False)
    assert sc.skip_syscall is False  # allowed to load
    assert (tmp_path / "modules.log").read_text().splitlines() == ["/lib/wireguard.ko"]


def test_init_module_passes_through_igloo_ko(tmp_path):
    osi = _OSI(args=["/igloo/utils/busybox", "insmod", "/igloo/boot/igloo.ko"])
    lp = load_pyplugin(str(KMODS), outdir=tmp_path, doubles={"osi": osi})
    sc = _Sys()
    lp.dispatch_syscall("init_module", None, None, sc, 0, 0, 0, on_return=False)
    assert sc.skip_syscall is False               # our own module loads
    assert not (tmp_path / "modules.log").exists()  # and isn't tracked


def test_finit_module_blocks_denied_module(tmp_path):
    osi = _OSI(fd_name="/lib/evil.ko")
    lp = load_pyplugin(str(KMODS), outdir=tmp_path,
                       args={"denylist": ["evil"]}, doubles={"osi": osi})
    sc = _Sys()
    lp.dispatch_syscall("finit_module", None, None, sc, 5, 0, 0, on_return=False)
    assert sc.skip_syscall is True and sc.retval == 0
    assert (tmp_path / "modules.log").read_text().splitlines() == ["/lib/evil.ko"]
