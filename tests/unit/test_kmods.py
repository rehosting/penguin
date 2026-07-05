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
