"""Host-side snapshot coverage for the HyperFile intervention plugin
(pyplugins/interventions/hyperfile.py), driven with no PANDA/guest.

HyperFile records guest accesses to modeled pseudo-files into a YAML log that
lives in the wiped out_dir, so a snapshot restore must carry the recorded
results forward. The plugin imports ``hyper.consts`` (FFI-enum boundary) and its
__init__ needs a live panda + models dict, so we load it with ``real_isf=`` and
``call_init=False``, set the two attributes the snapshot path uses, and build the
results dict through the real ``handle_result`` appender.
"""
from pathlib import Path

import yaml

from penguin.testing import load_pyplugin, snapshot_roundtrip

REPO_ROOT = Path(__file__).resolve().parents[2]
HYPERFILE = str(REPO_ROOT / "pyplugins" / "interventions" / "hyperfile.py")


def _load(tmp_path, isf):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    lp = load_pyplugin(HYPERFILE, outdir=tmp_path, real_isf=isf,
                       args={"models": {}}, call_init=False)
    # __init__ (needs a live panda + models) is skipped; establish the two
    # attributes the snapshot path relies on, exactly as __init__ would.
    lp.plugin.results = {}
    lp.plugin.log_file = str(Path(tmp_path) / "hyperfile.yaml")
    return lp


def test_save_state_none_when_idle(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert lp.plugin.save_state() is None


def test_snapshot_restores_access_log(tmp_path, igloo_ko_isf):
    src = _load(tmp_path / "a", igloo_ko_isf)
    src.plugin.handle_result("/dev/foo", "read", 5, 8, b"hello")
    src.plugin.handle_result("/dev/foo", "ioctl", 0, 0x1234, 0)

    dst = _load(tmp_path / "b", igloo_ko_isf)
    snapshot_roundtrip(src, dst)

    logged = yaml.safe_load((tmp_path / "b" / "hyperfile.yaml").read_text())
    assert logged["/dev/foo"]["read"] == [
        {"readval": 5, "bytes_requested": 8, "data": "hello"}]
    assert logged["/dev/foo"]["ioctl"] == [
        {"cmd": 0x1234, "arg": 0, "retval": 0}]
    assert dst.plugin.results == src.plugin.results
    # Live accesses keep accumulating onto the restored log.
    dst.plugin.handle_result("/dev/foo", "read", 3, 3, b"bye")
    assert len(dst.plugin.results["/dev/foo"]["read"]) == 2
