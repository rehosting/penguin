"""In-place harness coverage for the Nvram2 intervention plugin
(pyplugins/interventions/nvram2.py), driven host-side with no PANDA/guest.

Nvram2's ``__init__`` shells out to ``clang-20`` to compile lib_inject for every
ABI — host-impossible without the toolchain image — so we load with
``call_init=False`` (the class still imports, so its class-body
``@plugins.subscribe`` decorators register) and set the handful of attributes the
get/set/clear handlers actually use. The event handlers themselves are plain host
logic: normalize the tmpfs key, append a CSV row, and mutate the set-value state.
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
NVRAM2 = REPO_ROOT / "pyplugins" / "interventions" / "nvram2.py"

# Guest passes the full tmpfs path; the plugin keeps only the basename.
KEY = "/igloo/libnvram_tmpfs/wan_proto"


def _load(tmp_path, log_mask=3):
    """Load nvram2 without running __init__ and wire the minimal handler state."""
    lp = load_pyplugin(str(NVRAM2), outdir=tmp_path, call_init=False)
    p = lp.plugin
    p.outdir = str(tmp_path)
    p.logging_enabled = True
    p.log_mask = log_mask
    p.state = {}
    p.persist = False
    p.persist_path = None
    p.log_write("key,operation,value\n")  # header, as real __init__ does
    return lp, p


def _rows(tmp_path):
    return (tmp_path / "nvram.csv").read_text().splitlines()


def test_get_hit_and_miss_are_logged(tmp_path):
    lp, _p = _load(tmp_path)
    lp.dispatch("igloo_nvram_get_hit", None, KEY)
    lp.dispatch("igloo_nvram_get_miss", None, KEY)
    assert _rows(tmp_path)[1:] == ["wan_proto,hit,", "wan_proto,miss,"]


def test_set_logs_and_updates_state(tmp_path):
    lp, p = _load(tmp_path)
    lp.dispatch("igloo_nvram_set", None, KEY, "dhcp")
    assert _rows(tmp_path)[1:] == ["wan_proto,set,dhcp"]
    assert p.state == {"wan_proto": "dhcp"}


def test_clear_logs_and_pops_state(tmp_path):
    lp, p = _load(tmp_path)
    lp.dispatch("igloo_nvram_set", None, KEY, "dhcp")
    lp.dispatch("igloo_nvram_clear", None, KEY)
    assert _rows(tmp_path)[-1] == "wan_proto,clear,"
    assert p.state == {}


def test_key_without_slash_is_ignored(tmp_path):
    lp, _p = _load(tmp_path)
    lp.dispatch("igloo_nvram_get_hit", None, "bare_key")
    assert _rows(tmp_path) == ["key,operation,value\n".strip()]  # header only


def test_logging_enabled_returns_mask(tmp_path):
    lp, _p = _load(tmp_path, log_mask=3)
    assert lp.dispatch("igloo_nvram_logging_enabled", None) == [3]
