"""Host-side coverage for the syscall hook budget (pyplugins/apis/syscalls.py).

WHY THE BUDGET EXISTS. A pyplugin-hooked syscall costs 95.880 us against an
unhooked one's 1.161 us, measured on bugbench with an injected-delay control,
a null pair and a linearity check all passing
(analysis/fastsnap/speedscheme.py). The three-layer split puts 98.8% of that in
the portal round trip -- the emulated kernel is 1.1 us and igloo_driver 0.02 --
so the only lever on hook cost is how many hooks FIRE.

Before this, no run could see that about itself, and the consequence was
concrete: snapfeed carried fifteen census hooks documented as "cheap: one
counter increment per call". The increment is cheap; reaching it is not, and
nothing in the system could have contradicted the comment.

These tests drive the report directly -- no PANDA, no guest.
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
SYSCALLS = REPO_ROOT / "pyplugins" / "apis" / "syscalls.py"


def _plugin(isf, tmp_path, **args):
    # real_isf: the plugin's __init__ reads the HYPER_OP enum out of the
    # module's DWARF, so a null backend cannot construct it.
    return load_pyplugin(str(SYSCALLS), outdir=str(tmp_path), args=args,
                         real_isf=isf)


def test_budget_is_off_by_default(igloo_ko_isf, tmp_path):
    """Opt-in, because a budget nobody reads is one more thing in the path."""
    p = _plugin(igloo_ko_isf, tmp_path).plugin
    assert p.hook_budget is False
    rep = p.hook_budget_report()
    assert rep["enabled"] is False
    assert rep["total_firings"] == 0


def test_budget_ranks_by_firings_and_names_the_syscall(igloo_ko_isf, tmp_path):
    p = _plugin(igloo_ko_isf, tmp_path, hook_budget=1).plugin
    # Stand in for registration: the report reads _hook_info for attribution
    # and _fire_counts for the count, which is what the dispatcher fills.
    p._hook_info[0x1000] = {"name": "poll", "procname": "lighttpd",
                            "on_enter": True}
    p._hook_info[0x2000] = {"name": "writev", "procname": "lighttpd",
                            "on_enter": True}
    p._fire_counts[0x1000] = 5000
    p._fire_counts[0x2000] = 12

    rep = p.hook_budget_report()
    assert rep["enabled"] is True
    assert rep["total_firings"] == 5012
    # Ranked most-expensive first: the point of the report is to name the
    # hook worth deleting, which is the one that fires most.
    assert [h["syscall"] for h in rep["hooks"]] == ["poll", "writev"]
    assert rep["hooks"][0]["comm"] == "lighttpd"
    assert rep["hooks"][0]["firings"] == 5000


def test_budget_estimate_uses_the_measured_per_firing_cost(igloo_ko_isf, tmp_path):
    """The count is exact; the milliseconds are count x a measured constant.

    Pinned so that a change to the cost constant has to be deliberate -- it
    came from a specific measurement on a specific target and is not a free
    parameter to be nudged.
    """
    p = _plugin(igloo_ko_isf, tmp_path, hook_budget=1).plugin
    p._hook_info[0x1000] = {"name": "poll", "on_enter": True}
    p._fire_counts[0x1000] = 1000

    rep = p.hook_budget_report()
    assert rep["us_per_firing_assumed"] == 95.880
    # 1000 firings x 95.880 us = 95.88 ms
    assert abs(rep["est_total_ms"] - 95.88) < 0.01
    assert abs(rep["hooks"][0]["est_ms"] - 95.88) < 0.01


def test_budget_written_at_uninit_only_when_enabled(igloo_ko_isf, tmp_path):
    p = _plugin(igloo_ko_isf, tmp_path, hook_budget=1)
    p.plugin._hook_info[0x1000] = {"name": "read", "on_enter": True}
    p.plugin._fire_counts[0x1000] = 7
    p.finalize()
    import json
    out = json.loads((tmp_path / "hook_budget.json").read_text())
    assert out["total_firings"] == 7
    assert out["hooks"][0]["syscall"] == "read"


def test_no_file_when_budget_is_off(igloo_ko_isf, tmp_path):
    p = _plugin(igloo_ko_isf, tmp_path)
    p.finalize()
    assert not (tmp_path / "hook_budget.json").exists()


def test_wildcard_hook_is_named_not_blank(igloo_ko_isf, tmp_path):
    """An on_all hook has no syscall name; it must not report as empty.

    A blank row in a ranking is the row a reader skips, and a wildcard hook is
    precisely the one that cannot be afforded -- it fires on every syscall.
    """
    p = _plugin(igloo_ko_isf, tmp_path, hook_budget=1).plugin
    p._hook_info[0x3000] = {"on_all": True, "on_return": True}
    p._fire_counts[0x3000] = 90000
    rep = p.hook_budget_report()
    assert rep["hooks"][0]["syscall"] == "<all>"
