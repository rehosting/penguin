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
    # Direction is part of the label: enter and return are different hooks,
    # and so are two plugins on the same syscall. Identical-looking rows in
    # the ranking were the first thing that read as a report bug.
    assert [h["syscall"] for h in rep["hooks"]] == ["poll:enter", "writev:enter"]
    assert rep["hooks"][0]["syscall_name"] == "poll"
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
    assert out["hooks"][0]["syscall"] == "read:enter"


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
    assert rep["hooks"][0]["syscall"] == "<all>:return"


def test_mark_splits_boot_from_the_measured_phase(igloo_ko_isf, tmp_path):
    """A whole-run total cannot answer what a LAP costs.

    Boot dominates the count -- the first real budget from firmware had 5,791
    ioctl firings, nearly all of them bringing the system up -- while the
    decision a fuzzing loop makes is about the laps. fastloop marks the budget
    at the instant it arms, and everything after that mark is lap cost.
    """
    p = _plugin(igloo_ko_isf, tmp_path, hook_budget=1).plugin
    p._hook_info[0x1000] = {"name": "ioctl", "on_return": True}
    p._hook_info[0x2000] = {"name": "read", "on_enter": True}

    p._fire_counts[0x1000] = 5791          # boot
    p._fire_counts[0x2000] = 12
    p.hook_budget_mark("armed")

    p._fire_counts[0x1000] += 4            # during laps
    p._fire_counts[0x2000] += 6000

    rep = p.hook_budget_report()
    assert rep["total_firings"] == 5791 + 12 + 4 + 6000
    assert rep["marks"]["armed"]["firings"] == 6004
    by = {r["syscall"]: r["firings_since"]["armed"] for r in rep["hooks"]}
    # ioctl dominates the RUN and is nearly absent from the laps; read is the
    # other way round. A report without the split inverts the ranking that
    # matters.
    assert by["ioctl:return"] == 4
    assert by["read:enter"] == 6000


def test_remark_moves_the_boundary_to_the_kept_draw(igloo_ko_isf, tmp_path):
    """Re-arming must re-mark: the laps belong to the draw actually kept.

    A rejected draw's probe laps are not the measured phase, and leaving the
    first mark in place would bill them to the accepted one.
    """
    p = _plugin(igloo_ko_isf, tmp_path, hook_budget=1).plugin
    p._hook_info[0x1000] = {"name": "writev", "on_enter": True}
    p._fire_counts[0x1000] = 100
    p.hook_budget_mark("armed")            # draw 1, later rejected
    p._fire_counts[0x1000] += 50           # its probe laps
    p.hook_budget_mark("armed")            # draw 2, kept
    p._fire_counts[0x1000] += 7

    rep = p.hook_budget_report()
    assert rep["marks"]["armed"]["firings"] == 7


def test_mark_is_a_noop_when_the_budget_is_off(igloo_ko_isf, tmp_path):
    p = _plugin(igloo_ko_isf, tmp_path).plugin
    p.hook_budget_mark("armed")
    assert p.hook_budget_report()["marks"] == {}
