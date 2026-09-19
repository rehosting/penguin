"""Host-side test of the fastsnap API plugin (pyplugins/apis/fastsnap.py).

No PANDA, no guest, no QEMU: everything this plugin does is schedule an op onto
QEMU's main loop and read single-slot accessors afterwards. That is pure host
logic with one genuinely hard property -- the operation is asynchronous, and the
plugin runs on a vCPU thread that must never block on it -- so the double below
runs bottom halves only when the test says so. A double that completed ops
synchronously would make the polling untestable and would pass a plugin that
deadlocks on the real thing.

The assertions that matter are the ones about ORDER and about NEGATIVES:

  * the sequence number must be captured before the schedule, or a caller can
    observe its own completion test already satisfied and read the previous
    operation's numbers (plausible, wrong, and silent);
  * a result read before completion must raise rather than return the previous
    operation's values;
  * -1 from an oracle means "could not look" and must never be laundered into
    a zero on the way through this plugin.

Each of those has been a real defect in this lane, in code that passed
everything else.
"""
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
FASTSNAP = REPO_ROOT / "pyplugins" / "apis" / "fastsnap.py"

SECTIONS = ["cpu", "cpu_common", "timer", "pl011",
            "0000:00:01.0/virtio-net"]


class FakeQemu:
    """A QEMU whose bottom halves run only when the test runs them."""

    def __init__(self):
        self.seq = 0
        self.pending = None
        self.ops = []
        self.allowlist = None
        self.denylist = None
        self.missing = []
        self.rc = 0
        self.us = 348
        self.diff_pages = 0
        self.diff_us = 48000
        self.dev_sections = 0
        self.dev_report = ""
        self.restored = 26

    # -- preflight --
    def fastsnap_missing_symbols(self):
        return list(self.missing)

    def fastsnap_section_names(self):
        return list(SECTIONS)

    # -- scoping --
    def fastsnap_set_allowlist(self, names):
        self.allowlist = list(names)

    def fastsnap_set_denylist(self, names):
        self.denylist = list(names)

    # -- scheduling --
    def fastsnap_schedule(self, op):
        self.ops.append(op)
        self.pending = op

    def fastsnap_seq(self):
        return self.seq

    def run_bottom_half(self):
        assert self.pending is not None, "nothing was scheduled"
        self.pending = None
        self.seq += 1

    # -- accessors (single-slot, exactly like the C side) --
    def fastsnap_last_rc(self):
        return self.rc

    def fastsnap_last_us(self):
        return self.us

    def fastsnap_last_digest(self):
        return 0xABCD

    def fastsnap_last_ram_digest(self):
        return 0xBEEF

    def fastsnap_ram_snapshot_bytes(self):
        return 281346048

    def fastsnap_ram_restored_pages(self):
        return self.restored

    def fastsnap_block_size(self):
        return 61987

    def fastsnap_diff_pages(self):
        return self.diff_pages

    def fastsnap_diff_bytes_checked(self):
        return 281346048

    def fastsnap_diff_us(self):
        return self.diff_us

    def fastsnap_diff_report(self):
        return ""

    def fastsnap_dev_diff_sections(self):
        return self.dev_sections

    def fastsnap_dev_diff_report(self):
        return self.dev_report


def _load(tmp_path, qemu=None, **args):
    lp = load_pyplugin(str(FASTSNAP), args=args, outdir=str(tmp_path),
                       call_init=False)
    lp.plugin.panda = qemu or FakeQemu()
    lp.plugin.__init__()
    return lp.plugin, lp.plugin.panda


def test_default_scope_denies_virtio(tmp_path):
    """The default is a correctness default, not a tuning one: a virtio
    device's state is split between the model, a vring in guest RAM and a
    host-side backend that is not part of the guest at all."""
    p, q = _load(tmp_path)
    p.arm()
    assert q.denylist == ["0000:00:01.0/virtio-net"]
    assert q.allowlist is None


def test_allow_reaches_qemu(tmp_path):
    p, q = _load(tmp_path, allow="cpu,timer", deny=None)
    p.arm()
    assert q.allowlist == ["cpu", "timer"]
    assert q.denylist is None


def test_allow_and_deny_together_refuse(tmp_path):
    """Two answers to one question. A precedence rule would make the block's
    scope depend on argument order, which nothing downstream reports."""
    p, _ = _load(tmp_path)
    with pytest.raises(ValueError):
        p.scope(allow="cpu", deny="timer")


def test_unknown_section_refuses_rather_than_ignoring(tmp_path):
    """An allowlist of typos produces an EMPTY block that restores nothing,
    very quickly. Every timing from such a run measures doing no work."""
    p, q = _load(tmp_path)
    with pytest.raises(ValueError) as e:
        p.scope(allow="cpu,no_such_section")
    assert "no_such_section" in str(e.value)
    assert q.allowlist is None


def test_ticket_is_not_done_until_the_bottom_half_runs(tmp_path):
    """Scheduling is not doing. This is the property a synchronous double
    would hide, and the one that deadlocks a vCPU thread if got wrong."""
    p, q = _load(tmp_path)
    t = p.arm()
    assert not t.done()
    q.run_bottom_half()
    assert t.done()


def test_result_before_completion_raises(tmp_path):
    """Rather than handing back the previous operation's numbers, which are
    indistinguishable from a real answer."""
    p, q = _load(tmp_path)
    q.run_bottom_half.__self__  # noqa: B018  (documents the double's shape)
    t = p.arm()
    with pytest.raises(RuntimeError):
        t.result()


def test_sequence_is_captured_before_the_schedule(tmp_path):
    """THE ordering bug. If the ticket read seq() after scheduling, then a
    bottom half that had already run for a PREVIOUS op would leave seq at a
    value the new ticket's own test treats as complete -- and result() would
    return the previous operation's timings and diffs, silently."""
    p, q = _load(tmp_path)
    t1 = p.arm()
    q.run_bottom_half()
    assert t1.done()
    t2 = p.reset()                 # seq is now 1; t2 must not consider itself done
    assert not t2.done(), "the ticket captured seq after scheduling"
    q.run_bottom_half()
    assert t2.done()


def test_result_is_latched_on_first_read(tmp_path):
    """The accessors are single-slot and the next op overwrites them, so a
    ticket read after a later reset would otherwise return that one's numbers."""
    p, q = _load(tmp_path)
    t = p.reset(verify=True)
    q.run_bottom_half()
    first = t.result()
    q.restored = 99999
    q.diff_pages = 41
    assert t.result() == first


def test_verify_reports_both_oracles_and_keeps_the_clocks_apart(tmp_path):
    """reset_us is the reset; the oracle's cost is its own field. Folding them
    would make every verified reset look two orders of magnitude more expensive
    than it is, and look entirely plausible doing so."""
    p, q = _load(tmp_path)
    t = p.reset(verify=True)
    q.run_bottom_half()
    r = t.result()
    assert r["us"] == q.us
    assert r["diff_us"] == q.diff_us
    assert r["us"] < r["diff_us"]
    assert r["diff_pages"] == 0
    assert r["dev_sections"] == 0


def test_plain_reset_reports_no_oracle_fields(tmp_path):
    """A reset with verification off did not look, and must not appear to have
    looked: absent is honest, zero is a claim."""
    p, q = _load(tmp_path)
    t = p.reset()
    q.run_bottom_half()
    r = t.result()
    assert "diff_pages" not in r
    assert "dev_sections" not in r
    assert r["restored_pages"] == q.restored


def test_blind_oracle_is_passed_through_as_negative(tmp_path):
    """-1 means the oracle could not look. Laundering it into 0 on the way
    through this plugin is how an instrument that said it was blind gets
    believed. (A real -1 is what surfaced guest RAM being MADV_DONTFORK.)"""
    p, q = _load(tmp_path)
    q.diff_pages = -1
    q.dev_sections = -1
    t = p.reset(verify=True)
    q.run_bottom_half()
    r = t.result()
    assert r["diff_pages"] == -1
    assert r["dev_sections"] == -1


def test_unrestored_device_sections_are_reported_by_name(tmp_path):
    """RAM byte-perfect and device state left behind is exactly what a scoped
    block fails as, and the fork oracle cannot see it."""
    p, q = _load(tmp_path, allow="cpu,timer", deny=None)
    q.dev_sections = 2
    q.dev_report = "pl011#3,pflash_cfi01#5"
    t = p.reset(verify=True)
    q.run_bottom_half()
    r = t.result()
    assert r["diff_pages"] == 0
    assert r["dev_sections"] == 2
    assert "pl011#3" in r["dev_report"]


def test_missing_symbols_is_reported_not_swallowed(tmp_path):
    """An image whose QEMU predates part of the ABI: every binding imports,
    every call returns a default, and the run produces a complete and entirely
    fictional result set. It happened to eleven symbols at once."""
    q = FakeQemu()
    q.missing = ["penguin_fastsnap_set_allowlist"]
    p, _ = _load(tmp_path, qemu=q)
    assert p.missing_symbols() == ["penguin_fastsnap_set_allowlist"]
    assert p.available() is False


def test_available_is_true_on_a_complete_abi(tmp_path):
    p, _ = _load(tmp_path)
    assert p.available() is True


def test_every_coverage_symbol_reached_for_is_in_the_preflight_list():
    """A C symbol this file calls but does not declare is invisible to the
    preflight and raises mid-run instead.

    FASTSNAP_COV_SYMBOLS is what fastloop checks before a run and refuses
    over. `_fastsnap_cov_fn` raises on anything absent -- which is the right
    behaviour at the call site and the wrong place to find out, because by
    then a boot, a warmup and an arm have been spent. The two only agree if
    every symbol reached for is also listed, and a hand-kept list of names
    that are also written out one by one a hundred lines below is exactly the
    pairing that drifts. So derive one from the file and compare.

    This is the penguin-side half of the same invariant
    qemu_builder/scripts/check-delta-present.sh enforces against the header.
    """
    import re

    src = (REPO_ROOT / "pyplugins" / "compat" / "qemu_compat.py").read_text()
    listed = set(re.findall(
        r'"(penguin_fastsnap_cov_\w+)"',
        src.split("FASTSNAP_COV_SYMBOLS = (")[1].split(")")[0]))
    assert listed, "the coverage symbol list is empty; this check is inert"

    # The list is itself part of the file, so everything in `listed` is also
    # in `mentioned`; the difference is exactly the symbols reached for and
    # never declared.
    mentioned = set(re.findall(r'"(penguin_fastsnap_cov_\w+)"', src))
    assert mentioned - listed == set(), sorted(mentioned - listed)


def test_coverage_symbols_are_not_in_the_required_group():
    """Coverage must not be a precondition for every run.

    An image whose QEMU predates coverage is a perfectly good image for every
    measurement that does not ask for it. FASTSNAP_SYMBOLS is the group
    fastloop refuses a run over, so folding these into it would turn an
    unrelated QEMU rebuild into a hard dependency of measurements that have
    nothing to do with coverage -- while still leaving the runs that DO want
    it protected, because fastloop checks the coverage group separately when
    it is asked for.
    """
    import re

    src = (REPO_ROOT / "pyplugins" / "compat" / "qemu_compat.py").read_text()
    required = set(re.findall(
        r'"(penguin_fastsnap_\w+)"',
        src.split("FASTSNAP_SYMBOLS = (")[1].split(")")[0]))
    assert required, "the required symbol list is empty; this check is inert"
    assert not [n for n in required if "_cov_" in n], sorted(required)


def test_fastloop_exempts_every_coverage_name_it_reaches_for():
    """Every coverage accessor fastloop uses must be in its API_COVERAGE group.

    THE BUG THIS CATCHES, which it was written after rather than before.
    `fastsnap_cov_hits` was added to coverage.c, to penguin-fastsnap.h, to
    qemu_compat.py and to FASTSNAP_COV_SYMBOLS -- everywhere but fastloop's
    own API_COVERAGE set. fastloop derives the names it needs from its
    bytecode and then subtracts API_OPTIONAL (which contains API_COVERAGE), so
    a coverage accessor left out of that set becomes a requirement of EVERY
    run, coverage or not. An image whose QEMU predates coverage would then be
    refused for measurements that never asked for it, which is precisely the
    failure API_COVERAGE exists to prevent.

    It went unnoticed because the symptom on a current image is nothing at
    all: the general preflight tests `dir(panda)`, and the binding was there.
    It only bites on an older QEMU -- and on the host-side fake, where it
    aborted the statemachine suite in its first group.

    Derived from the bytecode on both sides, so a name added tomorrow is
    covered without this test being edited.
    """
    import ast
    import types

    path = REPO_ROOT / "analysis" / "fastsnap" / "fastloop.py"
    if not path.exists():
        pytest.skip("analysis/fastsnap/fastloop.py is not in this checkout")

    # Exec'd the way penguin does -- into a bare module with the base class
    # stripped -- because the sets are class attributes and the name walk
    # needs real code objects, not source text. A regex over the source would
    # also match names inside comments, which is how a check like this quietly
    # becomes unfalsifiable.
    tree = ast.parse(path.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    cls.bases = []
    keep = [n for n in tree.body if isinstance(n, (ast.Import, ast.FunctionDef))]
    mod = types.ModuleType("fastloop_under_test")
    exec(compile(ast.fix_missing_locations(
        ast.Module(body=keep + [cls], type_ignores=[])),
        "fastloop_under_test", "exec"), mod.__dict__)
    FastLoop = mod.__dict__[cls.name]

    used = FastLoop._api_names_used()
    assert used, "the name walk found nothing; this check is inert"
    cov_used = {n for n in used if "_COV_" in n or "_cov_" in n}
    assert cov_used, "no coverage names found in fastloop; this check is inert"
    missing = sorted(cov_used - set(FastLoop.API_COVERAGE))
    assert not missing, (
        f"fastloop reaches for {missing} but does not list them in "
        f"API_COVERAGE, so every run -- including runs that never ask for "
        f"coverage -- now requires them")

    # And the reverse: a name listed but no longer used is a stale exemption,
    # which quietly widens what the general preflight will tolerate.
    stale = sorted(set(FastLoop.API_COVERAGE) - used)
    assert not stale, (
        f"API_COVERAGE lists {stale}, which fastloop no longer uses; a stale "
        f"exemption widens what the preflight lets through")

def test_on_lap_publisher_and_subscriber_agree_on_their_arguments():
    """fastloop publishes the lap event; snapfeed consumes it. Nothing checks
    that the two agree, and the failure mode is silent.

    plugin_manager's publish() calls `cb(*args)` with the PUBLISHER's own
    arguments and no (plugin, event) prefix. snapfeed's handler was written as
    `on_lap(self, plugin=None, event=None, *a)` -- names that describe a
    prefix that is never sent. It worked only because nothing read those two
    parameters. The moment one was read it would have held the lap index while
    claiming to hold a plugin, and the corpus built on it would have credited
    coverage to the wrong input while every counter still looked plausible.

    So this asserts the contract from BOTH files' source: every on_lap publish
    in fastloop sends exactly as many arguments as snapfeed's handler can
    accept in named positions.
    """
    import ast

    here = REPO_ROOT / "analysis" / "fastsnap"
    if not (here / "fastloop.py").exists():
        pytest.skip("analysis/fastsnap is not in this checkout")
    floop = ast.parse((here / "fastloop.py").read_text())
    sfeed = ast.parse((here / "snapfeed.py").read_text())

    published = []
    for node in ast.walk(floop):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr == "publish"):
            continue
        # plugins.publish(self, "on_lap", *args)
        if len(node.args) < 2:
            continue
        ev = node.args[1]
        if isinstance(ev, ast.Constant) and ev.value == "on_lap":
            published.append(len(node.args) - 2)

    assert published, "no on_lap publish found in fastloop.py"
    assert len(set(published)) == 1, (
        f"fastloop publishes on_lap with differing arities {sorted(set(published))}; "
        "a subscriber cannot be right for both")

    handler = next(
        (n for n in ast.walk(sfeed)
         if isinstance(n, ast.FunctionDef) and n.name == "on_lap"), None)
    assert handler is not None, "snapfeed has no on_lap handler"

    named = [a.arg for a in handler.args.args if a.arg != "self"]
    n_pub = published[0]
    assert len(named) == n_pub, (
        f"fastloop publishes {n_pub} arguments to on_lap; snapfeed names "
        f"{len(named)} ({named}). Extra published arguments land in *args and "
        f"are silently dropped; missing ones take their default and read as "
        f"'no coverage'.")
    assert named[0] == "lap" and named[1] == "closed_by", (
        f"snapfeed's on_lap names its first two parameters {named[:2]}. "
        "publish() sends no (plugin, event) prefix, so those positions are "
        "the lap index and the reason the previous lap ended.")
