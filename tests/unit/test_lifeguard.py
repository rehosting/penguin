"""In-place harness coverage for the Lifeguard intervention plugin
(pyplugins/interventions/lifeguard.py), driven host-side with no PANDA/guest.

The signal-send syscall handler is a portal generator (out of scope), but the
config-time signal classification, the delivery-drop path, and the CSV writer
are plain host logic. SIGKILL(9)/SIGSTOP(19) can only be suppressed at
syscall-send time, so they must land in syscall_blocked but NOT delivery_blocked.
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
LIFEGUARD = REPO_ROOT / "pyplugins" / "interventions" / "lifeguard.py"


def _load(tmp_path, blocked, doubles=None):
    return load_pyplugin(str(LIFEGUARD), outdir=tmp_path,
                         args={"conf": {"blocked_signals": blocked}},
                         doubles=doubles)


class _Deliver:
    def __init__(self, sig, pid=123, comm="httpd"):
        self.sig, self.pid, self.comm = sig, pid, comm
        self.drop = False


def test_classifies_syscall_only_vs_delivery_signals(tmp_path):
    # 9=SIGKILL (syscall-only), 15=SIGTERM, 11=SIGSEGV (delivery-capable).
    lp = _load(tmp_path, [9, 15, 11])
    assert lp.plugin.syscall_blocked_signals == {9, 15, 11}
    assert lp.plugin.delivery_blocked_signals == {15, 11}  # 9 dropped: syscall-only
    # CSV is created with a header row.
    assert (tmp_path / "lifeguard.csv").read_text().splitlines()[0] == \
        "signal,target_process,blocked,mechanism"


def test_delivery_hook_drops_and_logs_configured_signal(tmp_path):
    lp = _load(tmp_path, [15])
    ev = _Deliver(sig=15)
    lp.dispatch("signal_deliver", None, ev)
    assert ev.drop is True
    rows = (tmp_path / "lifeguard.csv").read_text().splitlines()
    assert rows[-1] == "15,123,1,delivery"


def test_delivery_hook_ignores_unconfigured_signal(tmp_path):
    lp = _load(tmp_path, [15])
    ev = _Deliver(sig=2)  # SIGINT not blocked
    lp.dispatch("signal_deliver", None, ev)
    assert ev.drop is False
    # Nothing beyond the header row was written.
    assert len((tmp_path / "lifeguard.csv").read_text().splitlines()) == 1


def test_no_delivery_subscription_when_only_syscall_only_signals(tmp_path):
    lp = _load(tmp_path, [9])  # SIGKILL only -> no delivery hook path
    assert lp.plugin.delivery_blocked_signals == set()
    assert not any(ev == "signal_deliver" for (_p, ev, _c) in lp.subscriptions)


# --- signal-send syscall interception, driven through the harness pump --------

class _Proto:
    def __init__(self, name, vals):
        self.name = name
        self._vals = vals

    def arg_value(self, args, *names, fallback_index=None):
        for n in names:
            if n in self._vals:
                return self._vals[n]
        return None


class _OSI:
    def get_proc(self):
        yield from ()
        return type("P", (), {"pid": 100})()

    def get_proc_name(self, target=None):
        yield from ()
        return "victim" if target else "attacker"


class _SC:
    def __init__(self):
        self.skip_syscall = False
        self.retval = None


def test_kill_syscall_blocks_configured_signal(tmp_path):
    lp = _load(tmp_path, [15], doubles={"osi": _OSI()})
    sc = _SC()
    proto = _Proto("sys_kill", {"sig": 15, "pid": 100})
    lp.dispatch_syscall("kill", None, proto, sc, on_return=False)
    assert sc.skip_syscall is True and sc.retval == 0
    assert (tmp_path / "lifeguard.csv").read_text().splitlines()[-1] == \
        "15,100,1,syscall:kill"


def test_kill_syscall_passes_through_unblocked_signal(tmp_path):
    lp = _load(tmp_path, [15], doubles={"osi": _OSI()})
    sc = _SC()
    proto = _Proto("sys_kill", {"sig": 2, "pid": 100})  # SIGINT not blocked
    lp.dispatch_syscall("kill", None, proto, sc, on_return=False)
    assert sc.skip_syscall is False
    assert (tmp_path / "lifeguard.csv").read_text().splitlines()[-1] == \
        "2,100,0,syscall:kill"


def test_sigkill_is_blocked_at_syscall_level(tmp_path):
    # SIGKILL can't be caught, so the only place to suppress it is the send syscall.
    lp = _load(tmp_path, [9], doubles={"osi": _OSI()})
    sc = _SC()
    proto = _Proto("sys_kill", {"sig": 9, "pid": 100})
    lp.dispatch_syscall("kill", None, proto, sc, on_return=False)
    assert sc.skip_syscall is True and sc.retval == 0
