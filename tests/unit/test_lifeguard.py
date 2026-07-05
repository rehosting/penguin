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


def _load(tmp_path, blocked):
    return load_pyplugin(str(LIFEGUARD), outdir=tmp_path,
                         args={"conf": {"blocked_signals": blocked}})


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
