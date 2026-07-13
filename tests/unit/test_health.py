"""In-place harness coverage for the Health analysis plugin
(pyplugins/analysis/health.py), driven host-side with no PANDA/guest.

Health tallies distinct binds/execs/device-opens seen during a run and writes
the counts (health_final.yaml) plus device/process lists on teardown.
"""
from pathlib import Path

from penguin import yaml
from penguin.testing import load_pyplugin, snapshot_roundtrip

REPO_ROOT = Path(__file__).resolve().parents[2]
HEALTH = REPO_ROOT / "pyplugins" / "analysis" / "health.py"


def _load_health(tmp_path):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    return load_pyplugin(str(HEALTH), outdir=tmp_path)


def test_health_counts_distinct_events(tmp_path):
    lp = _load_health(tmp_path)
    # Two distinct execs, one repeat (deduped), one bind, one /dev open.
    lp.dispatch("exec_event", {"procname": "/bin/sh", "argv": ["sh"]})
    lp.dispatch("exec_event", {"procname": "/bin/busybox", "argv": ["busybox"]})
    lp.dispatch("exec_event", {"procname": "/bin/sh", "argv": ["sh"]})  # repeat proc
    lp.dispatch("igloo_ipv4_bind", None, 80, True)
    lp.dispatch("igloo_open", None, "/dev/mtd0", 3)
    lp.finalize()

    counts = yaml.safe_load((tmp_path / "health_final.yaml").read_text())
    assert counts["nexecs"] == 2           # /bin/sh counted once
    assert counts["nexecs_args"] == 2      # two distinct argv combos
    assert counts["nbound_sockets"] == 1
    assert counts["nuniquedevs"] == 1


def test_health_writes_device_and_proc_lists(tmp_path):
    lp = _load_health(tmp_path)
    lp.dispatch("igloo_open", None, "/dev/mtd0", 3)
    lp.dispatch("igloo_open", None, "/etc/passwd", 4)   # non-/dev, ignored
    lp.dispatch("exec_event", {"procname": "/sbin/init", "argv": ["init"]})
    lp.finalize()

    devs = (tmp_path / "health_devices_accessed.txt").read_text().split()
    procs = (tmp_path / "health_procs.txt").read_text().split()
    assert devs == ["/dev/mtd0"]           # /etc/passwd not a device
    assert procs == ["/sbin/init"]


# --------------------------------------------------------------------------- #
# Snapshot / restore
# --------------------------------------------------------------------------- #
def test_health_save_state_none_when_idle(tmp_path):
    lp = _load_health(tmp_path)
    assert lp.plugin.save_state() is None


def test_snapshot_restores_health_tallies(tmp_path):
    src = _load_health(tmp_path / "a")
    src.dispatch("exec_event", {"procname": "/bin/sh", "argv": ["sh"]})
    src.dispatch("igloo_ipv4_bind", None, 80, True)
    src.dispatch("igloo_open", None, "/dev/mtd0", 3)

    dst = _load_health(tmp_path / "b")
    snapshot_roundtrip(src, dst)

    counts = yaml.safe_load((tmp_path / "b" / "health_final.yaml").read_text())
    assert counts["nexecs"] == 1
    assert counts["nbound_sockets"] == 1
    assert counts["nuniquedevs"] == 1
    assert (tmp_path / "b" / "health_devices_accessed.txt").read_text().split() == ["/dev/mtd0"]
    # Dedup sets carried: re-execing /bin/sh after restore does not double-count.
    dst.dispatch("exec_event", {"procname": "/bin/sh", "argv": ["sh"]})
    dst.finalize()
    counts = yaml.safe_load((tmp_path / "b" / "health_final.yaml").read_text())
    assert counts["nexecs"] == 1
