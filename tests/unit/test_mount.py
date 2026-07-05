"""In-place harness coverage for the MountTracker intervention plugin
(pyplugins/interventions/mount.py), driven host-side with no PANDA/guest.

MountTracker logs mount attempts. Its syscall-return hook (post_mount) is a
portal generator (out of scope for now), but the exec-driven path — spotting
`/bin/mount -t <fs> <src> <tgt>` and logging it — is plain host logic.
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
MOUNT = REPO_ROOT / "pyplugins" / "interventions" / "mount.py"


def _mount_exec(src="/dev/sda1", tgt="/mnt", fs="ext4"):
    return {"procname": "/bin/mount", "argv": ["mount", "-t", fs, src, tgt]}


def test_mount_tracker_logs_mount_exec(tmp_path):
    lp = load_pyplugin(str(MOUNT), outdir=tmp_path)
    lp.dispatch("exec_event", _mount_exec())
    rows = (tmp_path / "mounts.csv").read_text().splitlines()
    assert rows == ["/dev/sda1,/mnt,ext4,-1"]


def test_mount_tracker_dedupes_identical_mounts(tmp_path):
    lp = load_pyplugin(str(MOUNT), outdir=tmp_path)
    lp.dispatch("exec_event", _mount_exec())
    lp.dispatch("exec_event", _mount_exec())
    rows = (tmp_path / "mounts.csv").read_text().splitlines()
    assert len(rows) == 1


def test_mount_tracker_ignores_non_mount_exec(tmp_path):
    lp = load_pyplugin(str(MOUNT), outdir=tmp_path)
    lp.dispatch("exec_event", {"procname": "/bin/ls", "argv": ["ls", "-l"]})
    assert not (tmp_path / "mounts.csv").exists()  # nothing logged
