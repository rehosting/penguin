"""Host-side tests for the vfs_read_verify integration check.

That check only runs on a booted guest, so a mistake in it costs a full CI
matrix to find -- and an inverted check would report a broken read path as
green. These drive its ioctl hook against a stubbed ``fs`` so the verdict logic
is settled before it is trusted:

* a guest serving real procfs content -> PASS
* ``/proc/net/tcp`` unreadable -> FAIL naming the path and the guest errno
* a read that succeeds with the wrong content -> FAIL, not a pass on
  "non-empty bytes" (the case that would let a hyperfs-shadowed /proc
  masquerade as the guest's own)
* ``/proc/self/status`` naming a different pid -> FAIL (the task-context check)
* a run whose guest half never fired -> FAIL, never a missing marker
* the stateless A/B column is actually recorded
"""
from pathlib import Path

from penguin.testing import RealKffi, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN = str(REPO_ROOT / "pyplugins" / "testing" / "vfs_read_verify.py")

CALLER_PID = 431

# Enough of each real file to carry the marker the check looks for.
GUEST_FILES = {
    "/proc/net/tcp": (b"  sl  local_address rem_address   st tx_queue rx_queue"
                      b" tr tm->when retrnsmt   uid  timeout inode\n"),
    "/proc/version": b"Linux version 6.13.0 (igloo) #1 SMP\n",
    "/proc/mounts": b"proc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw 0 0\n",
    "/proc/self/status": (b"Name:\tsh\nUmask:\t0022\nState:\tR (running)\n"
                          b"Tgid:\t%d\nPid:\t%d\n" % (CALLER_PID, CALLER_PID)),
    "/proc/uptime": b"113.55 98.20\n",
    "/proc/cmdline": b"console=ttyS0 igloo\n",
}


class FakeFS:
    """Stands in for plugins.fs: a generator read_file over canned content."""

    def __init__(self, files, raise_on=()):
        self.files = files
        self.raise_on = set(raise_on)
        self.reads = []

    def read_file(self, path, size=None, offset=0):
        self.reads.append(path)
        if path in self.raise_on or path not in self.files:
            raise OSError(f"vfs_open({path!r}) failed: errno 2 (ENOENT)")
        return self.files[path]
        yield  # noqa -- unreachable; makes this a generator, as the real API is


class FakeOSI:
    """Names the calling task, as the real osi does from `current`."""

    def __init__(self, pid=CALLER_PID):
        self.pid = pid

    def get_proc(self, pid=None):
        if self.pid is None:
            raise OSError("no current proc")
        return type("P", (), {"pid": self.pid, "name": "sh"})()
        yield  # noqa -- generator, as the real API is


class FakeSyscall:
    retval = None


def _load(tmp_path, isf, fs, osi=None):
    # Real ISF: the plugin issues HYPER_OP_READ_FILE for the A/B column, so the
    # op it names must be the driver's real one, not a stand-in enum.
    return load_pyplugin(PLUGIN, outdir=tmp_path, real_isf=isf,
                         doubles={"fs": fs, "osi": osi or FakeOSI(),
                                  "kffi": RealKffi([isf])})


def _marker(tmp_path):
    return (Path(tmp_path) / "vfs_read_verify.txt").read_text()


def _trigger(lp, responses=None):
    """Fire the guest's magic ioctl once.

    The only thing the handler yields directly is the stateless-op A/B read
    (fs and osi are doubles whose generators yield nothing), so `responses` is
    the stateless side of the comparison.
    """
    sc = FakeSyscall()
    lp.dispatch_syscall("ioctl", None, None, sc, 0, 0x89f7,
                        0x1000, on_return=True, responses=responses)
    return sc


def test_real_procfs_content_passes(tmp_path, igloo_ko_isf):
    fs = FakeFS(GUEST_FILES)
    lp = _load(tmp_path, igloo_ko_isf, fs)
    sc = _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "seq=4/4" in marker
    assert f"caller_pid={CALLER_PID}" in marker
    # Every required path was actually read, not assumed.
    for path in ("/proc/net/tcp", "/proc/version", "/proc/mounts",
                 "/proc/self/status"):
        assert path in fs.reads
    assert sc.retval == 0, "the guest ioctl must be given a retval"


def test_unreadable_proc_net_fails_and_names_the_path(tmp_path, igloo_ko_isf):
    """The original defect: /proc/net/tcp unreadable must be a loud FAIL."""
    fs = FakeFS(GUEST_FILES, raise_on=["/proc/net/tcp"])
    lp = _load(tmp_path, igloo_ko_isf, fs)
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "seq=3/4" in marker
    assert "/proc/net/tcp" in marker
    # The guest-side reason must survive into the marker, or the failure is
    # indistinguishable from "the plugin did not run".
    assert "ENOENT" in marker


def test_wrong_content_is_a_failure_not_a_pass(tmp_path, igloo_ko_isf):
    """A non-empty read of the wrong bytes must not count.

    The case a length-only check would miss: something answered, but it was not
    the guest's own /proc/net/tcp.
    """
    files = dict(GUEST_FILES)
    files["/proc/net/tcp"] = b"hyperfs placeholder\n"
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "seq=3/4" in marker
    assert "no b'local_address'" in marker


def test_status_from_the_wrong_task_fails(tmp_path, igloo_ko_isf):
    """/proc/self/status must name the *calling* pid.

    A read resolved in some other task's context -- or a cached blob served to
    everyone -- reads as valid procfs and would pass a marker check like
    ``Name:``. Pinning it to the caller is what makes this evidence about task
    context rather than about file content.
    """
    files = dict(GUEST_FILES)
    files["/proc/self/status"] = b"Name:\tinit\nPid:\t1\n"
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "/proc/self/status" in marker


def test_unknown_caller_falls_back_without_failing(tmp_path, igloo_ko_isf):
    """If osi cannot name the caller, that is a different failure.

    The check degrades to a plain content marker rather than reporting the
    procfs read as broken -- otherwise an unrelated osi problem would be
    misattributed to the read path.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES), osi=FakeOSI(None))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "caller_pid=unknown" in marker


def test_empty_read_is_a_failure(tmp_path, igloo_ko_isf):
    files = dict(GUEST_FILES)
    files["/proc/net/tcp"] = b""
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)
    assert "VFS_READ_VERIFY=FAIL" in _marker(tmp_path)
    assert "seq=EMPTY" in _marker(tmp_path)


def test_never_triggered_writes_a_failure_not_nothing(tmp_path, igloo_ko_isf):
    """A boot whose guest half never ran must still leave a negative verdict."""
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    lp.finalize()

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "never_triggered=yes" in marker


def test_check_runs_once_and_only_once(tmp_path, igloo_ko_isf):
    fs = FakeFS(GUEST_FILES)
    lp = _load(tmp_path, igloo_ko_isf, fs)
    _trigger(lp)
    first = list(fs.reads)
    _trigger(lp)
    _trigger(lp)
    assert fs.reads == first, "the check re-ran; the latch does not hold"
    # uninit must not overwrite a real verdict with the never-triggered one.
    lp.finalize()
    assert "VFS_READ_VERIFY=PASS" in _marker(tmp_path)


def test_stateless_ab_column_is_recorded(tmp_path, igloo_ko_isf):
    """The A/B evidence: what the old op returned, per path.

    Feeding the stateless reads nothing (as an unreadable synthetic file does)
    must show up as stateless=0/4 beside a passing seq column -- that contrast
    is the whole justification for routing /proc reads differently.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, responses=[None, None, None, None])
    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "stateless=0/4" in marker
    assert "stateless=none" in marker


def test_stateless_success_is_recorded_too(tmp_path, igloo_ko_isf):
    """If the old op *does* work on a path, the marker says so.

    Recorded rather than asserted either way: this reports the comparison, it
    does not require that the old op keep failing.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, responses=[b"data", b"data", b"data", b"data"])
    assert "stateless=4/4" in _marker(tmp_path)
