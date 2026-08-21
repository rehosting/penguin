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
    assert "seq=3/3" in marker
    assert f"caller_pid={CALLER_PID}" in marker
    # Every required path was actually read, not assumed.
    for path in ("/proc/version", "/proc/mounts", "/proc/self/status"):
        assert path in fs.reads
    assert sc.retval == 0, "the guest ioctl must be given a retval"


def test_unreadable_required_path_fails_and_names_it(tmp_path, igloo_ko_isf):
    """An unreadable required path must be a loud FAIL carrying the errno."""
    fs = FakeFS(GUEST_FILES, raise_on=["/proc/mounts"])
    lp = _load(tmp_path, igloo_ko_isf, fs)
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "seq=2/3" in marker
    assert "/proc/mounts" in marker
    # The guest-side reason must survive into the marker, or the failure is
    # indistinguishable from "the plugin did not run".
    assert "ENOENT" in marker


def test_wrong_content_is_a_failure_not_a_pass(tmp_path, igloo_ko_isf):
    """A non-empty read of the wrong bytes must not count.

    The case a length-only check would miss: something answered, but it was not
    the guest's own /proc/net/tcp.
    """
    files = dict(GUEST_FILES)
    files["/proc/version"] = b"hyperfs placeholder\n"
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "seq=2/3" in marker
    assert "no b'Linux version'" in marker


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
    files["/proc/version"] = b""
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
    _trigger(lp, responses=[None, None, None])
    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "stateless=0/3" in marker
    assert "stateless=none" in marker


def test_stateless_success_is_recorded_too(tmp_path, igloo_ko_isf):
    """If the old op *does* work on a path, the marker says so.

    Recorded rather than asserted either way: this reports the comparison, it
    does not require that the old op keep failing.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, responses=[b"data", b"data", b"data"])
    assert "stateless=3/3" in _marker(tmp_path)


def test_stateless_counted_even_where_the_sequential_read_failed(
        tmp_path, igloo_ko_isf):
    """The most interesting cell of the A/B table must not be dropped.

    The first version tallied the stateless column only on paths where the
    sequential read had succeeded, so "the old op read a file the new one could
    not" was invisible in the summary -- exactly the comparison the control
    exists to surface. All four paths are readable statelessly here while one
    fails sequentially, so the counts must differ.
    """
    fs = FakeFS(GUEST_FILES, raise_on=["/proc/mounts"])
    lp = _load(tmp_path, igloo_ko_isf, fs)
    _trigger(lp, responses=[b"data", b"data", b"data"])

    marker = _marker(tmp_path)
    assert "seq=2/3" in marker
    assert "stateless=3/3" in marker, (
        "stateless was not counted on the path where seq failed")


def test_a_known_gap_does_not_fail_the_check(tmp_path, igloo_ko_isf):
    """/proc/net/tcp is unreadable on >=5.10 for a reason we cannot fix here.

    It must be reported, not asserted: a gate that can never go green trains
    people to ignore CI, and this one would stay red on every 6.13 combo.
    """
    # As on a real >=5.10 guest: the read is refused, not the file missing.
    lp = _load(tmp_path, igloo_ko_isf,
               FakeFS(GUEST_FILES, raise_on=["/proc/net/tcp"]))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "gaps_closed=0/1" in marker
    assert "/proc/net/tcp gap=open" in marker


def test_a_gap_that_starts_working_is_reported_loudly(tmp_path, igloo_ko_isf):
    """A closed gap is news: the entry must be removed on purpose, not decay.

    Without this the list would silently outlive its cause and keep excusing a
    path that works, which is how a known-issue list becomes a blind spot.
    """
    files = dict(GUEST_FILES)
    files["/proc/net/tcp"] = b"  sl  local_address rem_address\n"
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "gaps_closed=1/1" in marker
    assert "gap=CLOSED" in marker
    assert "remove from KNOWN_GAPS" in marker
