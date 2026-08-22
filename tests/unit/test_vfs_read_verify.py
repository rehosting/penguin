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
import struct
from pathlib import Path

from penguin.testing import RealKffi, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN = str(REPO_ROOT / "pyplugins" / "testing" / "vfs_read_verify.py")

CALLER_PID = 431

# Enough of each real file to carry the marker the check looks for.
GUEST_FILES = {
    "/proc/net/tcp": (b"  sl  local_address rem_address   st tx_queue rx_queue"
                      b" tr tm->when retrnsmt   uid  timeout inode\n"),
    "/proc/version": (b"Linux version 6.13.0-igloo (nix@builder) "
                      b"(gcc (GCC) 13.2.0, GNU ld 2.41) #1 SMP PREEMPT_DYNAMIC "
                      b"Thu Aug 21 00:00:00 UTC 2026\n"),
    "/proc/mounts": b"proc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw 0 0\n",
    "/proc/self/status": (b"Name:\tsh\nUmask:\t0022\nState:\tR (running)\n"
                          b"Tgid:\t%d\nPid:\t%d\n" % (CALLER_PID, CALLER_PID)),
    "/proc/uptime": b"113.55 98.20\n",
    "/proc/cmdline": b"console=ttyS0 igloo\n",
    # Not a synthetic path: the sequential op should work on an ordinary file
    # too, and had never been pointed at one.
    "/igloo/utils/send_syscall": b"\x7fELF\x01\x01\x01" + b"\0" * 57,
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
        data = self.files[path]
        return data[:size] if size is not None else data
        yield  # noqa -- unreachable; makes this a generator, as the real API is

    # The size-cap check calls this directly: a cap that is quietly advisory is
    # exactly the kind of thing routing through read_file would hide.
    read_file_seq = read_file


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


class _KFFI(RealKffi):
    """Real dwarffi kffi plus the two calls the plugin makes on it."""

    def sizeof(self, type_name):
        return self.ffi.sizeof(type_name)

    def from_buffer(self, type_name, buf, instance_offset_in_buffer=0):
        return self.ffi.from_buffer(type_name, bytearray(buf),
                                    offset=instance_offset_in_buffer)


class FakePortal:
    regions_size = 4072


def _open_res(error=0, handle=7, fs_magic=0x9fa0):
    """struct vfs_open_result { int32 error; uint32 handle; uint64 fs_magic; }"""
    return struct.pack("<iIQ", error, handle, fs_magic)


def _read_res(payload=b"", error=0, eof=0):
    """struct vfs_read_result { int32 error; uint32 nbytes; uint8 eof; pad[7]; }"""
    return struct.pack("<iIB7x", error, len(payload), eof) + payload


def _close_res(error=0):
    return struct.pack("<iI", error, 0)


# The window is chosen from the largest readable required path, which in these
# fixtures is /proc/version. Kept explicit so a fixture change that shifts the
# winner shows up as a test failure rather than as silently weaker coverage.
VERSION = GUEST_FILES["/proc/version"]
assert len(VERSION) > max(
    len(GUEST_FILES["/proc/mounts"]),
    len(GUEST_FILES["/proc/self/status"])), (
    "the windowed check aims at the largest required file; keep it /proc/version")


def _windowed_ok(window=None, data=VERSION):
    """Driver responses for a healthy windowed read: open, chunks, EOF, close.

    Mirrors what the driver really does -- a short read is NOT EOF; EOF is a
    separate zero-byte read -- so a plugin that treats a short read as the end
    fails here rather than in CI.
    """
    if window is None:
        window = max(1, min(64, len(data) // 4))   # mirrors _pick_window
    out = [_open_res()]
    for i in range(0, len(data), window):
        out.append(_read_res(data[i:i + window]))
    out.append(_read_res(b"", eof=1))
    out.append(_close_res())
    return out


EBADF, EISDIR, ENFILE = 9, 21, 23
SLOTS = 16          # must match VFS_SLOTS in the driver
OVERSHOOT = 4       # how many opens past the table the check makes


def _bad_handle_responses(read_after_close=-EBADF, unissued=-EBADF,
                          zero=-EBADF, double_close=-EBADF):
    """Driver responses for _check_bad_handles, in the order it issues them.

    Defaults are a healthy driver. Each errno is a parameter so a test can
    single out one regression -- notably read-after-close answering EINVAL,
    which is what the driver used to do and which made a handle-table failure
    indistinguishable from the kernel refusing the file.
    """
    return [_open_res(handle=7), _close_res(0), _read_res(error=read_after_close),
            _close_res(error=double_close), _read_res(error=unissued),
            _read_res(error=zero)]


def _handle_table_responses(opens=SLOTS + OVERSHOOT, reclaimed=None,
                            open_fails_at=None):
    """Driver responses for _check_handle_table.

    `reclaimed` is the set of 0-based OPEN indices whose later read reports
    EBADF, i.e. the slots the driver chose to reclaim; the default is the oldest
    OVERSHOOT, which is the documented policy. `open_fails_at` makes that open
    fail with ENFILE, modelling a table that wedges on a leak instead of
    reclaiming -- the failure mode that would make one leaked handle break every
    later read in the run.
    """
    if reclaimed is None:
        reclaimed = set(range(OVERSHOOT))
    out = []
    n = opens if open_fails_at is None else open_fails_at + 1
    for i in range(n):
        if i == open_fails_at:
            out.append(_open_res(error=-ENFILE, handle=0))
            return out
        out.append(_open_res(handle=i + 1))
    for i in range(opens):
        out.append(_read_res(error=-EBADF) if i in reclaimed
                   else _read_res(b"x" * 16))
    out += [_close_res(0)] * (opens - len(reclaimed))
    return out


def _directory_responses(read=_read_res(error=-EISDIR)):
    return [_open_res(handle=99), read, _close_res(0)]


def _handle_checks_ok():
    """A healthy driver's answers to all of the handle-table checks."""
    return (_bad_handle_responses() + _handle_table_responses()
            + _directory_responses())


def _load(tmp_path, isf, fs, osi=None):
    # Real ISF: the plugin issues raw vfs_*/READ_FILE PortalCmds and decodes the
    # driver's result structs, so both the ops and the layouts must be the real
    # ones rather than stand-ins.
    return load_pyplugin(PLUGIN, outdir=tmp_path, real_isf=isf,
                         doubles={"fs": fs, "osi": osi or FakeOSI(),
                                  "portal": FakePortal(),
                                  "kffi": _KFFI([isf])})


def _drive_collect(lp, windowed, sc):
    """Fire the ioctl and return (results, yielded PortalCmds).

    Needed where a test asserts on WHICH ops were issued -- that a handle was
    closed on the error path, for instance -- rather than on the marker text.
    """
    from penguin.testing import drive
    hooks = [h for h in lp.manager.syscall_hooks if h["name"] == "ioctl"]
    assert hooks, "no ioctl hook registered"
    gen = hooks[0]["handler"](None, None, sc, 0, 0x89f7, 0x1000)
    # Three stateless required-path reads precede the windowed sequence.
    return drive(gen, [None] * 3 + list(windowed) + [None] * 8, collect=True)


def _marker(tmp_path):
    return (Path(tmp_path) / "vfs_read_verify.txt").read_text()


def _trigger(lp, responses=None, windowed=None, stateless=None,
             handles=None):
    """Fire the guest's magic ioctl once.

    The handler yields raw PortalCmds in a fixed order -- the windowed
    open/read.../close first, then one stateless read per required path -- and
    `responses` is fed to them in that order. `windowed`/`stateless` build that
    list so a test states its intent instead of a bare sequence of blobs.
    """
    if responses is None:
        responses = (list(stateless if stateless is not None else [None] * 3)
                     + (windowed if windowed is not None else _windowed_ok())
                     + list(handles if handles is not None else []))
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
    _trigger(lp, stateless=[None, None, None])
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
    _trigger(lp, stateless=[b"data", b"data", b"data"])
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
    _trigger(lp, stateless=[b"data", b"data", b"data"])

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
    assert "gaps_closed=0/3" in marker
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
    assert "gaps_closed=1/3" in marker
    assert "gap=CLOSED" in marker
    assert "remove from KNOWN_GAPS" in marker


# --------------------------------------------------------------------------- #
# The sequential contract. These are the cases the earlier check could not see:
# every file it read fit in one chunk, so nothing ever proved that a second read
# of the same handle continues the file rather than restarting it.
# --------------------------------------------------------------------------- #

def test_windowed_read_reassembles_the_file(tmp_path, igloo_ko_isf):
    """Several small reads of one handle must equal one big read."""
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "contract=ok" in marker
    # /proc/version is 36B here, so 64B windows give one data read plus EOF...
    assert "sequential_contract=OK" in marker


def test_single_read_does_not_count_as_sequential(tmp_path, igloo_ko_isf):
    """A file served in one read proves nothing about f_pos advancing.

    This is precisely the hole in the first version of this check: everything it
    read came back in a single chunk, so the driver could have ignored f_pos
    entirely and the check would still have passed.
    """
    one_read = [_open_res(), _read_res(VERSION), _read_res(b"", eof=1),
                _close_res()]
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES),)
    _trigger(lp, windowed=one_read)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "the multi-read path never ran" in marker


def test_regenerated_content_is_caught(tmp_path, igloo_ko_isf):
    """A driver that restarts the file per read must fail.

    The failure mode a length check cannot see: each read returns the file's
    opening bytes again, so the result is the right *shape* and the wrong data.
    Detected by requiring the opening bytes to appear exactly once.
    """
    # A full window's worth, so the repetition is visible to the check's
    # 32-byte head comparison rather than straddling the boundary.
    head = VERSION[:64]
    regenerated = [_open_res(), _read_res(head), _read_res(head),
                   _read_res(b"", eof=1), _close_res()]
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, windowed=regenerated)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "re-generated per read" in marker


def test_windowed_result_must_match_the_one_shot_read(tmp_path, igloo_ko_isf):
    """Truncation or reordering across reads must fail, not just be smaller."""
    truncated = [_open_res(), _read_res(VERSION[:16]), _read_res(VERSION[20:]),
                 _read_res(b"", eof=1), _close_res()]
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, windowed=truncated)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "!= one-shot" in marker


def test_missing_eof_is_a_failure(tmp_path, igloo_ko_isf):
    """A short read is not EOF; the driver has to say so explicitly.

    Without this, a driver that never reports EOF would look fine to any caller
    that stops on a short read -- and would loop forever for one that does not.
    """
    no_eof = [_open_res(), _read_res(VERSION[:20]), _read_res(VERSION[20:]),
              _read_res(b"")]  # zero bytes, eof flag NOT set
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, windowed=no_eof + [_close_res()])

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "never reported EOF" in marker


def test_mid_read_errno_is_reported_with_progress(tmp_path, igloo_ko_isf):
    """A failure part-way through must say how far it got, not just fail."""
    import errno as E
    partial = [_open_res(), _read_res(VERSION[:20]),
               _read_res(b"", error=-E.EIO), _close_res()]
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, windowed=partial)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert f"errno {E.EIO}" in marker
    assert "after 20B" in marker


def test_handle_is_closed_even_when_the_read_fails(tmp_path, igloo_ko_isf):
    """The 16-slot table must not leak a handle on the error path.

    A leak forces the driver to reclaim the oldest slot, which breaks an
    unrelated reader -- a failure that would surface far from its cause.
    """
    import errno as E
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    sc = FakeSyscall()
    _, yielded = _drive_collect(
        lp, [_open_res(), _read_res(b"", error=-E.EIO), _close_res()], sc)
    ops = [c.op for c in yielded if hasattr(c, "op")]
    import hyper.consts as consts
    assert consts.HYPER_OP.HYPER_OP_VFS_CLOSE in ops, (
        "no vfs_close was issued after a failed read; the handle leaked")


def test_bad_handle_reports_ebadf_not_a_silent_empty(tmp_path, igloo_ko_isf):
    """vfs_open refusing must not be reported as an empty file.

    EBADF rather than EINVAL is the point of igloo_driver #102: EINVAL is also
    what kernel_read returns for a file it will not serve, so the two were
    indistinguishable and the failure could not be attributed.
    """
    import errno as E
    refused = [_open_res(error=-E.EBADF, handle=0)]
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, windowed=refused)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert f"errno {E.EBADF}" in marker


def test_size_cap_must_not_be_advisory(tmp_path, igloo_ko_isf):
    class Overrun(FakeFS):
        def read_file_seq(self, path, size=None, offset=0):
            return self.files[path]          # ignores `size`
            yield  # noqa

    lp = _load(tmp_path, igloo_ko_isf, Overrun(GUEST_FILES))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "size_cap=FAIL" in marker


def test_probes_record_chunk_size_and_multichunk_reach(tmp_path, igloo_ko_isf):
    """The probe sweep must say whether anything exceeded one portal chunk.

    Without that line the marker cannot distinguish "multi-chunk works" from
    "nothing we read was big enough to need it" -- which is the confusion this
    whole round of work came out of.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "chunk_bytes=" in marker
    assert "multichunk_seen=" in marker
    # Every probe path is absent from GUEST_FILES, so each is reported, not skipped.
    assert "probe /proc/zoneinfo" in marker
    assert "probe /sys/kernel/debug" in marker     # the debugfs question
    # hyperfs and kallsyms are tracked as KNOWN_GAPS rather than probes now:
    # both have a measured mechanism, so they belong where the canary watches
    # them instead of in the open-question sweep.
    assert "/proc/large_file gap=" in marker


def test_a_big_probe_is_flagged_as_multichunk(tmp_path, igloo_ko_isf):
    files = dict(GUEST_FILES)
    files["/proc/zoneinfo"] = b"z" * 9000
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "MULTI-CHUNK" in marker
    assert "multichunk_seen=yes" in marker


# --------------------------------------------------------------------------- #
# Kernel-aware gaps. __kernel_read's refusal only exists from ~5.10, and the
# live run confirmed every gap reads fine on 4.10 -- so a version-blind canary
# would shout "gap closed!" on every 4.10 job, which is how a warning turns into
# noise and then gets ignored.
# --------------------------------------------------------------------------- #

OLD_KERNEL = dict(GUEST_FILES)
OLD_KERNEL["/proc/version"] = (b"Linux version 4.10.0-igloo (nix@builder) "
                               b"(gcc (GCC) 9.5.0) #1 SMP Thu Aug 21 2026\n")


def test_a_gap_readable_below_its_min_kernel_is_not_news(tmp_path, igloo_ko_isf):
    files = dict(OLD_KERNEL)
    files["/proc/net/tcp"] = b"  sl  local_address rem_address\n"
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "kernel=4.10" in marker
    assert "gap=n/a on 4.10" in marker
    assert "gap=CLOSED" not in marker, (
        "a gap reading on a kernel below its threshold was reported as news")
    # And it must not inflate the denominator either: nothing was expected to
    # fail here, so 0 gaps applied.
    assert "gaps_closed=0/0" in marker


def test_the_same_gap_is_news_on_a_new_kernel(tmp_path, igloo_ko_isf):
    """Same data, newer kernel -> now it is a real finding."""
    files = dict(GUEST_FILES)          # 6.13 in /proc/version
    files["/proc/net/tcp"] = b"  sl  local_address rem_address\n"
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "gap=CLOSED on 6.13" in marker
    assert "remove from KNOWN_GAPS" in marker


def test_unreadable_version_applies_every_gap(tmp_path, igloo_ko_isf):
    """If the kernel cannot be identified, do not silently skip the gaps.

    Reporting a gap that might not apply is recoverable; quietly dropping one
    because a read failed is how coverage disappears without anyone noticing.
    """
    files = dict(GUEST_FILES)
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files, raise_on=["/proc/version"]))
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "kernel=unknown" in marker
    assert "gap=n/a" not in marker


def test_probe_reads_are_capped(tmp_path, igloo_ko_isf):
    """A 4 MB informational read is ~1000 portal round trips; cap it.

    Uncapped, /proc/kallsyms alone did that on every 4.10 job. The cap must stay
    above a chunk so MULTI-CHUNK is still detectable, and a capped read must be
    labelled so nobody reads the number as the file's real size.
    """
    files = dict(GUEST_FILES)
    files["/proc/zoneinfo"] = b"z" * 5_000_000
    fs = FakeFS(files)
    lp = _load(tmp_path, igloo_ko_isf, fs)
    _trigger(lp)

    marker = _marker(tmp_path)
    assert "probe_cap=16384" in marker
    assert "OK(>=16384B) MULTI-CHUNK" in marker
    assert "5000000" not in marker, "the probe read was not capped"


# --------------------------------------------------------------------------- #
# Handle-table checks
#
# These cover the part of the driver that is not about file contents at all:
# what happens to a handle that was closed, never issued, or evicted because
# the host leaked all 16 slots. None of it had ever run on a guest, and none of
# it can be reached through read_file_seq, which never exposes a handle.
# --------------------------------------------------------------------------- #
def test_handle_checks_pass_on_a_healthy_driver(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, handles=_handle_checks_ok())

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=PASS" in marker
    assert "handle_checks=4/4" in marker
    assert "bad_handles=OK" in marker
    assert "handle_table=OK" in marker
    assert "directory=OK" in marker
    assert "regular_file=OK" in marker


def test_read_after_close_answering_einval_fails(tmp_path, igloo_ko_isf):
    """The EBADF/EINVAL distinction is load-bearing, so assert it.

    EINVAL is what __kernel_read returns for a file it will not serve, so a
    driver that also uses it for a bad handle makes those two indistinguishable
    on a live guest -- which is exactly the ambiguity that cost a debugging pass
    on /proc/self/status. Reverting that must fail here, not in a person's head.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, handles=(_bad_handle_responses(read_after_close=-22)
                          + _handle_table_responses() + _directory_responses()))

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "bad_handles=FAIL" in marker
    assert "want EBADF" in marker


def test_unissued_handle_that_reads_successfully_fails(tmp_path, igloo_ko_isf):
    """A handle we never issued must not read anything.

    Same slot, wrong generation: if the generation check were dropped this
    returns another file's bytes with no error at all, which is the worst shape
    of bug in the whole bridge.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, handles=(_bad_handle_responses(unissued=0)
                          + _handle_table_responses() + _directory_responses()))

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "unissued handle" in marker


def test_a_wedged_handle_table_fails(tmp_path, igloo_ko_isf):
    """Leaking every slot must cost one reader an EBADF, not break the portal.

    A driver that refuses the 17th open instead of reclaiming turns a single
    leaked handle into "penguin can no longer read any file for the rest of the
    run" -- so this asserts the open SUCCEEDS, which reads backwards until you
    remember the failure it prevents.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, handles=(_bad_handle_responses()
                          + _handle_table_responses(open_fails_at=SLOTS)
                          + _directory_responses()))

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "handle_table=FAIL" in marker
    assert "wedges" in marker


def test_reclaiming_a_recent_handle_instead_of_the_oldest_fails(
        tmp_path, igloo_ko_isf):
    """Reclaim has to take the oldest, or a long read loses to a short one.

    Evicting recent handles is not merely unfair: the newest handle is the one
    most likely to have a read in flight, and reclaiming that is a use-after-free
    on the struct file it is reading from.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, handles=(
        _bad_handle_responses()
        + _handle_table_responses(reclaimed={4, 5, 6, 7})
        + _directory_responses()))

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "oldest" in marker


def test_a_directory_reading_as_empty_fails(tmp_path, igloo_ko_isf):
    """Opening a directory succeeds, so a silent empty read is the danger.

    A caller that read /proc as b"" would conclude there are no processes. The
    errno rework exists to make that impossible, and this is the check that
    proves it on a guest instead of by inspection.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, handles=(
        _bad_handle_responses() + _handle_table_responses()
        + _directory_responses(read=_read_res(b"", error=0, eof=1))))

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "directory=FAIL" in marker
    assert "indistinguishable from an empty file" in marker


def test_regular_file_wrong_content_fails(tmp_path, igloo_ko_isf):
    """The sequential op on an ordinary file must return that file's bytes."""
    files = dict(GUEST_FILES)
    files["/igloo/utils/send_syscall"] = b"#!/bin/sh\n"
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(files))
    _trigger(lp, handles=_handle_checks_ok())

    marker = _marker(tmp_path)
    assert "VFS_READ_VERIFY=FAIL" in marker
    assert "regular_file=FAIL" in marker


def test_no_portal_response_is_not_a_pass_and_not_a_wedged_table(
        tmp_path, igloo_ko_isf):
    """A portal that answers nothing must read as unexercised, not as either.

    Reported as a pass it would hide a dead portal; reported as a failure it
    would blame the handle table for a plumbing problem. n/a is the only honest
    verdict, and it must not count toward handle_checks.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp)   # no handle responses at all

    marker = _marker(tmp_path)
    assert "handle_table=n/a" in marker
    assert "bad_handles=n/a" in marker
    assert "handle_checks=1/4" in marker, \
        "only regular_file runs without the portal; n/a must not be counted"
    # and the run does not fail on account of the unexercised checks
    assert "VFS_READ_VERIFY=PASS" in marker


def test_the_unexercised_blocking_open_is_stated(tmp_path, igloo_ko_isf):
    """No silent gaps: what the check cannot prove has to say so.

    O_NONBLOCK cannot be demonstrated here -- showing it needs a file that
    blocks forever, and reading one against a driver that lacks the fix hangs
    the run rather than failing it, producing no marker at all. That is a real
    hole in the coverage, so it is written into every marker instead of being
    absent from it.
    """
    lp = _load(tmp_path, igloo_ko_isf, FakeFS(GUEST_FILES))
    _trigger(lp, handles=_handle_checks_ok())
    assert "blocking_open=unexercised" in _marker(tmp_path)
