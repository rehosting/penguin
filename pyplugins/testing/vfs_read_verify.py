"""Integration check: the host can actually read the guest's synthetic filesystems.

``plugins.fs.read_file_seq`` -- and the automatic routing of ``/proc``, ``/sys``
and debugfs inside ``read_file`` -- is covered host-side by tests that pack the
igloo_driver structs and decode them through the real ISF. Those prove the ABI;
they stub the transport, so they say nothing about whether a *booted* guest
hands back procfs content. Every consumer of the process and peer model depends
on that, so it gets checked live on every arch/kernel combo in CI.

Triggered by the guest
----------------------

A guest script issues a magic ``ioctl`` and the check runs in that syscall's
return hook. Deliberately not a timer or an all-syscalls tick: the reads then
happen in a known userspace task context, which is what makes ``/proc/self``
meaningful, they happen exactly once, and they cost nothing for the rest of the
boot (an ``on_all`` hook would slow every syscall in the merged suite).

What this asserts
-----------------

Content, not just a non-empty buffer -- a read that returns the wrong file, or
a truncated first chunk, has to fail. The strongest of these is
``/proc/self/status``: it must report the **pid of the process that made the
ioctl**, which only the guest's own per-task procfs can produce. A cached blob,
a penguin-modelled pseudofile, or a read resolved in the wrong task context all
fail that.

The A/B control
---------------

Each required path is *also* read through the old stateless op
(``HYPER_OP_READ_FILE``, issued directly here to bypass ``read_file``'s
routing). That comparison is the evidence for the change rather than an
assumption about it: the marker records ``seq=N/M stateless=K/M``, so every run
states whether the sequential path reads files the stateless one cannot. If
both columns fill, the routing is unnecessary; if ``seq`` fills and
``stateless`` does not, it is load-bearing.

It also answers the open diagnostic question -- whether the old op failed at
``filp_open`` (a lookup/permission bug that would matter for regular files too)
or read fine and returned nothing (the stateless-vs-synthetic mismatch).
``vfs_open`` succeeding on the same path in the same boot is what separates
those two.

Writes ``vfs_read_verify.txt``; the ``verifier`` fixture asserts
``VFS_READ_VERIFY=PASS``.
"""
from os.path import join

from penguin import Plugin, plugins
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd

kffi = plugins.kffi

# Magic ioctl the guest script issues to trigger the check. 0x89f1/f3/f5 are
# already taken by other integration tests.
TRIGGER_IOCTL = 0x89f7

# (path, marker that only the real file's content contains).
#
# All real-kernel procfs, never a penguin-modelled pseudofile: a hyperfs-backed
# /proc entry is served by penguin itself and would pass without the guest's own
# procfs ever being touched. Each of these is generated at open time and reports
# st_size 0 -- exactly the case the stateless op cannot serve.
REQUIRED = [
    ("/proc/version", b"Linux version"),
    # Several seq_file records long, so a read that stops after the first chunk
    # shows up here rather than passing.
    ("/proc/mounts", b"proc"),
]

# Read and reported, never asserted: real sysfs layout varies across the kernel
# configs in CI, so a miss is information rather than a verdict. The marker
# still carries it, so a regression stays visible.
OPTIONAL = [
    "/proc/uptime",
    "/proc/cmdline",
    "/sys/kernel/uevent_seqnum",
]

# Paths the driver provably CANNOT read on some kernels, with the reason. Read
# and reported, never asserted -- a gate that can never go green trains people
# to ignore CI, and this one would stay red on every 6.13 combo forever.
#
# Each entry earns its place by having a known mechanism, not by being
# inconvenient. If a gap starts working, the check says so loudly (see the
# canary below) so the list shrinks instead of quietly outliving its cause.
# Each entry is (min_kernel, reason). min_kernel matters: __kernel_read's
# refusal only exists from ~5.10, and MEASURED CONFIRMS IT -- every one of these
# reads fine on 4.10 and fails on 6.13. Without the version condition the canary
# would fire "gap closed!" on every 4.10 run, which is how a warning becomes
# noise and then gets ignored.
KNOWN_GAPS = {
    "/proc/net/tcp": (
        (5, 10),
        "/proc/net/* register proc_read = seq_read, so the inode gets "
        "proc_reg_file_ops (.read, no .read_iter) and __kernel_read refuses it "
        "(warn_unsupported -> EINVAL) for both portal read ops. Not fixable "
        "module-side: proc_reg_read forwards to a proc_ops a module cannot "
        "inspect, so private_data cannot be proven to be a seq_file (in "
        "/proc/<pid>/mem it is an mm_struct). Consumers should read socket state "
        "from the kernel via the OSI fd walk instead of from procfs."),
    # Measured 2026-08-21: reads (8192B, multi-chunk) on 4.10, EINVAL on 6.13.
    # This is the widest of the gaps -- it means penguin cannot read its OWN
    # modelled pseudofiles from the host on a modern kernel.
    "/proc/large_file": (
        (5, 10),
        "a penguin-MODELLED pseudofile, so its f_op comes from the HOST: "
        "hyperfile/procfs.py builds igloo_proc_ops from whichever methods the "
        "model overrides, and handle_op_procfs_create_file installs them. A "
        "model that defines read() therefore produces .read with no .read_iter, "
        "which is the class __kernel_read refuses -- and the seq_read_iter "
        "fallback does not help, since it keys on ->read == seq_read. (An "
        "earlier version of this note blamed hyperfs_file_operations. That is "
        "the wrong file: hyperfs backs the passthrough tree, not procfs "
        "models.) Fixable per model rather than in the driver: igloo_proc_ops "
        "already carries read_iter and the driver already wires it to "
        "proc_read_iter/.read_iter, so a model implementing ONLY read_iter is "
        "readable from the guest (via new_sync_read) AND from the host. Only -- "
        "__kernel_read refuses any file with .read set, whatever else it has."),
    # Same class, reached a different way: proc_ops.proc_read = seq_read.
    "/proc/kallsyms": (
        (5, 10),
        "proc_reg_file_ops via proc_ops.proc_read = seq_read -- same refusal as "
        "/proc/net/*. Notable because it is 4 MB and reads fine on 4.10, so it "
        "is the only file here that proves the multi-chunk path at scale."),
}

# The windowed-read check: open one file and read it in deliberately small
# windows. This is how the sequential contract gets proven without depending on
# finding a file bigger than a portal chunk (~4 KB) on a minimal emulated guest.
# Every file the earlier version of this check read fit in ONE chunk -- the
# largest was 453 bytes -- so the loop, the driver's f_pos writeback, EOF across
# calls and handle lifetime over a long read, i.e. the entire reason the
# sequential op exists, had never actually run on a guest.
# The path and window are chosen from what the run actually measured, not fixed
# in advance. Hardcoding /proc/version with a 64-byte window failed on mips64
# 4.10 for a silly reason: /proc/version there is EXACTLY 64 bytes, so the file
# arrived in one read and the check reported the driver as broken. The window is
# now derived from the file's real size, so there are always several data reads.
MIN_WINDOW_READS = 4
MAX_WINDOW_BYTES = 64

# Read for information only. Sizes are recorded so we learn what is actually
# available on these guests -- in particular whether anything here exceeds a
# portal chunk, which is what would let the multi-chunk case become a hard
# requirement instead of a windowed stand-in.
PROBES = [
    # proc_create_seq -> proc_read_iter, so readable; usually the largest
    # readable procfs files on a small guest.
    "/proc/zoneinfo",
    "/proc/vmstat",
    "/proc/interrupts",
    "/proc/meminfo",
    # kernfs with real content, rather than the 4-byte counter the first version
    # of this check called "sysfs coverage".
    "/sys/kernel/vmcoreinfo",
    "/sys/devices/system/cpu/online",
    "/sys/class/net/lo/mtu",
    # debugfs: routed by _SYNTHETIC_PREFIXES but never exercised. If it is not
    # even mounted here, that is worth knowing -- an unexercised route is not a
    # working one.
    "/sys/kernel/debug",
    "/sys/kernel/debug/sched/debug",
    # /proc/large_file (a modelled pseudofile) and /proc/kallsyms moved to
    # KNOWN_GAPS: both are
    # now measured facts with a mechanism, not open questions, so they belong
    # where the canary watches them.
]

# Probe reads are capped. Uncapped, /proc/kallsyms alone pulled 4,202,759 bytes
# on 4.10 -- about 1037 portal round trips for one informational line. The cap is
# still comfortably over a chunk, so it can prove MULTI-CHUNK; sizes at or above
# it are reported as ">=" rather than as the file's real length.
PROBE_CAP = 16384

# An ordinary file present on every target, used to point the sequential op at
# something that is not a synthetic filesystem. /igloo/utils is injected by
# penguin itself, so it exists regardless of what the firmware ships.
REGULAR_FILE = "/igloo/utils/send_syscall"

MARKER = "vfs_read_verify.txt"


class VfsReadVerify(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.done = False
        self._reported = False

        @plugins.syscalls.syscall("on_sys_ioctl_return",
                                  arg_filters=[None, TRIGGER_IOCTL])
        def _triggered(regs, proto, syscall, fd, op, arg):
            if self.done:
                return
            self.done = True   # latch before yielding: one run, no reentry
            try:
                yield from self._verify()
            except Exception as e:
                # A crash must still produce a verdict. `done` is already
                # latched, so without this the marker would simply be absent
                # and the failure would read as unrelated plumbing.
                self.logger.error(f"vfs_read_verify: check raised: {e!r}")
                self._write(f"VFS_READ_VERIFY=FAIL raised={type(e).__name__}",
                            [], [repr(e)])
            syscall.retval = 0

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def _read_seq(self, path, size=None):
        """Read via the sequential path; return ``(bytes, error-string)``."""
        try:
            data = yield from plugins.fs.read_file(path, size=size)
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"
        return data, None

    def _read_stateless(self, path):
        """Read via the old offset+size op, bypassing read_file's routing.

        Issued as a raw PortalCmd on purpose: read_file now sends every
        synthetic path down the sequential route, so going through it could not
        exercise the op this is comparing against.
        """
        name = path.encode("latin-1")[:255] + b"\0"
        try:
            data = yield PortalCmd(hop.HYPER_OP_READ_FILE, 0, 4096, None, name)
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"
        return data, None

    # ------------------------------------------------------------------ #
    # The check
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # Raw handle primitives
    #
    # The checks below are about the HANDLE TABLE rather than about file
    # contents, so they need open/read/close separately instead of as one read.
    # read_file_seq deliberately never hands a handle to a caller, which is
    # right for the API and useless for testing what happens to a handle after
    # it is closed, reclaimed, or never existed.
    # ------------------------------------------------------------------ #
    def _vfs_open(self, path):
        """Return ``(handle, errno, fs_magic)``; handle is 0 on failure."""
        name = path.encode("latin-1")[:255] + b"\0"
        raw = yield PortalCmd(hop.HYPER_OP_VFS_OPEN, 0, 0, None, name)
        if not raw:
            return 0, None, 0
        res = kffi.from_buffer("vfs_open_result", raw)
        return int(res.handle), -int(res.error), int(res.fs_magic)

    def _vfs_read(self, handle, want):
        """Return ``(data, errno, eof)``. errno is 0 on success."""
        raw = yield PortalCmd(hop.HYPER_OP_VFS_READ, handle, want, None)
        if not raw:
            return None, None, False
        hdr = kffi.sizeof("vfs_read_result")
        r = kffi.from_buffer("vfs_read_result", raw)
        n = int(r.nbytes)
        return bytes(raw[hdr:hdr + n]), -int(r.error), bool(r.eof)

    def _vfs_close(self, handle):
        raw = yield PortalCmd(hop.HYPER_OP_VFS_CLOSE, handle, 0, None)
        if not raw:
            return None
        return -int(kffi.from_buffer("vfs_close_result", raw).error)

    def _read_windowed(self, path, want):
        """Read a file through raw vfs_open/read/close in small windows.

        Returns ``(data, reads, data_reads, eof_seen, error)``. ``data_reads``
        excludes the trailing zero-byte EOF read, which every healthy read has
        and which would otherwise make a single-chunk file look like two reads.
        Raw PortalCmds rather than
        read_file_seq: the point is to control the window size so the file gets
        consumed over several reads of one open handle, which is the contract
        read_file_seq relies on and which no live read had ever exercised.
        """
        name = path.encode("latin-1")[:255] + b"\0"
        raw = yield PortalCmd(hop.HYPER_OP_VFS_OPEN, 0, 0, None, name)
        if not raw:
            return b"", 0, 0, False, "vfs_open: no response"
        res = kffi.from_buffer("vfs_open_result", raw)
        err, handle = int(res.error), int(res.handle)
        if err or not handle:
            return b"", 0, 0, False, f"vfs_open: errno {-err}"

        hdr = kffi.sizeof("vfs_read_result")
        out, reads, data_reads, eof_seen, error = b"", 0, 0, False, None
        try:
            # Bounded so a driver that never reports EOF cannot spin forever;
            # generous enough that hitting it means a real bug, not a big file.
            for _ in range(512):
                raw = yield PortalCmd(hop.HYPER_OP_VFS_READ, handle, want, None)
                if not raw:
                    error = "vfs_read: no response"
                    break
                r = kffi.from_buffer("vfs_read_result", raw)
                rerr, n, eof = int(r.error), int(r.nbytes), int(r.eof)
                reads += 1
                if n:
                    data_reads += 1
                if rerr:
                    error = f"vfs_read: errno {-rerr} after {len(out)}B"
                    break
                if n:
                    out += bytes(raw[hdr:hdr + n])
                if eof:
                    eof_seen = True
                    break
                if n == 0:
                    break
            else:
                error = "vfs_read: no EOF after 512 reads"
        except BaseException:
            # NOT a finally: you cannot yield while a generator is closing, so
            # a close in finally turns an abandoned read into "generator
            # ignored GeneratorExit" and buries the leaked handle under it.
            # This is the same hole that was fixed in fs.read_file_seq.
            yield PortalCmd(hop.HYPER_OP_VFS_CLOSE, handle, 0, None)
            raise
        yield PortalCmd(hop.HYPER_OP_VFS_CLOSE, handle, 0, None)
        return out, reads, data_reads, eof_seen, error

    def _pick_window(self, sizes):
        """Choose (path, window) so the windowed read spans several reads.

        Largest readable required path wins, with a window sized to give at
        least MIN_WINDOW_READS data-bearing reads. Derived from measurement
        because a window that happens to equal the file size proves nothing --
        and silently looked like a driver bug when it happened.
        """
        readable = [(n, p) for p, n in sizes.items() if n]
        if not readable:
            return None, 0
        n, path = max(readable)
        return path, max(1, min(MAX_WINDOW_BYTES, n // MIN_WINDOW_READS))

    def _check_sequential_contract(self, path, window, one_shot):
        """Prove the sequential semantics, not just that a read returns bytes.

        Four things have to hold, and only the first is about getting data:

          * the file is consumed over MORE than one read (so f_pos really
            advanced between calls -- the driver writing it back is the whole
            mechanism)
          * the concatenation equals what a single read returns, byte for byte
          * the file's opening bytes appear EXACTLY ONCE. A stateless read
            re-opens and re-generates per chunk, so its output repeats the
            header at every boundary; this is what separates "sequential" from
            "the same first chunk N times" and no length or content check can
            see the difference.
          * EOF is reported, rather than the read stopping because a bounded
            loop ran out

        Returns ``(ok, detail)``.
        """
        if not path:
            return False, ("no required path was readable, so the sequential "
                           "contract could not be exercised at all")
        data, reads, data_reads, eof, error = yield from self._read_windowed(
            path, window)
        if error:
            return False, f"{path} windowed read failed: {error}"
        if data_reads < 2:
            return False, (f"{path} came back in {data_reads} data-bearing "
                           f"read(s) of {window}B: the multi-read path never "
                           f"ran (got {len(data)}B)")
        # Checked before the one-shot comparison: a regenerating driver also
        # fails that comparison, but "the content repeats" is the diagnosis and
        # "the bytes differ" is only the symptom.
        head = data[:32]
        if head and data.count(head) != 1:
            return False, (f"{path} opening bytes appear "
                           f"{data.count(head)}x: content was re-generated per "
                           f"read instead of continued")
        if one_shot is not None and data != one_shot:
            return False, (f"{path} windowed ({len(data)}B) != one-shot "
                           f"({len(one_shot)}B): {data[:48]!r} vs "
                           f"{one_shot[:48]!r}")
        if not eof:
            return False, f"{path} never reported EOF over {reads} reads"
        return True, (f"{path} {len(data)}B over {data_reads} data-bearing "
                      f"reads of {window}B (+EOF), coherent")

    def _check_size_cap(self, path):
        """``size=`` must stop early rather than being advisory."""
        want = 32
        try:
            data = yield from plugins.fs.read_file_seq(path, size=want)
        except Exception as e:
            return False, f"size cap: {type(e).__name__}: {e}"
        if len(data) != want:
            return False, f"size={want} returned {len(data)}B"
        return True, f"size={want} honoured"

    # ------------------------------------------------------------------ #
    # Handle-table checks
    #
    # None of this is about file contents. It is about the failure modes the
    # driver has when the host misbehaves -- and every one of them was
    # previously unexercised on a guest, so "the handle table works" rested on
    # reading the C.
    # ------------------------------------------------------------------ #
    def _check_bad_handles(self, path):
        """A handle that is closed, never existed, or is zero must be EBADF.

        EBADF specifically, not EINVAL. kernel_read() also returns EINVAL for a
        file it refuses to serve, so while the driver used EINVAL for both, a
        live failure could not be attributed to either the handle table or the
        kernel's read path without a debug build -- which CI does not build.
        Asserting the distinction here is what keeps that diagnosis available.
        """
        EBADF = 9
        problems = []

        handle, err, _ = yield from self._vfs_open(path)
        if not handle:
            return None, (f"could not open {path} to get a handle "
                          f"({_errname(err) if err else 'no response'})")
        cerr = yield from self._vfs_close(handle)
        if cerr:
            problems.append(f"close of a live handle failed with errno {cerr}")

        # read-after-close: the generation counter's entire purpose
        _, err, _ = yield from self._vfs_read(handle, 64)
        if err != EBADF:
            problems.append(f"read after close gave errno {err}, want EBADF "
                            f"({EBADF})")
        cerr = yield from self._vfs_close(handle)
        if cerr != EBADF:
            problems.append(f"double close gave errno {cerr}, want EBADF")

        # A handle we never issued. Same slot, wrong generation: this is the one
        # that would silently read the WRONG FILE if the generation check were
        # dropped, so it matters more than the arithmetic suggests.
        _, err, _ = yield from self._vfs_read(handle + (1 << 8), 64)
        if err != EBADF:
            problems.append(f"read of an unissued handle gave errno {err}, "
                            f"want EBADF")
        # Handle 0 is reserved invalid so that a zeroed field cannot address
        # slot 0 by accident.
        _, err, _ = yield from self._vfs_read(0, 64)
        if err != EBADF:
            problems.append(f"read of handle 0 gave errno {err}, want EBADF")

        if problems:
            return False, "; ".join(problems)
        return True, "read-after-close, double close, unissued handle and "\
                     "handle 0 all EBADF"

    def _check_handle_table(self, path):
        """Leaking every slot must degrade for one reader, not wedge the table.

        The driver has 16 slots. A host that leaks handles -- a crashed
        generator, a plugin that forgot to close -- must not make the portal
        permanently unable to read any file, so the driver reclaims the oldest
        idle slot. The property being checked is that the (N+1)th open still
        SUCCEEDS and that the cost lands on the oldest handle as an EBADF,
        rather than the open failing forever.

        Never run on a guest before. It also covers the case that made
        reclaiming dangerous in the first place: a slot with a read in flight
        must not be the victim (it cannot be reached single-threaded from here,
        so it is called out in the marker rather than claimed).
        """
        SLOTS = 16
        EBADF = 9
        handles = []
        for _ in range(SLOTS + 4):
            handle, err, _ = yield from self._vfs_open(path)
            if not handle and err is None:
                # No response at all is a portal problem, not a table problem.
                # Reported as unexercised so it cannot masquerade as either a
                # pass or a wedged table.
                for h in handles:
                    yield from self._vfs_close(h)
                return None, (f"no portal response opening {path}; the handle "
                              f"table was not exercised")
            if not handle:
                # Refusing an open because the table is full is exactly the
                # failure this is here to catch: a leak would become a
                # permanent inability to read anything.
                for h in handles:
                    yield from self._vfs_close(h)
                return False, (f"open {len(handles) + 1} of {SLOTS + 4} failed "
                               f"with errno {err}: the table wedges on a leak "
                               f"instead of reclaiming")
            handles.append(handle)

        # The 4 oldest should have been reclaimed to make room.
        reclaimed = []
        live = []
        for h in handles:
            _, err, _ = yield from self._vfs_read(h, 16)
            (reclaimed if err == EBADF else live).append((h, err))

        for h, _ in live:
            yield from self._vfs_close(h)

        if len(reclaimed) != 4:
            return False, (f"{len(reclaimed)} of {len(handles)} handles were "
                           f"reclaimed, expected exactly 4 (opened "
                           f"{SLOTS + 4} into {SLOTS} slots); live errnos "
                           f"{[e for _, e in live]}")
        # Reclaim must take the OLDEST, or a long-lived reader loses its handle
        # to a short-lived one.
        if [h for h, _ in reclaimed] != handles[:4]:
            return False, ("reclaim did not take the 4 oldest handles: "
                           f"took {[h for h, _ in reclaimed]}, oldest are "
                           f"{handles[:4]}")
        return True, (f"{SLOTS + 4} opens into {SLOTS} slots: the 4 oldest "
                      f"became EBADF, the rest stayed readable")

    def _check_directory(self, path="/proc"):
        """A directory must fail with an errno, not read as an empty file.

        Opening a directory succeeds -- filp_open is happy with it -- so this is
        the shape of bug the whole errno rework exists to prevent: something
        that looks exactly like a file with no content. A caller reading /proc
        as b"" would conclude there are no processes.
        """
        handle, err, _ = yield from self._vfs_open(path)
        if not handle and err is None:
            return None, f"no portal response opening {path}"
        if not handle:
            # Also acceptable: refusing at open. What is not acceptable is
            # success followed by silence.
            return True, f"{path} refused at open (errno {err})"
        data, err, eof = yield from self._vfs_read(handle, 256)
        yield from self._vfs_close(handle)
        if err:
            return True, f"{path} read gave errno {err} ({_errname(err)})"
        if data:
            return True, f"{path} read returned {len(data)}B of directory data"
        return False, (f"{path} opened and read {len(data or b'')}B with errno "
                       f"0 and eof={eof}: a directory is indistinguishable "
                       f"from an empty file")

    def _check_regular_file(self, path=REGULAR_FILE, magic=b"\x7fELF"):
        """The sequential op on an ordinary file.

        read_file routes regular files to the stateless op, so the sequential
        op had never been pointed at one. It should work: nothing about
        vfs_open/read/close is procfs-specific, and if it does not, then the
        routing is load-bearing for correctness rather than only for
        synthetic-filesystem coherence -- which is a different claim than the
        one this plugin has been making.
        """
        try:
            data = yield from plugins.fs.read_file_seq(path, size=len(magic))
        except Exception as e:
            return False, f"{path}: {type(e).__name__}: {e}"
        if not data.startswith(magic):
            return False, f"{path}: got {data!r}, want a {magic!r} prefix"
        return True, f"{path} reads {magic!r} through the sequential op"

    def _verify(self):
        lines = []
        failures = []
        checks = list(REQUIRED)

        # The strongest check in the set, built from ground truth we already
        # hold: /proc/self/status must name the pid of the task that made the
        # ioctl. Only the guest's own per-task procfs can produce that, so it
        # rules out a cached blob, a modelled pseudofile, and a read that
        # resolved in the wrong task context. Appended (not asserted) if osi
        # cannot name the caller, since that would be a different failure.
        caller = None
        try:
            caller = yield from plugins.osi.get_proc()
        except Exception as e:
            self.logger.warning(f"vfs_read_verify: no caller proc ({e})")
        pid = getattr(caller, "pid", None)
        if pid:
            checks.append(("/proc/self/status", b"Pid:\t%d" % int(pid)))
        else:
            checks.append(("/proc/self/status", b"Name:"))

        seq_ok = 0
        stateless_ok = 0
        sizes = {}
        one_shot = {}
        # Counted for EVERY required path, not just the ones the sequential read
        # served. The first version only tallied stateless on seq-successful
        # paths, which understated it and hid the most interesting cell of the
        # table: what the old op did on a path where the new one failed.

        for path, marker in checks:
            data, err = yield from self._read_seq(path)
            st, st_err = yield from self._read_stateless(path)

            if st:
                stateless_ok += 1

            if err is not None:
                failures.append(f"{path}: seq read failed ({err})")
                lines.append(f"{path} seq=ERROR({err}) stateless={_n(st)}")
                continue
            if not data:
                failures.append(f"{path}: seq read returned no data")
                lines.append(f"{path} seq=EMPTY stateless={_n(st)}")
                continue
            if marker not in data:
                # Wrong content is worse than none: something answered that is
                # not the file we asked for.
                failures.append(
                    f"{path}: {len(data)} bytes but no {marker!r} "
                    f"(head={data[:64]!r})")
                lines.append(f"{path} seq=WRONG({len(data)}B) stateless={_n(st)}")
                continue

            seq_ok += 1
            sizes[path] = len(data)
            lines.append(f"{path} seq=OK({len(data)}B) stateless={_n(st)}"
                         + (f" stateless_err={st_err}" if st_err else ""))
            one_shot[path] = data

        # Mechanism checks, aimed at the largest path this run actually read.
        # Deliberately after the table rather than before it: the window has to
        # be derived from a measured size, or it can equal the file size and
        # report a healthy driver as broken (which is what happened on mips64
        # 4.10, where /proc/version is exactly 64 bytes).
        wpath, window = self._pick_window(sizes)
        contract_ok, detail = yield from self._check_sequential_contract(
            wpath, window, one_shot.get(wpath))
        lines.append(f"sequential_contract={'OK' if contract_ok else 'FAIL'}"
                     f" -- {detail}")
        if not contract_ok:
            failures.append(f"sequential contract: {detail}")

        if wpath:
            cap_ok, cap_detail = yield from self._check_size_cap(wpath)
            lines.append(f"size_cap={'OK' if cap_ok else 'FAIL'} -- {cap_detail}")
            if not cap_ok:
                failures.append(f"size cap: {cap_detail}")

        # Handle-table and op-shape checks. Each returns (ok, detail), where ok
        # is None for "could not be exercised here" -- recorded, never counted
        # as a pass, because an unexercised check that reports green is worse
        # than no check.
        handle_path = wpath or "/proc/version"
        table_checks = [
            ("bad_handles", self._check_bad_handles(handle_path)),
            ("handle_table", self._check_handle_table(handle_path)),
            ("directory", self._check_directory()),
            ("regular_file", self._check_regular_file()),
        ]
        table_ok = 0
        for name, gen in table_checks:
            try:
                ok, detail = yield from gen
            except Exception as e:
                ok, detail = False, f"raised {type(e).__name__}: {e}"
            verdict = "OK" if ok else ("n/a" if ok is None else "FAIL")
            lines.append(f"{name}={verdict} -- {detail}")
            if ok is False:
                failures.append(f"{name}: {detail}")
            elif ok:
                table_ok += 1

        # Stated rather than left absent: the O_NONBLOCK open cannot be
        # demonstrated from here. Showing it needs a file whose ->read blocks
        # with nothing to return (a FIFO with no writer, /proc/kmsg after its
        # buffer is drained), and reading one of those against a driver WITHOUT
        # the fix does not fail the test -- it hangs the emulation until the CI
        # job times out, with no marker written at all. So the check would be
        # safe only once the pin already carries the thing it is checking for.
        lines.append("blocking_open=unexercised (proving O_NONBLOCK needs a "
                     "file that blocks forever, which on an unfixed driver "
                     "hangs the run instead of failing it)")

        for path in OPTIONAL:
            data, err = yield from self._read_seq(path)
            n = len(data) if data else 0
            lines.append(f"{path} seq={'OK(%dB)' % n if n else 'none'}"
                         + (f" ({err})" if err else ""))

        # Canary: a gap that starts reading ON A KERNEL WHERE IT WAS EXPECTED TO
        # FAIL is news. Below that kernel it is expected to work, so reading is
        # not news and must not warn -- otherwise the warning fires on every
        # 4.10 run and stops meaning anything.
        kver = _kernel_version(one_shot.get("/proc/version"))
        closed = []
        expected_gaps = 0
        for path, (min_kernel, reason) in KNOWN_GAPS.items():
            applies = kver is None or kver >= min_kernel
            data, err = yield from self._read_seq(path)
            got = bool(data) and not err
            if not applies:
                lines.append(
                    f"{path} gap=n/a on {_kv(kver)} (expected readable below "
                    f"{_kv(min_kernel)}): "
                    + (f"OK({len(data)}B)" if got else f"none ({err})"))
                continue
            expected_gaps += 1
            if got:
                closed.append(path)
                lines.append(f"{path} gap=CLOSED on {_kv(kver)} "
                             f"seq=OK({len(data)}B) -- remove from KNOWN_GAPS "
                             f"({reason})")
            else:
                lines.append(f"{path} gap=open ({err or 'no data'})")
        if closed:
            self.logger.warning(
                "vfs_read_verify: KNOWN_GAPS entries now readable on "
                f"{_kv(kver)}, remove them: " + ", ".join(closed))

        # Informational sweep across the vfs types, so the marker records what
        # is actually reachable on these guests instead of us inferring it from
        # the handful of paths the required set happens to name.
        chunk = max(1, self.plugins.portal.regions_size
                    - kffi.sizeof("vfs_read_result") - 1)
        biggest = 0
        for path in PROBES:
            data, err = yield from self._read_seq(path, size=PROBE_CAP)
            n = len(data) if data else 0
            biggest = max(biggest, n)
            size_txt = f"{'>=' if n >= PROBE_CAP else ''}{n}B"
            lines.append(f"probe {path} "
                         + (f"OK({size_txt})"
                            f"{' MULTI-CHUNK' if n > chunk else ''}"
                            if n else f"none ({err or 'no data'})"))
        # Stated explicitly because its absence is meaningful and easy to
        # misread: on 6.13 the only readable procfs files are all smaller than a
        # chunk (the big ones are in the refused class), so a real multi-chunk
        # read cannot be demonstrated there at all and the windowed check above
        # is the stand-in. Saying "no" beats leaving it ambiguous.
        lines.append(f"chunk_bytes={chunk} largest_probe={biggest}B "
                     f"multichunk_seen={'yes' if biggest > chunk else 'no'}"
                     f" probe_cap={PROBE_CAP}")

        ok = not failures
        summary = (f"VFS_READ_VERIFY={'PASS' if ok else 'FAIL'} "
                   f"seq={seq_ok}/{len(checks)} "
                   f"stateless={stateless_ok}/{len(checks)} "
                   f"contract={'ok' if contract_ok else 'FAIL'} "
                   f"handle_checks={table_ok}/{len(table_checks)} "
                   f"kernel={_kv(kver)} "
                   f"gaps_closed={len(closed)}/{expected_gaps} "
                   f"caller_pid={pid if pid else 'unknown'}")
        if ok:
            self.logger.info(summary)
        else:
            self.logger.error(summary)
            for f in failures:
                self.logger.error(f"vfs_read_verify: {f}")
        self._write(summary, lines, failures)

    def _write(self, summary, lines, failures):
        self._reported = True
        try:
            with open(join(self.outdir, MARKER), "w") as f:
                f.write(summary + "\n")
                for line in lines:
                    f.write("  " + line + "\n")
                for fail in failures:
                    f.write("FAIL: " + fail + "\n")
        except OSError as e:
            self.logger.error(f"vfs_read_verify: cannot write marker: {e}")

    def uninit(self):
        # A run that never reached the check must not look like a pass: write
        # the negative verdict so a missing marker is never the signal.
        if not self._reported:
            self._write("VFS_READ_VERIFY=FAIL never_triggered=yes "
                        "(the guest ioctl never reached the host hook)", [], [])


def _kernel_version(version_bytes):
    """(major, minor) from /proc/version, or None if it cannot be read.

    None means "do not apply a version condition": better to report a gap that
    might not apply than to silently skip one because a read failed.
    """
    if not version_bytes:
        return None
    try:
        text = version_bytes.decode("latin-1", "replace")
        rel = text.split("version", 1)[1].strip().split()[0]
        major, minor = rel.split(".")[:2]
        return int(major), int("".join(c for c in minor if c.isdigit()))
    except Exception:
        return None


def _kv(ver):
    return "unknown" if not ver else f"{ver[0]}.{ver[1]}"


_ERRNAMES = {2: "ENOENT", 5: "EIO", 9: "EBADF", 11: "EAGAIN", 13: "EACCES",
             16: "EBUSY", 21: "EISDIR", 22: "EINVAL", 23: "ENFILE"}


def _errname(n):
    return _ERRNAMES.get(n, f"errno {n}")


def _n(data):
    """Render a stateless read result compactly for the marker line."""
    if data is None:
        return "none"
    return f"OK({len(data)}B)" if data else "empty"
