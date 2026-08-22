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
KNOWN_GAPS = {
    "/proc/net/tcp": (
        "kernels >=~5.10: /proc/net/* register proc_read = seq_read, so the "
        "inode gets proc_reg_file_ops (.read, no .read_iter) and __kernel_read "
        "refuses it (warn_unsupported -> EINVAL) for both portal read ops. Not "
        "fixable module-side: proc_reg_read forwards to a proc_ops a module "
        "cannot inspect, so private_data cannot be proven to be a seq_file "
        "(in /proc/<pid>/mem it is an mm_struct). Consumers should read socket "
        "state from the kernel via the OSI fd walk instead of from procfs."),
}

# The windowed-read check: open one file and read it in deliberately small
# windows. This is how the sequential contract gets proven without depending on
# finding a file bigger than a portal chunk (~4 KB) on a minimal emulated guest.
# Every file the earlier version of this check read fit in ONE chunk -- the
# largest was 453 bytes -- so the loop, the driver's f_pos writeback, EOF across
# calls and handle lifetime over a long read, i.e. the entire reason the
# sequential op exists, had never actually run on a guest.
WINDOW_PATH = "/proc/version"
WINDOW_BYTES = 64

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
    # hyperfs (penguin's OWN modelled pseudofile, 8192 bytes, from
    # procfs_test.yaml). hyperfs_file_operations sets .read with no .read_iter,
    # which puts every modelled pseudofile in the class __kernel_read refuses --
    # so penguin may not be able to read its own /proc and /sys models from the
    # host at all on >=5.10. Measured here rather than assumed.
    "/proc/large_file",
    # ->read = seq_read via proc_ops, so proc_reg_file_ops: expected refused,
    # and NOT fixed by the seq_read_iter fallback (its ->read is proc_reg_read).
    "/proc/kallsyms",
]

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
    def _read_seq(self, path):
        """Read via the sequential path; return ``(bytes, error-string)``."""
        try:
            data = yield from plugins.fs.read_file(path)
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
        finally:
            yield PortalCmd(hop.HYPER_OP_VFS_CLOSE, handle, 0, None)
        return out, reads, data_reads, eof_seen, error

    def _check_sequential_contract(self, one_shot):
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
        data, reads, data_reads, eof, error = yield from self._read_windowed(
            WINDOW_PATH, WINDOW_BYTES)
        if error:
            return False, f"{WINDOW_PATH} windowed read failed: {error}"
        if data_reads < 2:
            return False, (f"{WINDOW_PATH} came back in {data_reads} "
                           f"data-bearing read(s) of {WINDOW_BYTES}B: the "
                           f"multi-read path never ran (got {len(data)}B)")
        # Checked before the one-shot comparison: a regenerating driver also
        # fails that comparison, but "the content repeats" is the diagnosis and
        # "the bytes differ" is only the symptom.
        head = data[:32]
        if head and data.count(head) != 1:
            return False, (f"{WINDOW_PATH} opening bytes appear "
                           f"{data.count(head)}x: content was re-generated per "
                           f"read instead of continued")
        if one_shot is not None and data != one_shot:
            return False, (f"{WINDOW_PATH} windowed ({len(data)}B) != one-shot "
                           f"({len(one_shot)}B): {data[:48]!r} vs "
                           f"{one_shot[:48]!r}")
        if not eof:
            return False, f"{WINDOW_PATH} never reported EOF over {reads} reads"
        return True, (f"{WINDOW_PATH} {len(data)}B over {data_reads} "
                      f"data-bearing reads of {WINDOW_BYTES}B (+EOF), coherent")

    def _check_size_cap(self):
        """``size=`` must stop early rather than being advisory."""
        want = 32
        try:
            data = yield from plugins.fs.read_file_seq(WINDOW_PATH, size=want)
        except Exception as e:
            return False, f"size cap: {type(e).__name__}: {e}"
        if len(data) != want:
            return False, f"size={want} returned {len(data)}B"
        return True, f"size={want} honoured"

    def _verify(self):
        lines = []
        failures = []

        # The mechanism checks come first: they are the ones that say the
        # sequential contract holds at all, and a failure in the path table
        # below must not stop them from running.
        one_shot, one_shot_err = yield from self._read_seq(WINDOW_PATH)
        seq_ok_contract, detail = yield from self._check_sequential_contract(
            one_shot if not one_shot_err else None)
        lines.append(f"sequential_contract={'OK' if seq_ok_contract else 'FAIL'}"
                     f" -- {detail}")
        if not seq_ok_contract:
            failures.append(f"sequential contract: {detail}")

        cap_ok, cap_detail = yield from self._check_size_cap()
        lines.append(f"size_cap={'OK' if cap_ok else 'FAIL'} -- {cap_detail}")
        if not cap_ok:
            failures.append(f"size cap: {cap_detail}")

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
            lines.append(f"{path} seq=OK({len(data)}B) stateless={_n(st)}"
                         + (f" stateless_err={st_err}" if st_err else ""))

        for path in OPTIONAL:
            data, err = yield from self._read_seq(path)
            n = len(data) if data else 0
            lines.append(f"{path} seq={'OK(%dB)' % n if n else 'none'}"
                         + (f" ({err})" if err else ""))

        # Canary: a known gap that starts reading is news. Report it as such
        # rather than silently passing, so the entry gets removed on purpose.
        closed = []
        for path, reason in KNOWN_GAPS.items():
            data, err = yield from self._read_seq(path)
            if data and not err:
                closed.append(path)
                lines.append(f"{path} gap=CLOSED seq=OK({len(data)}B) -- "
                             f"remove from KNOWN_GAPS ({reason})")
            else:
                lines.append(f"{path} gap=open ({err or 'no data'})")
        if closed:
            self.logger.warning(
                "vfs_read_verify: KNOWN_GAPS entries now readable, remove them: "
                + ", ".join(closed))

        # Informational sweep across the vfs types, so the marker records what
        # is actually reachable on these guests instead of us inferring it from
        # the handful of paths the required set happens to name.
        chunk = max(1, self.plugins.portal.regions_size
                    - kffi.sizeof("vfs_read_result") - 1)
        biggest = 0
        for path in PROBES:
            data, err = yield from self._read_seq(path)
            n = len(data) if data else 0
            biggest = max(biggest, n)
            lines.append(f"probe {path} "
                         + (f"OK({n}B){' MULTI-CHUNK' if n > chunk else ''}"
                            if n else f"none ({err or 'no data'})"))
        lines.append(f"chunk_bytes={chunk} largest_probe={biggest}B "
                     f"multichunk_seen={'yes' if biggest > chunk else 'no'}")

        ok = not failures
        summary = (f"VFS_READ_VERIFY={'PASS' if ok else 'FAIL'} "
                   f"seq={seq_ok}/{len(checks)} "
                   f"stateless={stateless_ok}/{len(checks)} "
                   f"contract={'ok' if seq_ok_contract else 'FAIL'} "
                   f"gaps_closed={len(closed)}/{len(KNOWN_GAPS)} "
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


def _n(data):
    """Render a stateless read result compactly for the marker line."""
    if data is None:
        return "none"
    return f"OK({len(data)}B)" if data else "empty"
