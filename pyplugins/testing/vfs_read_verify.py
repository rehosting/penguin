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
    def _verify(self):
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

        lines = []
        seq_ok = 0
        stateless_ok = 0
        failures = []
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

        ok = not failures
        summary = (f"VFS_READ_VERIFY={'PASS' if ok else 'FAIL'} "
                   f"seq={seq_ok}/{len(checks)} "
                   f"stateless={stateless_ok}/{len(checks)} "
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
