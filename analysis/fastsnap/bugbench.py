"""bugbench -- the missing join between an input and a crash record.

`fuzzdrive` injects inputs and counts them. `crashes` records fatal signal
deliveries. Neither knows about the other, so a crashes.yaml row can never name
the input that produced it. This plugin is the smallest thing that closes that:

  1. It owns the injection point, so every payload gets a monotonically
     increasing `seq`, is hashed, and is written to a corpus directory.
  2. It remembers, per pid, the last seq delivered to that pid.
  3. It subscribes to the SAME `signal_deliver` event the crashes plugin
     subscribes to, and on a fatal signal joins the delivery to that pid's
     last input.

The join key is (pid, last input delivered). It is exact for a single-threaded
victim that parses each input before reading the next -- the case a snapshot
fuzzing loop constructs on purpose. It is a heuristic for a threaded or
pipelined server, and the output says so on every row.

Output: `crashes_attributed.yaml` (one row per attributed delivery) and
`corpus/<seq>.bin` (the exact bytes, byte-for-byte replayable).

Replay: `replay_file: <path>` injects only those bytes, every read, and asserts
the same crash comes back. That is the reproducer half of the pipeline.

WHERE THIS FILE LIVES. Here, canonically, and copied into
`work/bugbench/proj/plugins.d/` to run -- the same arrangement as fastloop.py,
and for the same reason: `work/` is gitignored in its entirety (a `*` rule that
exists because this lane once swept a 1.8 MB busybox into a public repo), so a
plugin kept only there is untracked, and the two host-side tests that read it
could not run from a clean checkout at all.

WHY THIS FILE IS TIMED. The reset is no longer the expensive part of a lap.
Measured on this target, an ordinary lap is 0.740 ms of which the reset's own
clock is 0.062 ms and the whole reset side -- main-loop latency, the reset,
and the post-resume penalty -- is 0.206 ms. A bare lap with this plugin loaded
is 0.523 ms; the same bare lap without it was 0.111 ms. So roughly 0.41 ms per
lap, more than half of every iteration, is spent HERE, and it was never
attributed to a line. `_phase` does that: five spans per lap, summed, so the
answer is a table rather than a guess.
"""

import hashlib
import json
import os
import random
import time
from collections import deque
from os.path import join

import yaml

from penguin import Plugin, plugins

syscalls = plugins.syscalls

FATAL = ["SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT", "SIGFPE"]



# The seven planted triggers, mirrored from ../../bugbench_truth.py. Inlined
# rather than imported because this file is loaded as a plugins.d drop-in inside
# the container, where the analysis directory is not on sys.path. The pairing is
# checked by tools/check_bugbench_sync.py -- a copy that silently drifts from the
# manifest would make every score wrong in a way no run could reveal.
def _inp(*prefix, length=32, fill=0x41):
    b = bytearray([fill]) * length
    for i, v in enumerate(prefix):
        b[i] = v
    return bytes(b)


TRIGGERS = [
    ("B1", _inp(0x01, 0xFF)),
    ("B2", _inp(0x02, 0x00)),
    ("B3", _inp(0x03, 0x00)),
    ("B4", _inp(0x04, 0x80)),
    ("B5", _inp(0x05, 0xC0)),
    ("B6", _inp(0x06, ord("F"), ord("U"), ord("Z"), ord("Z"))),
    ("B7", _inp(0x07, 0x5A, 0xFF, 0x00, 0x00, 0x00)),
]

class BugBench(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "parsed"
        self.rng = random.Random(int(self.get_arg("seed") or 1337))
        self.bad_seq = int(self.get_arg("bad_seq") or 42)
        replay_file = self.get_arg("replay_file")
        self.replay = None
        self.replay_path = None
        if replay_file:
            if not os.path.isabs(replay_file):
                replay_file = join(self.get_arg("proj_dir") or ".", replay_file)
            self.replay_path = replay_file
            with open(replay_file, "rb") as fh:
                self.replay = fh.read()

        self.corpus_dir = join(self.outdir, "corpus")
        os.makedirs(self.corpus_dir, exist_ok=True)

        self.fd_suffix = self.get_arg("fd_suffix") or "/zero"
        self.mode = (self.get_arg("mode") or "oracle").lower()
        if self.mode not in ("oracle", "fuzz"):
            raise ValueError("bugbench: mode must be 'oracle' or 'fuzz'")
        self._fdnames = {}
        self.n_skipped = 0
        self.seq = 0
        self.last_by_pid = {}     # pid -> input record
        self.n_sent = 0           # how many were ever delivered
        # Caps, so a snapshot loop delivering thousands a second does not turn
        # the harness into the bottleneck it is measuring.
        self.corpus_max = int(self.get_arg("corpus_max") or 20000)
        self.sent_max = int(self.get_arg("sent_max") or 5000)
        # A deque, not a list. `sent` is a ring capped at sent_max and the list
        # form dropped its oldest entry with pop(0) -- an O(n) memmove of 5,000
        # pointers on EVERY lap, on the vCPU thread, in the hook whose cost this
        # plugin now measures. maxlen does the same thing in O(1).
        self.sent = deque(maxlen=self.sent_max)
        self.recent_max = 256
        self.recent = {}          # seq -> payload, not yet on disk
        self.report_every = int(self.get_arg("report_every") or 50)
        self.on_disk = set()
        self.attributed = []      # joined crash rows

        # ---- PER-INPUT SCOPE ----------------------------------------------
        #
        # In a normal run this plugin's state is run-scoped and that is right:
        # one execution, everything accumulates into it. Under a snapshot loop
        # it is wrong. Each lap is an independent execution of the same instant
        # with a different input, and the join this plugin performs -- which
        # input crashed the victim -- is a per-input question answered with a
        # run-scoped table, `last_by_pid`.
        #
        # That table was catastrophically wrong once already, in the other
        # direction (a latch keyed on (fd, pid) sent 2,786 inputs into the
        # dynamic loader's read of libgcc_s.so.1). It is right now because it
        # is rebuilt from the guest's own events -- but "the last input this
        # pid saw" is still a guess about which execution a crash belongs to,
        # and nothing was checking it.
        #
        # fastloop publishes `on_lap` at the one instant that answers it: the
        # reset has completed and the guest is back at the armed point, so
        # everything between two of those events belongs to exactly one input.
        # Bound lazily (load order is config order, and fastloop may not exist
        # yet) and at most once (a failed bind must not be retried on the vCPU
        # thread on every read).
        self.lap = None            # the iteration fastloop says we are in
        self.lap_closed_by = None  # why the previous one ended
        self._lap_bound = False
        self._lap_rec = None       # the input delivered in this lap
        self._lap_inputs = 0       # how many, to know when the join is exact
        self.lap_multi = 0         # laps that delivered more than one input
        self.n_join_lap = 0
        self.n_join_pid = 0
        # The cross-check. Both joins are available whenever a lap boundary
        # exists, they answer the same question, and a disagreement means the
        # pid join -- the only one available without fastloop, and the one
        # every earlier run in this lane used -- named the wrong input.
        self.n_join_disagree = 0
        self.t0 = time.time()
        self.p0 = time.perf_counter()

        # ---- the lean path ------------------------------------------------
        #
        # Both osi calls in on_read were PORTAL ROUND TRIPS: get_fd_name walks
        # the guest's fd table and get_proc reads the current task, each as a
        # hypercall the in-guest driver services while the vCPU waits. Measured
        # here, run 28: 128.79 us and 73.73 us of a 280.22 us hook, so 72% of
        # every injection was spent asking the guest two questions per lap.
        #
        # THE FIRST ATTEMPT WAS WRONG AND IS WORTH KEEPING WRITTEN DOWN. It
        # latched (fd, pid) on the theory that a snapshot loop returns the
        # guest to one instant, so both are constants. They are -- AFTER the
        # loop arms. Before it, the guest is an ordinary forward-running system
        # whose victim crashes and restarts, and fd 3 is the dynamic loader's
        # libgcc_s.so.1 before it is the victim's request descriptor. The latch
        # was earned during that window and 2,786 inputs went into the loader's
        # read of its own shared library -- the exact failure the uncached
        # resolve was written to avoid. The audit caught it three times and the
        # run still ended with 3,000 inputs instead of 124,452. A cache whose
        # correctness rests on "the guest is in a state I believe it is in" is
        # the wrong shape however carefully it is audited.
        #
        # WHAT REPLACES IT DERIVES BOTH ANSWERS FROM THE GUEST'S OWN EVENTS.
        #
        #   pid  -- `struct syscall_event` already carries `pid` (current->pid)
        #           and `create_time`, denormalized by the driver for this
        #           purpose. No round trip, no assumption, no staleness.
        #   fd   -- learned from open/openat returning it and forgotten on
        #           close, keyed by (pid, create_time, fd). The close hook is
        #           not optional: the loader closes fd 3 and the victim's
        #           open() gets 3 back, in the SAME process, which is why a
        #           key without it would reproduce the bug above.
        #
        # An unknown fd falls back to the portal resolve and caches the answer,
        # so the worst case is today's cost. Opens and closes are a handful per
        # process life against thousands of reads a second.
        #
        # And the audit stays, because it is what turned the first attempt from
        # a plausible speedup into a measured retraction: every
        # `revalidate_every` injections the fd is resolved the expensive way
        # and compared, and the cheap pid is compared against get_proc() for
        # the first `verify_first`.
        self.fast = bool(self.get_arg("fast"))
        self.fast_rng = bool(self.get_arg("fast_rng"))
        self.revalidate_every = int(self.get_arg("revalidate_every") or 1000)
        self.verify_first = int(self.get_arg("verify_first") or 200)
        self._fdmap = {}          # (pid, create_time, fd) -> name
        self.n_fd_cached = 0      # reads answered from the map
        self.n_fd_resolved = 0    # reads that paid the portal
        self.n_opens = 0
        self.n_closes = 0
        self.n_pid_checked = 0
        self.n_pid_agree = 0
        self.pid_from_event = None   # None until the cross-check decides
        self.n_revalidated = 0
        self.n_audit_blind = 0
        self.cache_errors = []

        # ---- per-lap attribution -------------------------------------------
        # sum/count/max rather than a percentile: 100k+ laps of floats would
        # cost more to keep than the thing being measured, and for attributing
        # a mean the sum is exactly right. `max` is kept because a phase whose
        # mean is small and whose max is 200 ms is a different problem.
        self._ph = {}

        self.signames = {}
        for name in FATAL:
            num = plugins.signals.signal_name_to_num(name)
            if num is not None:
                self.signames.setdefault(num, name)

        syscalls.syscall("on_sys_read_return", comm_filter=self.comm)(self.on_read)
        if self.fast:
            # Rare hooks that pay for a hot one. The victim opens and closes a
            # handful of descriptors per life and reads thousands a second, so
            # learning the map here costs a portal call per open instead of one
            # per read. read_only on close -- it inspects an argument and
            # changes nothing.
            for nm in ("on_sys_open_return", "on_sys_openat_return"):
                try:
                    syscalls.syscall(nm, comm_filter=self.comm)(self.on_open_ret)
                except Exception as e:                      # noqa: BLE001
                    self.cache_errors.append(f"{nm}: {e!r}")
            try:
                syscalls.syscall("on_sys_close_enter", comm_filter=self.comm,
                                 read_only=True)(self.on_close)
            except Exception as e:                          # noqa: BLE001
                # Fatal for the map: without close the loader's fd 3 is
                # remembered as libgcc_s.so.1 and the victim's fd 3 never gets
                # an input. Fall back to resolving every read rather than run
                # with a map that cannot forget.
                self.logger.error(
                    f"bugbench: no close hook ({e!r}), so the fd map cannot "
                    f"forget a recycled descriptor. Disabling it; every read "
                    f"resolves through the guest as before.")
                self.cache_errors.append(f"close hook: {e!r}")
                self.fast = False
        plugins.subscribe(plugins.signal_monitor, "signal_deliver",
                          self.on_signal_deliver)
        for num in self.signames:
            plugins.signal_monitor.register_hook(sig=num)

        # Opened line-buffered: a run killed mid-flight still has every crash
        # recorded, which is the durability the periodic YAML dump was for.
        try:
            self._jsonl = open(join(self.outdir, "crashes_attributed.jsonl"),
                               "w", buffering=1)
        except Exception as e:                              # noqa: BLE001
            self.logger.warning(f"bugbench: no crash journal ({e!r}); crashes "
                                f"are still written by uninit()")
            self._jsonl = None
        self.write_report()
        mode = (f"REPLAY {self.replay_path} ({len(self.replay)} B, "
                f"sha256={hashlib.sha256(self.replay).hexdigest()[:16]})"
                if self.replay is not None else self.mode.upper())
        self.logger.info(f"bugbench: armed on comm={self.comm!r} mode={mode} "
                         f"fast={self.fast} corpus_max={self.corpus_max}")

    # ---- attribution ------------------------------------------------------

    def _bind_lap(self):
        """Subscribe to fastloop's iteration boundary. Once, lazily, quietly.

        `plugins.plugins` is read directly rather than `plugins.fastloop`,
        which would LOAD fastloop if it were not configured -- turning a
        missing measurement harness into a second instance of one, in the
        middle of the run it is supposed to be measuring.
        """
        self._lap_bound = True
        loop = getattr(plugins, "plugins", {}).get("fastloop")
        if loop is None:
            self.logger.info(
                "bugbench: no fastloop in this run, so there is no iteration "
                "boundary to scope inputs by; crashes join to the last input "
                "the crashing pid received, as before.")
            return
        try:
            plugins.subscribe(loop, "on_lap", self.on_lap)
        except Exception as e:                              # noqa: BLE001
            self.logger.warning(
                f"bugbench: could not subscribe to fastloop.on_lap ({e!r}); "
                f"falling back to the pid join")
            return
        self.logger.info("bugbench: scoping inputs per lap via fastloop.on_lap")

    def on_lap(self, lap, closed_by):
        """A new iteration is starting: the guest is back at the armed instant.

        Everything after this and before the next one is one input's doing.
        """
        if self._lap_inputs > 1:
            # Not fatal, but it makes the lap join no more exact than the pid
            # join for that lap, and a count of these is the only way to know
            # whether the detector really is one-input-per-lap on this target.
            self.lap_multi += 1
        self._lap_inputs = 0
        self._lap_rec = None
        self.lap = lap
        self.lap_closed_by = closed_by

    def _phase(self, name, dt):
        s = self._ph.get(name)
        if s is None:
            self._ph[name] = [dt, 1, dt]
            return
        s[0] += dt
        s[1] += 1
        if dt > s[2]:
            s[2] = dt

    def _phases_out(self):
        out = {}
        for k, (tot, n, mx) in sorted(self._ph.items(),
                                      key=lambda kv: -kv[1][0]):
            out[k] = {"total_s": round(tot, 6), "n": n,
                      "mean_us": round(tot / n * 1e6, 2),
                      "max_us": round(mx * 1e6, 2)}
        return out

    # ---- input generation -------------------------------------------------

    def make_payload(self, seq: int, limit: int) -> bytes:
        """One request for the victim: req[0] is an opcode, req[1..] operands.

        Two modes, and the first is what makes the second readable.

        ORACLE mode sends the seven known triggers, in order, then benign
        traffic. It is not a fuzzer -- it is the control that proves the
        pipeline can carry every planted bug from input to crash to
        attribution. If oracle mode does not score 7/7, a low score in fuzz
        mode says nothing about the fuzzer, because the plumbing is already
        losing bugs.

        FUZZ mode is blind byte mutation, which is the honest baseline: no
        coverage feedback, no dictionary. It should find the trivial and easy
        tiers and stall on B6 (a 4-byte magic, 2^-32) and B7 (two conditions
        at once). If it were to "find" those, that would be evidence of a
        scoring bug, not of a strong mutator.
        """
        if self.replay is not None:
            return self.replay[:limit]

        if self.mode == "oracle":
            if seq < len(TRIGGERS):
                return TRIGGERS[seq][1][:limit]
            # after the triggers, benign traffic so the run keeps going and the
            # negative control has something to be checked against
            return self._benign()[:limit]

        return self._fuzz()[:limit]

    def _benign(self) -> bytes:
        n = self.rng.randrange(8, 40)
        return bytes([0x00] + [self.rng.randrange(0x20, 0x7f)
                               for _ in range(n - 1)])

    def _fuzz(self) -> bytes:
        n = self.rng.randrange(8, 64)
        if self.fast_rng:
            # 36 randrange() calls per input measured at 28.85 us, a tenth of
            # the hook. randbytes is the same blind mutation in one call; it is
            # a DIFFERENT byte stream from the same seed, so a run with it on
            # is not corpus-comparable with one without, and the manifest's
            # per-input probabilities -- which is what the score is predicted
            # from -- are unchanged.
            return self.rng.randbytes(n)
        return bytes(self.rng.randrange(0, 256) for _ in range(n))

    # ---- hooks ------------------------------------------------------------

    # ---- the fd map, learned from the guest -------------------------------

    def _key(self, syscall, fd):
        """(process identity, fd). create_time distinguishes a recycled pid
        from the process that held it before, which a bare pid cannot."""
        try:
            return (int(syscall.pid), int(syscall.create_time), int(fd))
        except Exception:                                   # noqa: BLE001
            return None

    def on_open_ret(self, regs, proto, syscall, *args):
        """open/openat returning an fd. The path is read through the portal --
        once per open, against thousands of reads a second."""
        t = time.perf_counter()
        try:
            fd = int(syscall.retval)
            if fd < 0:
                return
            # openat(dirfd, path, ...) vs open(path, ...): the path is the
            # first pointer-shaped argument, so take it by prototype position
            # rather than by guessing the syscall's shape.
            path_ptr = args[1] if proto.name.endswith("openat") else args[0]
            name = yield from plugins.mem.read_str(int(path_ptr))
            k = self._key(syscall, fd)
            if k is not None and name:
                self._fdmap[k] = name
                self.n_opens += 1
        except Exception as e:                              # noqa: BLE001
            if len(self.cache_errors) < 5:
                self.cache_errors.append(f"open hook: {e!r}")
        finally:
            self._phase("open (portal, rare)", time.perf_counter() - t)

    def on_close(self, regs, proto, syscall, fd):
        """Forgetting is the load-bearing half. The dynamic loader closes fd 3
        and the victim's own open() is handed 3 back inside the same process;
        a map that never forgets would hand back libgcc_s.so.1 forever."""
        k = self._key(syscall, fd)
        if k is not None and self._fdmap.pop(k, None) is not None:
            self.n_closes += 1
        return
        yield

    # ---- hooks ------------------------------------------------------------

    def on_read(self, regs, proto, syscall, fd, buf, count):
        if not self._lap_bound:
            # First read, not __init__: plugin load order is config order, so
            # fastloop may not have registered its event yet when this plugin
            # was constructed. One boolean per injection thereafter.
            self._bind_lap()
        rv = int(syscall.retval)
        limit = min(int(count), rv if rv > 0 else int(count))
        if limit <= 0:
            return

        t_enter = time.perf_counter()

        # DISCRIMINATE THE INJECTION POINT. comm_filter alone is not enough:
        # the dynamic loader runs under the victim's comm, so an unfiltered
        # "rewrite every read by this process" clobbers the loader's read of
        # its own ELF headers and the victim never starts. (Observed: attrib
        # run 0, "Error loading shared library libgcc_s.so.1: Exec format
        # error".)
        #
        # The answer comes from the map when the map has it, from the portal
        # when it does not, and from the portal anyway once every
        # `revalidate_every` so that a wrong map is found by this run rather
        # than by whoever reads its numbers.
        k = self._key(syscall, fd) if self.fast else None
        cached = self._fdmap.get(k) if k is not None else None
        due = self.fast and self.n_sent % self.revalidate_every == 0
        if cached is not None and not due:
            name = cached
            self.n_fd_cached += 1
            # Kept counted on both paths so the "fd names seen" control still
            # describes every read, not just the ones that paid a round trip.
            self._fdnames[name] = self._fdnames.get(name, 0) + 1
        else:
            t = time.perf_counter()
            try:
                name = (yield from plugins.osi.get_fd_name(fd)) or "?"
            except Exception:
                name = "?"
            self._phase("resolve_fd (portal)", time.perf_counter() - t)
            self.n_fd_resolved += 1
            if cached is not None:
                self.n_revalidated += 1
                if name == "?":
                    # THE AUDIT COULD NOT LOOK, which is not the same as the
                    # map being wrong, and the first version of this check
                    # conflated them: get_fd_name() came back empty twice in
                    # 145,215 reads and both were reported as a corrupt map on
                    # a run whose map was fine. An instrument that fails its
                    # own control has said nothing in either direction -- the
                    # same distinction the fork oracle draws between -1 pages
                    # and 0 pages.
                    self.n_audit_blind += 1
                elif cached != name:
                    self._cache_wrong(
                        f"fd {fd} was mapped to {cached!r} and the guest "
                        f"resolves it to {name!r} at seq {self.seq}")
            elif self.fast and k is not None and name != "?":
                # Learned the slow way (a dup, or an fd already open when this
                # plugin loaded); remembered so it is paid once.
                self._fdmap[k] = name
            self._fdnames[name] = self._fdnames.get(name, 0) + 1
        if not name.endswith(self.fd_suffix):
            self.n_skipped += 1
            return

        t = time.perf_counter()
        payload = self.make_payload(self.seq, limit)
        if not payload:
            return
        self._phase("generate", time.perf_counter() - t)

        t = time.perf_counter()
        yield from plugins.mem.write_bytes(buf, payload)
        syscall.retval = len(payload)
        self._phase("inject (portal)", time.perf_counter() - t)

        # THE PID, FROM THE EVENT. The driver denormalizes current->pid into
        # every syscall_event precisely so the host need not make an OSI_PROC
        # round trip for it, and its header says so. Trusted only after it has
        # been checked against the expensive answer `verify_first` times -- a
        # field that is present and means something ELSE (a tgid, say, where
        # signal_deliver reports a thread id) would silently break the join
        # between an input and the crash it caused, and nothing downstream
        # could notice.
        if self.pid_from_event and not due:
            pid = int(syscall.pid)
        else:
            t = time.perf_counter()
            pid = None
            try:
                proc = yield from plugins.osi.get_proc()
                pid = int(proc.pid)
            except Exception:
                pid = None
            self._phase("resolve_pid (portal)", time.perf_counter() - t)
            if self.fast and pid is not None:
                try:
                    ev_pid = int(syscall.pid)
                except Exception:                           # noqa: BLE001
                    ev_pid = None
                self.n_pid_checked += 1
                if ev_pid == pid:
                    self.n_pid_agree += 1
                elif self.pid_from_event:
                    self._cache_wrong(
                        f"syscall_event.pid is {ev_pid} and get_proc() says "
                        f"{pid} at seq {self.seq}")
                    self.pid_from_event = False
                if (self.pid_from_event is None
                        and self.n_pid_checked >= self.verify_first):
                    self.pid_from_event = (
                        self.n_pid_agree == self.n_pid_checked)
                    self.logger.info(
                        f"bugbench: syscall_event.pid agreed with get_proc() "
                        f"on {self.n_pid_agree}/{self.n_pid_checked} "
                        f"injections; "
                        + ("using it and dropping the round trip"
                           if self.pid_from_event else
                           "NOT using it -- the round trip stays"))

        t = time.perf_counter()
        # The payload itself, not a digest of it. sha256 and head_hex are only
        # ever read on a crash row or in the final dump, so hashing every input
        # on the vCPU thread buys nothing: 99.6% of these records are discarded
        # having never been looked at. Computed lazily in _digest().
        rec = {
            "seq": self.seq,
            "pid": pid,
            "comm": self.comm,
            # The iteration this input belongs to. None when nothing is
            # resetting the guest, which is the honest answer: without a
            # rewind there are no independent executions to scope to.
            "lap": self.lap,
            "len": len(payload),
            "payload": payload,
            "t": round(t - self.p0, 3),
        }
        # WRITE EVERY INPUT, UP TO A POINT. Under a snapshot loop this hook
        # fires ~1,400 times a second, and one file per input is ~1,400
        # creations a second in the directory the run is being measured from --
        # the harness would become the thing being measured. So: the first
        # `corpus_max` go to disk unconditionally (that is the reproducible
        # corpus), and past that the payload is kept in a small in-memory ring
        # and written out only if it turns out to have crashed the victim.
        # Nothing that produces a crash is ever lost; what is dropped is the
        # 99.6% of inputs that did nothing, which no one replays.
        if self.seq < self.corpus_max:
            self._write_corpus(self.seq, payload)
        else:
            self.recent[self.seq] = payload
            if len(self.recent) > self.recent_max:
                self.recent.pop(next(iter(self.recent)))
        self.n_sent += 1
        self.sent.append(rec)
        self._lap_rec = rec
        self._lap_inputs += 1
        if pid is not None:
            self.last_by_pid[pid] = rec
        self.seq += 1
        self._phase("bookkeeping", time.perf_counter() - t)
        self._phase("on_read total", time.perf_counter() - t_enter)

    def _cache_wrong(self, why):
        """Not a warning. A wrong fd injects into the wrong descriptor and a
        wrong pid attributes a crash to an input that process never received;
        either way the run keeps producing plausible numbers about something
        else. Recorded as an error and reported in the verdict line."""
        self.logger.error(
            f"bugbench: CACHE WRONG - {why}. Dropping the map and resolving "
            f"through the guest again; inputs delivered since the last audit "
            f"may have gone to the wrong descriptor.")
        self.cache_errors.append(why)
        self._fdmap.clear()

    @staticmethod
    def _digest(rec):
        p = rec.get("payload")
        if p is None:
            return rec.get("sha256"), rec.get("head_hex")
        return hashlib.sha256(p).hexdigest(), p[:16].hex()

    def _write_corpus(self, seq, payload):
        with open(join(self.corpus_dir, f"{seq:06d}.bin"), "wb") as fh:
            fh.write(payload)
        self.on_disk.add(seq)

    def on_signal_deliver(self, cpu, event):
        t_enter = time.perf_counter()
        sig = int(event.sig)
        signame = self.signames.get(sig)
        if signame is None or event.drop:
            return
        pid = int(event.pid)
        pid_rec = self.last_by_pid.get(pid)
        # PREFER THE LAP, AND CHECK THE OTHER ONE AGAINST IT.
        #
        # The lap join is exact by construction when a lap delivered exactly
        # one input: the crash happened between two rewinds and only one input
        # was injected between them, so there is nothing to guess. The pid join
        # is a heuristic -- "the last input this pid saw" -- that happens to be
        # right most of the time and was silently wrong for 2,786 consecutive
        # inputs once. Both are computed whenever both exist, precisely so the
        # weaker one stops being trusted on faith.
        if self.lap is not None:
            # AUTHORITATIVE, INCLUDING WHEN IT SAYS NOTHING. A lap that
            # crashed before any input reached the victim has no input to
            # blame, and `last_by_pid` still holds the PREVIOUS lap's -- an
            # input this execution never received. Falling back to the pid
            # join here would reintroduce, at the only moment it matters,
            # exactly the misattribution the boundary exists to remove. (The
            # first draft of this did fall back, and the test below caught
            # it naming seq 1 for a crash in lap 2.)
            rec, join = self._lap_rec, "lap"
            exact = rec is not None and self._lap_inputs == 1
            if rec is not None:
                self.n_join_lap += 1
                if pid_rec is not None and pid_rec["seq"] != rec["seq"]:
                    self.n_join_disagree += 1
        else:
            rec, join = pid_rec, "last-input-to-pid"
            exact = pid_rec is not None and event.comm == self.comm
            if pid_rec is not None:
                self.n_join_pid += 1
        pc = int(event.pc)
        if pc == 0 and event.regs:
            pc = event.regs.get_pc()
        row = {
            "proc": event.comm,
            "pid": pid,
            "signal": sig,
            "signame": signame,
            "t": round(t_enter - self.p0, 3),
            "pc": f"0x{pc:08x}",
            "attributed": rec is not None,
            "join": join,
            "join_exact": exact,
            "lap": self.lap,
            "lap_inputs": self._lap_inputs if self.lap is not None else None,
        }
        if rec is not None:
            # The input that crashed it always goes to disk, whatever the cap.
            sq = rec["seq"]
            if sq not in self.on_disk and sq in self.recent:
                self._write_corpus(sq, self.recent[sq])
            sha, head = self._digest(rec)
            row.update({
                "input_seq": rec["seq"],
                "input_sha256": sha,
                "input_len": rec["len"],
                "input_head_hex": head,
                "input_file": f"corpus/{rec['seq']:06d}.bin",
                "input_to_crash_ms": round((row["t"] - rec["t"]) * 1000.0, 1),
            })
            self.logger.info(
                f"bugbench: {signame} in {event.comm} (pid {pid}) at {row['pc']} "
                f"<- input seq={rec['seq']} sha256={sha[:16]} "
                f"({row['input_to_crash_ms']} ms after delivery)")
        else:
            self.logger.warning(
                f"bugbench: {signame} in {event.comm} (pid {pid}) at {row['pc']} "
                "- UNATTRIBUTED: no input was ever delivered to this pid")
        self.attributed.append(row)
        # APPEND ONE LINE. Throttling the YAML rewrite was the previous fix and
        # it was only half of one: re-dumping the whole growing list every
        # `report_every` crashes is O(n^2/report_every), and a snapshot loop
        # makes a crash an ordinary event. Measured, run 31: 1,802 crashes,
        # 13.75 ms mean inside this callback, 24.8 s of a 220 s loop -- and the
        # cost grows with the crash count, which is why the crash lap read
        # 22.5 ms over 54 crashes and 66.2 ms over 1,482.
        #
        # It happens on the vCPU thread, and a bottom half cannot run while
        # that thread is busy, so every millisecond here is a millisecond the
        # reset is not being serviced. One appended line is O(1), durable the
        # same way the periodic dump was meant to be, and the YAML is written
        # once from the accumulated list in uninit().
        if self._jsonl is not None:
            try:
                self._jsonl.write(json.dumps(row) + "\n")
            except Exception:                               # noqa: BLE001
                self._jsonl = None
        self._phase("signal_deliver", time.perf_counter() - t_enter)

    # ---- report -----------------------------------------------------------

    def write_report(self):
        with open(join(self.outdir, "crashes_attributed.yaml"), "w") as fh:
            yaml.safe_dump({
                "comm": self.comm,
                "inputs_delivered": self.n_sent,
                "crashes": self.attributed,
            }, fh, sort_keys=False)

    def uninit(self):
        if self._jsonl is not None:
            try:
                self._jsonl.close()
            except Exception:                               # noqa: BLE001
                pass
            self._jsonl = None
        self.write_report()
        # SNAPSHOT FIRST. uninit() runs on the timeout thread while the vCPU
        # thread is still injecting, so iterating the live ring raises
        # "deque mutated during iteration" and loses the whole report. The
        # race predates the deque -- a list was being iterated too, it just
        # failed silently by dropping entries instead of raising.
        rows = []
        for rec in list(self.sent):
            sha, head = self._digest(rec)
            rows.append({k: v for k, v in rec.items() if k != "payload"}
                        | {"sha256": sha, "head_hex": head})
        with open(join(self.outdir, "bugbench_inputs.yaml"), "w") as fh:
            yaml.safe_dump({"inputs_delivered": self.n_sent,
                            "inputs_retained": len(rows),
                            "inputs": rows}, fh, sort_keys=False)
        phases = self._phases_out()
        with open(join(self.outdir, "bugbench_cost.yaml"), "w") as fh:
            yaml.safe_dump({
                "fast": self.fast,
                "fast_rng": self.fast_rng,
                "corpus_max": self.corpus_max,
                "inputs_delivered": self.n_sent,
                "fd_from_map": self.n_fd_cached,
                "fd_from_portal": self.n_fd_resolved,
                "opens_learned": self.n_opens,
                "closes_forgotten": self.n_closes,
                "pid_from_event": self.pid_from_event,
                "pid_cross_checked": self.n_pid_checked,
                "pid_agreed": self.n_pid_agree,
                "revalidations": self.n_revalidated,
                "audits_blind": self.n_audit_blind,
                "join_by_lap": self.n_join_lap,
                "join_by_pid": self.n_join_pid,
                "join_disagreed": self.n_join_disagree,
                "laps_with_multiple_inputs": self.lap_multi,
                "cache_errors": self.cache_errors,
                "phases": phases,
            }, fh, sort_keys=False)
        n_att = sum(1 for r in self.attributed if r["attributed"])
        self.logger.info(
            f"bugbench: RESULTS inputs={self.n_sent} "
            f"crashes={len(self.attributed)} attributed={n_att} "
            f"reads_skipped_wrong_fd={self.n_skipped}   <- CONTROL")
        if self.n_join_lap:
            self.logger.info(
                f"bugbench: JOIN by_lap={self.n_join_lap} "
                f"by_pid={self.n_join_pid} disagreed={self.n_join_disagree} "
                f"laps_with_multiple_inputs={self.lap_multi}   <- CONTROL")
        if self.n_join_disagree:
            # Stated as a result, not a warning. Every run in this lane before
            # the lap boundary existed used the pid join alone and had no way
            # to know; this is the first number that can say how often it was
            # naming the wrong input.
            self.logger.warning(
                f"bugbench: the pid join named a DIFFERENT input than the lap "
                f"join on {self.n_join_disagree} of {self.n_join_lap} crashes "
                f"({self.n_join_disagree / self.n_join_lap:.1%}). The lap join "
                f"was used. Earlier runs of this harness had only the pid "
                f"join and reported that fraction as fact.")
        self.logger.info(f"bugbench: fd names seen: {self._fdnames}   <- CONTROL")
        tot = phases.get("on_read total", {}).get("mean_us")
        self.logger.info(
            f"bugbench: COST per injection {tot} us total; "
            + "  ".join(f"{k}={v['mean_us']}us" for k, v in phases.items()))
        if self.fast:
            self.logger.info(
                f"bugbench: MAP fd_from_map={self.n_fd_cached} "
                f"fd_from_portal={self.n_fd_resolved} opens={self.n_opens} "
                f"closes={self.n_closes} revalidations={self.n_revalidated} "
                f"audits_blind={self.n_audit_blind} "
                f"pid_from_event={self.pid_from_event} "
                f"pid_agreed={self.n_pid_agree}/{self.n_pid_checked} "
                f"errors={len(self.cache_errors)}   <- CONTROL")
            if self.cache_errors:
                self.logger.error(
                    f"bugbench: the fd map or the event pid disagreed with the "
                    f"guest {len(self.cache_errors)} times. Inputs delivered "
                    f"between audits may have gone to the wrong descriptor, so "
                    f"this run's corpus and its rate are both suspect: "
                    f"{self.cache_errors[:3]}")
            elif self.n_fd_cached < 0.9 * (self.n_fd_cached + self.n_fd_resolved):
                self.logger.warning(
                    f"bugbench: fast was requested and only "
                    f"{self.n_fd_cached} of "
                    f"{self.n_fd_cached + self.n_fd_resolved} reads were "
                    f"answered from the map, so this run mostly paid the full "
                    f"per-lap cost whatever the config says.")
        if not self.n_sent:
            self.logger.error(
                "bugbench: CONTROL FAILED - zero inputs delivered; this run "
                f"says nothing about comm={self.comm!r}.")
