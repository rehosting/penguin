"""Pin the guest's clock to the snapshot, and collapse the waits it causes.

WHY THIS EXISTS
---------------
This lane's rule, learned twice and from opposite directions:

    Anything a replay depends on must be rewound with the guest.

The driver pin's counters were rewound while the reader assumed they were not
(`fastloop`, commit 22716298). `snapfeed`'s per-fd feed count was NOT rewound
while the guest assumed it was (commit 29aae4b5). After both fixes the clock is
the most conspicuous thing a replayed span still depends on and still does not
get back: `LOOP_RESET` restores guest RAM and devices, and the wall clock the
guest reads through `gettimeofday`/`clock_gettime` keeps running forward.

So the same span, replayed, sees a later time than it did on the traversal it
is being compared against. A victim that computes a deadline, ages a cache,
stamps a log line, or expires a session sees something different every lap --
divergence manufactured by the harness, in exactly the class the fidelity check
exists to catch.

WHAT IT DOES
------------
Two interventions, separately switchable, because they answer different
problems and only one of them is about speed:

  pin_time        gettimeofday / clock_gettime / time answer from a virtual
                  clock that is rewound by `on_lap`. FIDELITY: every replay of
                  a span reads the same instants the first traversal did.

  collapse_sleep  nanosleep / clock_nanosleep / alarm return immediately.
                  SPEED, and only the kind that pays -- see the rule below.

THE RULE THAT DECIDES WHAT BELONGS HERE
---------------------------------------
    A host-side hook pays for itself when it removes WAITING.
    It loses money when it removes COMPUTING.

Measured, in both directions. `swallow_writes` -- which unblocks a write --
was worth 28x. The input feeding beside it was noise. And the cost side is now
quantified too: a full-system iteration of this lane's victim costs 111 us
against 0.9 us for the same work under qemu-user (`USERMODE.md`), ~123x, and
almost none of that is instruction emulation. It is the emulated kernel
answering the syscall, plus penguin's own per-hook hypercall into Python. A
hook therefore adds a round trip ON TOP of an already expensive syscall, so
skipping a cheap computation is a net loss. Sleeps and blocking waits are the
cases where the arithmetic works, which is why this file stops at those.

WHY THE CLOCK TICKS INSTEAD OF FREEZING
---------------------------------------
A frozen clock wedges any guest that waits for time to pass:

    deadline = time(NULL) + 1;
    while (time(NULL) < deadline) { ... }        /* never terminates */

So the virtual clock advances `tick_us` per observed call and the call counter
is what `on_lap` rewinds. Within a lap it is monotonic, so deadline loops
terminate; across laps it is identical, so the replay matches. Both properties
are needed and freezing gives only the second.

`tick_us` is a real trade-off with no free setting. Too large and virtual time
races ahead of the work, tripping the guest's own timeouts. Too small and a
deadline loop spins for many more iterations before it exits. It errs small.

CONTROLS
--------
A plugin that silently does nothing looks exactly like a target that never
asked, and this lane has already spent runs on that failure. So every hook
counts, `uninit` reports, and the two ways this can be quietly wrong are
named rather than inferred:

  n_time == 0          nothing asked for the time. Either the victim really
                       does not, or `comm` is wrong -- the same mistake that
                       made a select() handler fire zero times on target B.
  lap_subscribed False  the clock is NOT rewound. Pinning without rewinding is
                       worse than not pinning, because it looks pinned.
"""

import struct

from penguin import Plugin, plugins

syscalls = plugins.syscalls

USEC = 1_000_000
NSEC = 1_000_000_000


class TimePin(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"

        # `x or default` is wrong for any arg whose meaningful value is 0.
        # snapfeed shipped that bug and `mutate: 0` could not turn mutation
        # off at all; the same helper is used here for the same reason.
        self.pin_time = bool(int(self._arg("pin_time", 1)))
        self.collapse_sleep = bool(int(self._arg("collapse_sleep", 1)))

        # Seconds since the epoch the virtual clock starts from. 0 means "take
        # the host's clock once, now". A fixed value is reproducible across
        # runs; the host's is realistic, which matters to a guest that checks
        # certificate validity or file mtimes. Neither is right for everyone,
        # so the choice is explicit and recorded.
        base_s = float(self._arg("base_s", 0))
        if base_s <= 0:
            import time as _time
            base_s = _time.time()
            self.base_is_captured = True
        else:
            self.base_is_captured = False
        self.base_us = int(base_s * USEC)

        self.tick_us = int(self._arg("tick_us", 1000))

        # A collapsed sleep turns a waiting guest into a spinning one. That is
        # the trade this plugin exists to make, but it must not become
        # unbounded: a retry loop whose sleep is collapsed and whose condition
        # never becomes true would spin at 100% for the whole lap instead of
        # waiting quietly. Past this many collapses in one lap, sleeps are let
        # through and the run says so.
        self.max_collapse = int(self._arg("max_collapse", 10000))

        # struct timeval / timespec are two words. 4-byte words on every
        # target in this lane; the 64-bit-time_t variants are a separate
        # syscall (clock_gettime64) and are hooked separately when present.
        self.word = int(self._arg("word", 4))
        self.endian = self._arg("endian", "<")
        self.pin_filter = bool(int(self._arg("pin_filter", 0)))

        self.n_calls = 0          # virtual-clock advances THIS LAP
        self.n_sleep_lap = 0      # sleeps collapsed THIS LAP, against the cap
        self.n_time = 0           # CONTROL: time answered, whole run
        self.n_sleep = 0          # sleeps collapsed
        self.n_sleep_pass = 0     # CONTROL: sleeps left alone (cap, or off)
        self.n_lap_resets = 0     # laps that rewound the virtual clock
        self.n_unwritable = 0     # CONTROL: struct writes that failed

        pf = self.pin_filter
        if self.pin_time:
            syscalls.syscall("on_sys_gettimeofday_enter", comm_filter=self.comm,
                             pin_filter=pf)(self.on_gettimeofday)
            syscalls.syscall("on_sys_clock_gettime_enter", comm_filter=self.comm,
                             pin_filter=pf)(self.on_clock_gettime)
            # Optional by architecture. `time` is not a syscall everywhere --
            # several ABIs route it through gettimeofday or the vDSO -- and
            # clock_gettime64 exists only on 32-bit kernels new enough to have
            # a 64-bit time_t path. Registering one that does not exist must
            # not take the plugin down with it.
            self._optional("on_sys_time_enter", self.on_time, pf)
            self._optional("on_sys_clock_gettime64_enter",
                           self.on_clock_gettime64, pf)
        if self.collapse_sleep:
            syscalls.syscall("on_sys_nanosleep_enter", comm_filter=self.comm,
                             pin_filter=pf)(self.on_nanosleep)
            syscalls.syscall("on_sys_clock_nanosleep_enter", comm_filter=self.comm,
                             pin_filter=pf)(self.on_clock_nanosleep)
            self._optional("on_sys_alarm_enter", self.on_alarm, pf)

        # Follow the loop's rewinds, when there is a loop. Optional because
        # this plugin is useful without fastsnap -- collapse_sleep alone needs
        # no snapshot -- but a MISSING subscription while pin_time is on is
        # the dangerous case and is warned about, not merely recorded.
        try:
            plugins.subscribe(plugins.fastloop, "on_lap", self.on_lap)
            self.lap_subscribed = True
        except Exception as e:                              # noqa: BLE001
            self.lap_subscribed = False
            if self.pin_time:
                self.logger.warning(
                    f"timepin: pin_time is on but the lap event is not "
                    f"available ({e!r}), so the virtual clock is NOT rewound "
                    f"with the guest. Every lap will read a later time than "
                    f"the one before it -- the divergence this plugin exists "
                    f"to remove, wearing the costume of a fix.")

        self.logger.info(
            f"timepin: armed on comm={self.comm!r}, pin_time={self.pin_time} "
            f"(base {'captured' if self.base_is_captured else 'fixed'} at "
            f"{self.base_us / USEC:.3f}, tick {self.tick_us} us), "
            f"collapse_sleep={self.collapse_sleep} (cap {self.max_collapse}/lap)")

    # ---- helpers ----------------------------------------------------------

    def _arg(self, name, default):
        v = self.get_arg(name)
        return default if v is None or v == "" else v

    def _optional(self, hook, fn, pf):
        """Register a hook whose syscall may not exist on this architecture."""
        try:
            syscalls.syscall(hook, comm_filter=self.comm, pin_filter=pf)(fn)
        except Exception as e:                              # noqa: BLE001
            self.logger.debug(f"timepin: {hook} unavailable ({e!r})")

    def _pack(self, a, b):
        """struct timeval/timespec: two words, guest byte order."""
        fmt = self.endian + ("i" if self.word == 4 else "q") * 2
        return struct.pack(fmt, a, b)

    def _advance(self):
        """The virtual clock, in microseconds. Monotonic within a lap,
        identical across replays of one, because `n_calls` is what `on_lap`
        rewinds."""
        us = self.base_us + self.tick_us * self.n_calls
        self.n_calls += 1
        return us

    def on_lap(self, plugin=None, event=None, *a):
        """The loop rewound the guest; rewind the clock it reads.

        Without this the plugin pins the clock to a value that still advances
        monotonically across laps, which is the original problem with extra
        steps. The collapse budget is per-lap for the same reason: a lap that
        exhausted it must not hand a spent budget to the next one."""
        self.n_calls = 0
        self.n_sleep_lap = 0
        self.n_lap_resets += 1

    # ---- the clock --------------------------------------------------------

    def on_gettimeofday(self, regs, proto, syscall, tv, tz, *a):
        us = self._advance()
        if int(tv):
            yield from self._write(int(tv), us // USEC, us % USEC)
        syscall.retval = 0
        syscall.skip_syscall = True
        self.n_time += 1

    def on_clock_gettime(self, regs, proto, syscall, clk, tp, *a):
        us = self._advance()
        if int(tp):
            yield from self._write(int(tp), us // USEC, (us % USEC) * 1000)
        syscall.retval = 0
        syscall.skip_syscall = True
        self.n_time += 1

    def on_clock_gettime64(self, regs, proto, syscall, clk, tp, *a):
        """Same answer, 64-bit fields regardless of the target's word size."""
        us = self._advance()
        if int(tp):
            data = struct.pack(self.endian + "qq", us // USEC, (us % USEC) * 1000)
            yield from self._write_raw(int(tp), data)
        syscall.retval = 0
        syscall.skip_syscall = True
        self.n_time += 1

    def on_time(self, regs, proto, syscall, tloc, *a):
        us = self._advance()
        secs = us // USEC
        if int(tloc):
            fmt = self.endian + ("i" if self.word == 4 else "q")
            yield from self._write_raw(int(tloc), struct.pack(fmt, secs))
        syscall.retval = secs
        syscall.skip_syscall = True
        self.n_time += 1

    # ---- the waits --------------------------------------------------------

    def _collapsing(self):
        if not self.collapse_sleep:
            return False
        if self.n_sleep_lap >= self.max_collapse:
            return False
        return True

    def on_nanosleep(self, regs, proto, syscall, req, rem, *a):
        if not self._collapsing():
            self.n_sleep_pass += 1
            return
        # A collapsed sleep slept for nothing, so nothing REMAINS. Leaving the
        # remainder untouched would hand back whatever the guest happened to
        # have there and a retry loop would sleep on garbage.
        if int(rem):
            yield from self._write(int(rem), 0, 0)
        syscall.retval = 0
        syscall.skip_syscall = True
        self._tally_sleep()

    def on_clock_nanosleep(self, regs, proto, syscall, clk, flags, req, rem, *a):
        if not self._collapsing():
            self.n_sleep_pass += 1
            return
        if int(rem):
            yield from self._write(int(rem), 0, 0)
        syscall.retval = 0
        syscall.skip_syscall = True
        self._tally_sleep()

    def on_alarm(self, regs, proto, syscall, seconds, *a):
        if not self._collapsing():
            self.n_sleep_pass += 1
            return
            yield
        # alarm() returns the seconds left on any previous alarm. Zero is both
        # the honest answer once no alarm is being armed and the one that will
        # not make the guest think it pre-empted a pending timer.
        syscall.retval = 0
        syscall.skip_syscall = True
        self._tally_sleep()

    def _tally_sleep(self):
        self.n_sleep += 1
        self.n_sleep_lap += 1

    # ---- memory -----------------------------------------------------------

    def _write(self, addr, a, b):
        yield from self._write_raw(addr, self._pack(a, b))

    def _write_raw(self, addr, data):
        """A failed write must not leave the syscall skipped with a stale
        buffer -- the guest would read whatever was there and call it the
        time. Counted, so a run where this happens cannot look clean."""
        try:
            yield from plugins.mem.write_bytes(addr, data)
        except Exception:                                   # noqa: BLE001
            self.n_unwritable += 1
            raise

    # ---- report -----------------------------------------------------------

    def uninit(self):
        self.logger.info(
            f"timepin: time answered {self.n_time}, sleeps collapsed "
            f"{self.n_sleep} (passed {self.n_sleep_pass}), laps rewound "
            f"{self.n_lap_resets}, unwritable {self.n_unwritable}")
        if self.pin_time and self.n_time == 0:
            self.logger.warning(
                f"timepin: pin_time was on and NOTHING asked for the time. "
                f"Either the victim does not, or comm={self.comm!r} never "
                f"matched -- the same way a select() handler fired zero times "
                f"on target B while the victim blocked in epoll_wait.")
        if self.pin_time and not self.lap_subscribed:
            self.logger.warning(
                "timepin: the clock was pinned but never rewound; treat any "
                "fidelity result from this run as unmeasured.")
