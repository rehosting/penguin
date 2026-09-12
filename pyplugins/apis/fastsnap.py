"""
.. include:: /docs/fastsnap.md
   :parser: myst_parser.sphinx_

Fastsnap Plugin (fastsnap.py) for Penguin
=========================================

A fast in-process guest reset: rewind the machine to a recorded instant in a
few hundred microseconds instead of the tens of milliseconds a savevm/loadvm
round trip costs, so a fuzzing or search loop can run thousands of iterations
per second without restarting a process.

What it is for
--------------

Iterating the same code path in a booted guest many times from the same state:
fuzzing a parser, sweeping inputs through a handler, re-running one request
under different conditions. A reset puts back the device state and every RAM
page written since the arm; the guest continues from the armed instant with no
memory of the iteration.

The shape of the API, and why it is this shape
----------------------------------------------

Every operation runs in a QEMU bottom half on the main loop, while your plugin
callback runs on a vCPU thread. **Scheduling is not doing.** Blocking on
completion from a vCPU callback deadlocks, so every call here returns a
:class:`Ticket` and you poll it from a later callback::

    t = plugins.fastsnap.arm()
    ...                                 # on a later hook
    if t.done():
        r = t.result()

The ticket exists to make one specific mistake impossible. The completion test
is ``seq() > seq_at_schedule``, and capturing that sequence number *after*
scheduling rather than before produces a loop that reads results from an
operation that has not run -- timings from the previous op, a diff from the
previous lap -- and every number it reports looks plausible. The ticket
captures it in the right order once, here, instead of in every caller.

The arming point is yours, deliberately
---------------------------------------

Nothing in this plugin decides when to arm, and that is not an omission. An
iteration costs the span from the armed instant to the next detector hit,
because that is exactly what a reset rewinds -- so arming "at the next
convenient callback" draws a random sample from that detector's interval
distribution. Measured on real firmware the difference between a well-chosen
and a blind arming point was **29x**, larger than any other factor in this
mechanism, including the reset itself. Arm where the guest is about to do the
work you want to repeat, and not before.

Scoping the device block
------------------------

The device half of a reset is the expensive half. :meth:`scope` narrows it:

* ``deny`` leaves named sections out. Conservative: a device nobody named is
  still restored. The default (``auto``) denies virtio, which is a correctness
  requirement rather than a tuning choice -- a virtio device's state is split
  between the model and a vring in guest RAM plus a host-side backend that is
  not part of the guest at all.
* ``allow`` keeps *only* the named sections. Measured, a full 17-section block
  restores in 0.752 ms and ``{cpu, timer}`` in 0.043 ms. It is also the only
  setting here whose failure mode is silence: a section left out is not
  restored, nothing errors, and the guest misbehaves thousands of iterations
  later with nothing pointing back.

So an allowlist should be run with verification on. ``result()["dev_sections"]``
counts the device sections that did **not** come back, by name -- against a
reference covering the full section set, whatever the block was scoped to.

Checking that the reset is actually correct
-------------------------------------------

``reset(verify=True)`` runs two independent oracles in the same bottom half as
the reset, so nothing executes in between and any difference found is the
reset's rather than the guest's:

* a **fork oracle** for RAM -- a child forked at the arm, parked in ``pause()``,
  read back with ``process_vm_readv()`` and compared page by page. It shares no
  code with the restore, which reads an in-process copy, so neither can launder
  the other's mistakes.
* the **per-section device oracle** described above.

Verification reads all of guest RAM back and costs roughly 80x the reset, so
verify on a schedule (every Nth iteration), not every lap. ``reset_us`` is
always the reset alone; the oracle's cost is reported separately as
``diff_us``. Conflating them would make every verified reset look two orders of
magnitude more expensive while looking entirely plausible.

Read the negatives
------------------

``diff_pages`` and ``dev_sections`` are ``-1`` when the oracle could not look --
a failed read, no reference. That is **not** zero, and treating it as a pass is
how an instrument that reports success when it is blind gets believed.

Example
-------

.. code-block:: python

    from penguin import plugins

    class MyLoop(Plugin):
        def __init__(self):
            missing = plugins.fastsnap.missing_symbols()
            if missing:
                raise RuntimeError(f"stale QEMU image, missing: {missing}")
            self.ticket = None
            self.n = 0

        @syscalls.syscall("on_sys_read_enter")
        def on_read(self, regs, proto, sc, *args):
            if self.ticket is None:                 # arm once, where it counts
                self.ticket = plugins.fastsnap.arm()
                return
            if not self.ticket.done():
                return
            self.n += 1
            r = self.ticket.result()
            if r["diff_pages"] > 0:
                self.logger.error(f"reset left {r['diff_pages']} pages wrong")
            self.ticket = plugins.fastsnap.reset(verify=(self.n % 50 == 0))
"""

from typing import Any, Dict, List, Optional

from pydantic import Field

from penguin import Plugin, PluginArgs


class Ticket:
    """One scheduled fastsnap operation, and the only way to read its result.

    Holds the sequence number captured BEFORE the operation was scheduled. That
    ordering is the entire point of the class: ``seq()`` is bumped when a bottom
    half finishes, so a caller that reads it after scheduling can observe a
    value that already satisfies its own completion test and will then read
    timings and diffs belonging to the previous operation.
    """

    __slots__ = ("_fs", "op", "_seq_before", "_result")

    def __init__(self, fs: "Fastsnap", op: int, seq_before: int):
        self._fs = fs
        self.op = op
        self._seq_before = seq_before
        self._result = None

    def done(self) -> bool:
        """Has the bottom half run? Safe to call from a vCPU callback."""
        return self._fs.panda.fastsnap_seq() > self._seq_before

    def result(self) -> Dict[str, Any]:
        """Everything the completed operation reported.

        Latched on first call: the accessors are single-slot and a later
        operation overwrites them, so a ticket read after the next reset would
        otherwise silently return that one's numbers.

        Raises if the operation has not completed -- the alternative is
        returning the previous operation's values, which is indistinguishable
        from a real answer.
        """
        if self._result is not None:
            return self._result
        if not self.done():
            raise RuntimeError(
                f"fastsnap: result() for op {self.op} before its bottom half "
                f"ran. Poll done() from a later callback; blocking here would "
                f"deadlock, and returning now would hand you the previous "
                f"operation's numbers.")
        self._result = self._fs._read_result(self.op)
        return self._result


class Fastsnap(Plugin):
    """Fast in-process guest reset. See the module docstring."""

    class Args(PluginArgs):
        allow: Optional[str] = Field(
            default=None,
            description=(
                "Comma-separated device section ids to keep in the block, and "
                "ONLY those. The largest lever on reset cost and the only one "
                "whose failure is silent -- run it with verify on. Mutually "
                "exclusive with deny."))
        deny: Optional[str] = Field(
            default="auto",
            description=(
                "Comma-separated device section ids to leave out of the block. "
                "'auto' (the default) denies every virtio section, which is a "
                "correctness requirement, not a tuning choice."))

    # The op numbers are an implementation detail of the QEMU side and are not
    # part of this plugin's interface; callers use the methods below.
    _TAKE = 0
    _RESTORE = 1
    _RELEASE = 2
    _STATE_DIGEST = 5
    _FORK_DIFF = 7
    _FORK_DROP = 8
    _LOOP_ARM = 15
    _LOOP_RESET = 16
    _LOOP_RESET_VERIFY = 17

    def __init__(self):
        self._scoped = False
        missing = self.missing_symbols()
        if missing:
            # Loud at load, not at first use. The failure this guards against
            # is an image whose QEMU predates part of the ABI: the bindings are
            # all importable, the calls all return defaults, and the run
            # produces a complete and entirely fictional result set. It has
            # happened once, to eleven of these symbols at the same time.
            self.logger.error(
                f"fastsnap: this QEMU image does not export {len(missing)} of "
                f"the symbols this plugin calls: {missing}. Rebuild the image "
                f"against a matching qemu_builder tree; every reset scheduled "
                f"against this build would silently do nothing.")

    # -- availability -------------------------------------------------------

    def available(self) -> bool:
        """Whether this QEMU build has the fastsnap ABI at all."""
        try:
            return not self.missing_symbols()
        except Exception:                                   # noqa: BLE001
            return False

    def missing_symbols(self) -> List[str]:
        """Symbols this plugin needs that the image does not export.

        Check this before a run rather than after: a missing symbol reads as a
        plausible default at every call site downstream.
        """
        return list(self.panda.fastsnap_missing_symbols())

    def sections(self) -> List[str]:
        """Every device section a block would cover on this machine.

        Ids are NOT unique -- some machines register two sections with the same
        name, distinguished only by an instance id that is not exposed here.
        Both an allowlist and a denylist match by name, so naming one matches
        every section that carries it.
        """
        return list(self.panda.fastsnap_section_names())

    # -- scoping ------------------------------------------------------------

    def scope(self, allow=None, deny=None) -> None:
        """Choose which device sections the block covers. See the module docs.

        Takes effect on the next :meth:`arm`. Names that match no section on
        this machine are refused rather than ignored: an allowlist of typos
        produces an empty block that restores nothing, very quickly, and every
        number from the run would then be a measurement of doing no work.
        """
        if allow and deny:
            raise ValueError(
                "fastsnap: allow and deny are two answers to 'is this section "
                "in the block' and the QEMU side takes exactly one. Picking a "
                "precedence would make the scope depend on argument order.")
        names = self.sections()

        def check(spec):
            wanted = [x.strip() for x in spec.split(",") if x.strip()]
            unknown = [w for w in wanted if w not in names]
            if unknown:
                raise ValueError(
                    f"fastsnap: {unknown} are not device sections on this "
                    f"machine. Available: {names}")
            return wanted

        if allow:
            self.panda.fastsnap_set_allowlist(check(allow))
        elif deny == "auto":
            self.panda.fastsnap_set_denylist(
                [n for n in names if "virtio" in n.lower()])
        elif deny:
            self.panda.fastsnap_set_denylist(check(deny))
        else:
            self.panda.fastsnap_set_denylist([])
        self._scoped = True

    # -- the loop -----------------------------------------------------------

    def _sched(self, op: int) -> Ticket:
        # Captured BEFORE the schedule. See Ticket.
        seq = self.panda.fastsnap_seq()
        self.panda.fastsnap_schedule(op)
        return Ticket(self, op, seq)

    def arm(self) -> Ticket:
        """Record the instant every later reset rewinds to.

        Takes the device block, snapshots RAM with dirty tracking armed, and
        forks the reference oracle -- all in ONE bottom half, because the guest
        executes between bottom halves and a reference taken one operation
        later holds a different instant.

        Applies the configured scope on first use if :meth:`scope` has not been
        called, so the ``deny: auto`` default is in force rather than silently
        absent.
        """
        if not self._scoped:
            self.scope(allow=self.get_arg("allow"), deny=self.get_arg("deny"))
        return self._sched(self._LOOP_ARM)

    def reset(self, verify: bool = False) -> Ticket:
        """Rewind the guest to the armed instant.

        With ``verify``, both oracles run in the same bottom half, after the
        reset and before anything else executes. That costs roughly 80x the
        reset, so schedule it every Nth iteration rather than every one; the
        reset's own time is reported separately either way.
        """
        return self._sched(self._LOOP_RESET_VERIFY if verify
                           else self._LOOP_RESET)

    def release(self) -> Ticket:
        """Drop the fork reference. It holds a copy-on-write copy of guest RAM,
        so a reference left parked is a full extra copy of the guest."""
        return self._sched(self._FORK_DROP)

    def state_digest(self) -> Ticket:
        """Digest the whole guest -- every RAM block, then the device block --
        with the vCPUs stopped.

        Two runs that executed the same thing from the same state must agree
        here. This is the health signal that does not depend on the guest being
        well enough to deliver a signal: a kernel panic leaves userspace crash
        reporting completely unchanged.
        """
        return self._sched(self._STATE_DIGEST)

    # -- results ------------------------------------------------------------

    def _read_result(self, op: int) -> Dict[str, Any]:
        p = self.panda
        r = {
            "op": op,
            "rc": p.fastsnap_last_rc(),
            # The operation's own time, never the oracle's.
            "us": p.fastsnap_last_us(),
        }
        if op == self._LOOP_ARM:
            r["snapshot_bytes"] = p.fastsnap_ram_snapshot_bytes()
            r["block_bytes"] = p.fastsnap_block_size()
            r["digest"] = p.fastsnap_last_digest()
        elif op in (self._LOOP_RESET, self._LOOP_RESET_VERIFY):
            r["restored_pages"] = p.fastsnap_ram_restored_pages()
        if op in (self._LOOP_RESET_VERIFY, self._FORK_DIFF):
            # -1 here means the oracle could not look. Not zero. Callers that
            # treat it as a pass are trusting an instrument that said it was
            # blind.
            r["diff_pages"] = p.fastsnap_diff_pages()
            r["diff_bytes_checked"] = p.fastsnap_diff_bytes_checked()
            r["diff_us"] = p.fastsnap_diff_us()
            r["diff_report"] = p.fastsnap_diff_report()
            r["dev_sections"] = p.fastsnap_dev_diff_sections()
            r["dev_report"] = p.fastsnap_dev_diff_report()
        elif op == self._STATE_DIGEST:
            r["digest"] = p.fastsnap_last_digest()
            r["ram_digest"] = p.fastsnap_last_ram_digest()
        return r
