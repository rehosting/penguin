# Written before the run

Recorded ahead of the first real-firmware loop so the result can be scored
rather than narrated. This lane has twice written a number down after the fact
and found it agreed with a projection that had been quietly adjusted to it; and
once, when a projection was checked against a closed loop for the first time, it
was out by 3.7x (predicted 0.456 ms, measured 1.69 ms). So the predictions
below are committed now, with their reasoning, and the run either matches them
or it does not.

## What is being run

`analysis/fastsnap/fastloop.py`, three arms per target:

    mode=loop    LOOP_ARM once, LOOP_RESET every iteration      the product
    mode=armed   LOOP_ARM once, never reset                     the tracking cost
    mode=bare    neither                                        the floor

`loop - armed` is the reset. `armed - bare` is what arming costs on its own --
QEMU's global dirty log traps every first store to a clean page through
`notdirty_write()`, and that slows the guest whether or not anything is ever
restored. Without the `armed` arm that slowdown lands on the reset's bill.

Two targets, because they differ in the one variable that turns out to matter:

  A. **stride** -- the real firmware image, lighttpd, detector `writev`.
  B. **bugbench** -- the controlled victim, detector `read`, whose main loop is
     `read(); dispatch();` 4096 times over.

## The claim that decides whether this is real

**Every verification reports zero differing pages, while the split-order
control reports more than zero.**

The oracle is a child forked at the armed instant, read back with
`process_vm_readv()` and compared page by page; it shares no code with the
restore, which reads an in-process copy. `LOOP_RESET_VERIFY` runs both in one
bottom half. The control runs them as two, with the guest free to execute in
between, and must therefore see the pages of ordinary kernel work written in
that gap. A run where BOTH report zero has an oracle that is not looking at a
running guest, and its clean verifications would mean nothing -- which is why
the plugin marks that case INVALID rather than passing it.

## Predictions

### Reset cost (in-QEMU, `last_us`)

| quantity | predicted | why |
|---|---|---|
| `reset_us` median, stride | 400-900 us | the device block alone measured ~402 us on this target; the RAM term at ~128 dirty pages is ~54 us plus a word-wise bitmap scan |
| `reset_us` median, bugbench | 400-700 us | same device block, smaller dirty set |
| `restored_pages` median, stride | 20-200 | the measured per-request dirty set is 128-130 pages, and the arm-to-writev span is a fraction of a request |

### Iteration rate -- and the prediction I expect to be unwelcome

**Arm A (stride/writev) will NOT produce a fuzzing-grade rate, and the reset
will not be why.**

Predicted: `bare` median 5-50 ms per iteration, `loop` within ~1 ms of it,
exec/s in the **20-200** range. The reset should be **under 5%** of the
iteration.

The reason is structural rather than a defect. One iteration is the span of
guest execution from the armed instant to the next detector hit, because that
is what the reset rewinds. With `writev` as the detector that span is most of
an HTTP request, and `EXEC-RATE.md` already measured what an HTTP request is
made of: 0.111 ms of parsing inside ~14.3 ms of TCP loopback, socket reads,
response writes and event loop -- 0.8%. A cheap reset does not make the other
99.2% go away. **The arming point, not the reset cost, sets the rate.**

If arm A comes back at thousands of exec/s I have the model wrong and should
say so.

### Arm B (bugbench/read) is the one that should be fast

Predicted: `loop` median **0.7-1.5 ms**, exec/s **700-1,500**.

Built from three independently measured parts: reset ~0.5 ms, portal round trip
0.255 ms (`EXEC-RATE.md`, two agreeing controls), guest span ~0.1 ms. The sum
is ~0.86 ms. The range is wide on purpose -- the one previous check of a sum
like this against a closed loop was 3.7x low.

For comparison, `persist.py` measured **2,374 exec/s** on the same host with no
reset at all and no sound state between laps. Arm B should land **below** that,
and the gap is what soundness costs.

### Failure modes I expect to be live

- **The loop stalls.** After a reset the guest resumes at the armed instant and
  must reach the detector again. If the arm lands somewhere that does not, the
  run ends with few iterations. ~30% likely on at least one arm.
- **The portal desyncs.** Host-side plugin state does not rewind with the
  guest. A reset landing mid-transaction could wedge it. Unknown; the run will
  say.
- **`armed` is materially slower than `bare`.** If the dirty log costs more
  than ~10% this stops being a free measurement and the reset design has to
  account for it.

## What would make me call the loop unproven

Any of: the split-order control at zero; any verification non-zero; fewer than
~20 iterations completed; or `reset_us` disagreeing with the device-restore
profile by more than about 2x without an account of where the rest went.
