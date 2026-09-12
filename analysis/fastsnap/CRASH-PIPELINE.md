# From an input to an attributed, reproducible crash

Companion to `CRASHES.md`. That file established that the crash **sensor**
works and that no crash in this lane was ever produced by fuzzing. This file
answers the next question: what stands between a fuzzed input and a crash
record that names it, and how much of that already exists.

The distinction `CRASHES.md` draws is load-bearing here too. Below, one
attributed crash is demonstrated end to end — on a **planted** bug in a
purpose-written victim, not on the target. That proves the *pipeline*. It
proves nothing about the target's bugs, and the section that shows it says so
in its own heading.

---

## 0. One correction to CRASHES.md

> "`fuzzdrive`, the plugin that sends fuzzed requests, is **off** in every run
> referenced below [...] No input was ever fed."

The first clause is right for the runs that file tabulates. The second is too
strong as a blanket statement. `fuzzdrive` was enabled and did deliver inputs
in two runs of this lane:

| log | results | HTTP reads | fuzzed | passthrough | response mix |
|---|---|---|---|---|---|
| `work/<lane>/run_fuzz.log` | `.../results/10` | 190 | 164 | 26 | `{}` — control empty |
| `work/<lane>/run_fuzz2.log` | `.../results/11` | 658 | 579 | 79 | `{400:96, 401:13, 200:59, 404:13, 501:3, 411:1, 505:1}` |

Run 11 is a *valid* fuzzing run by `fuzzdrive`'s own controls: passthrough
samples exist, and the response mix contains 200s (the server was not wedged)
alongside 400s (mutants were rejected deep enough to be answered). **579
mutated requests were parsed by the target and produced zero new crashes.**

Both runs' `crashes.yaml` contain only the same two records seen in every
fuzzdrive-**off** run — `sxnetset@0x00009f3c` and `msdialer@0xb6eec2f0`, at
t≈58–71 s. Identical processes at identical PCs whether or not inputs were
delivered is what makes them the firmware's own boot-time crashes rather than
anything the harness produced.

So the accurate statement is: *inputs have been fed, ~743 of them, and no crash
resulted.* That is a negative result about the target under this harness, which
is weaker than "untested" and much weaker than "crash finding works". It also
means the attribution gap has never been *exercised* — there was never a crash
to attribute.

---

## 1. What the three harness plugins actually do

Read as source, not as names. All three exist in two identical copies
(`analysis/fastsnap/*.py` and the lane's project `plugins/` directory under
`work/`; `diff` is empty).

### `fuzzdrive.py` — it does send inputs

It is a real, working injector, not a stub:

- Hooks `on_sys_read_return` with `comm_filter`, sniffs the first 4 bytes for
  an HTTP verb, and for non-passthrough reads calls
  `plugins.mem.write_bytes(buf, payload)` then sets `syscall.retval`.
- Mutations come from a seeded `random.Random`, 6 operators (bit flip, long
  header, empty list element, truncate, duplicated `Range`, seed splice).
- Payloads are truncated to `count`, so it cannot overflow the guest buffer
  itself and manufacture its own crashes.
- Carries three named controls: passthrough fraction, buffer bound, response
  status histogram (hooked on both `write` and `writev`).

**What it does not do — this is the whole attribution gap:**

- No sequence number. `self.n_fuzzed` is a counter that is incremented and
  never associated with anything.
- No per-input timestamp. Only `t_first` / `t_last` for the whole run.
- No retention of the payload. `mutate()`'s bytes are written into guest
  memory and dropped. Nothing is hashed, nothing is written to a corpus.
- No pid. It never asks `osi` who it is injecting into.
- No knowledge that a crash plugin exists.

`fuzzdrive.json` is seven aggregate numbers. There is **no field in it that
could be joined to any field in `crashes.yaml`.** Attribution is not lossy
here; it is absent.

Two further consequences worth stating:

- The mutation stream is deterministic *in principle* (seeded RNG) but not
  *addressable*: the RNG is also consumed by the passthrough coin flip, so
  replaying input #N requires reproducing the exact read schedule the guest
  happened to issue. There is no way to ask for "the input that crashed it".
- The two artifacts do not even share a clock base. `crashes.yaml`'s `time` is
  seconds since the crashes plugin's own `__init__`, and that origin is never
  written anywhere; `fuzzdrive`'s spans are absolute `time.time()`. A coarse
  timestamp join is not available from the saved artifacts either.

### `persist.py` — no inputs; a rate ceiling only

AFL persistent-mode rewind implemented in a pyplugin: a uprobe at the parser's
entry overwrites `LR` with the function's own entry address so the epilogue
returns into it, restoring `r0-r3` from the entry snapshot each lap. It
measures per-lap intervals. Its own docstring says state is not reset between
laps, so it is a **ceiling**, not a usable fuzzer. It injects nothing and
records nothing about inputs. `laps: 0` is its control.

### `fuzzcal.py` — reconnaissance; explicitly does not inject

Locates the injection point: records `(fd, fdname, buf, count, retval, head)`
for every read by the target process, with a write hook as the control that
distinguishes "no reads" from "the instrument never armed". Its docstring says
"it does NOT inject anything yet". It is the only one of the three that
retains input *bytes* (`head`, first 96) — but for reads it observed, not
reads it caused, and with no link to any crash.

### Answering the three questions directly

- *Does fuzzdrive send inputs at all?* **Yes** — 743 across two runs.
- *Does anything record which input was sent?* **No.** Nothing anywhere
  records a payload the harness generated.
- *Is there any correlation mechanism between an input and a subsequent
  signal?* **No.** No shared sequence number, no shared pid, no per-input
  timestamp, no common clock origin.

---

## 2. Gap list, ordered by what blocks what

Each gap blocks the ones below it: you cannot attribute an input the harness
never delivered, and you cannot run a per-iteration oracle over a reset nobody
is told about.

### G1 — `analysis_scope` can silently disarm the harness *(blocks: everything)*

`core.analysis_scope: firmware` (the default) makes igloo_driver gate syscall
hypercall emission on the firmware UTS-namespace subtree
(`pyplugins/core/scope.py`). A harness aimed at a process outside that subtree
sees **zero reads**, and the run reports zero crashes — indistinguishable from
"the target has no bug". `fuzzdrive`'s `n_seen == 0` check catches this, but
only if someone reads the log; the artifact on disk looks like a clean run.

**Minimal change:** when a fuzz harness plugin is enabled, assert the scope
covers its target at load time and refuse to start otherwise — the same shape
as `persist.py`'s "SYMBOL RESOLUTION FAILED / this run measures nothing" guard.
(Also a known-failure class in this repo: `analysis_scope:firmware` previously
emptied `netbinds.csv` and hid a gdbserver bind.)

### G2 — the injection point is not discriminated *(blocks: the harness running at all)*

`comm_filter` is a process filter, not a descriptor filter. The dynamic loader
runs under the victim's `comm`, so "rewrite every read by this process"
overwrites the loader's read of its own ELF headers and the victim never
starts. Measured, in this audit's run 0:

```
[IGLOO] user init dispatched /igloo/init.d/parsed
Error loading shared library libgcc_s.so.1: Exec format error
```

`fuzzdrive` happens to dodge this because its HTTP-verb sniff acts as an
accidental content filter — but that is luck, not design, and it does not
generalise to a non-HTTP target.

A second, subtler form: caching the fd→name mapping by fd *number* is wrong.
The loader closes its library descriptors before the victim opens the request
one, so the cache hands back a stale `.so` path and the harness injects
nothing while reporting no error. Measured in run 1: `inputs_delivered: 0`.

**Minimal change:** resolve `plugins.osi.get_fd_name(fd)` per read (uncached)
and inject only on the request descriptor; count and log the skipped reads as
a control.

### G3 — no input identity *(blocks: attribution — this is the headline gap)*

As dissected in §1. The minimal change is small and needs no core change:

1. The injector assigns a monotonic `seq` to every payload, hashes it, and
   writes the exact bytes to `corpus/<seq>.bin`.
2. It records `last_by_pid[pid] = record` at injection time (pid from
   `plugins.osi.get_proc()`).
3. It subscribes to the **same** `signal_deliver` event `crashes.py`
   subscribes to (`plugins.subscribe(plugins.signal_monitor, "signal_deliver",
   ...)`) and, on a fatal signal, joins on pid to that pid's last input.

That is ~40 lines. It is implemented and demonstrated as
`work/attrib/proj/plugins.d/crashattr.py` (§3).

**Soundness of the join.** `(pid, last input delivered)` is *exact* for a
single-threaded victim that parses each input before reading the next — which
is the case a snapshot fuzzing loop constructs on purpose. It is a *heuristic*
for a threaded or pipelined server, where several requests can be in flight
at once, so the last input delivered to the pid need not be the one being
parsed. The output must carry that distinction on every row rather than
implying certainty; `crashattr.py` emits `join: last-input-to-pid` and
`join_exact`.

**Where it should eventually live.** Two artifacts (`crashes.yaml` +
`crashes_attributed.yaml`) that must be joined by hand is a stopgap. The
architectural fit is an input-context seam the injector writes and `crashes.py`
reads, so a single crash record carries its input — i.e. a small API plugin
under `pyplugins/apis/`, not a second analysis plugin. That is a design
proposal here, not something this audit built.

### G4 — a restore notifies no host-side plugin at all *(blocks: per-iteration oracle)*

This is bigger than "`crashes.py` lacks `on_restore`", and it has to be fixed
first or G5 is inert. Three defects compound:

1. **This lane's own reset loop bypasses the Snapshot plugin.**
   `analysis/fastsnap/notrap.py` calls
   `self.panda.schedule_snapshot(self.tag, load=True)` directly. It never goes
   through `Snapshot.request_restore`, so no lifecycle hook and no event fires.
   The 25-restore loop rewinds the guest 25 times with zero host-side
   notification.
2. **Even `request_restore` does not dispatch the method.**
   `pyplugins/core/snapshot.py:145-152` publishes
   `plugins.publish(self, "on_restore", tag)` and stops there.
   `_dispatch_lifecycle("on_restore", tag)` and `_restore_host_state()` are
   called **only** from `dispatch_restore()`, the `boot_from` boot path. So a
   plugin implementing the documented `on_restore` **method** — `netbinds.py`
   and `vpn.py` both do — is never called on an in-process restore.
3. **Nothing subscribes to that event.** A repo-wide grep for subscribers of
   Snapshot's `"on_restore"` returns nothing, so the `publish` in (2) reaches
   no one either.

And `Plugin.reset_state()` — the seam `plugin_manager.py:269` documents as
"reserved for fork/restore-many [...] the designed seam, not yet driven by any
caller" — is confirmed to have **no caller anywhere in the repo**.

**Minimal change (~10 lines, `snapshot.py` + `notrap.py`):**
route loop restores through `Snapshot.request_restore`; have `request_restore`
call `_dispatch_lifecycle("on_restore", tag)` the way the boot path does; and
give it a `reset=True` mode that calls `_dispatch_lifecycle("reset_state")`
instead, for restore-many.

### G5 — `crashes.py` is stateful with no snapshot hooks *(blocked by G4)*

Confirmed: no `save_state`, `load_state`, `on_restore`, or `reset_state`, while
`self.records` accumulates dedup counts that never rewind.

**What it needs — both halves, they are different cases:**

- `save_state` / `load_state` / `on_restore` for **once-and-continue,
  cross-process** restore (`boot_from`): a fresh penguin process attaches to a
  guest already past its pre-snapshot crashes, so without this the restored
  run starts blank and every earlier crash silently disappears. This is
  exactly `netbinds.py`'s pattern.
- `reset_state` for **restore-many**: restoring the same point repeatedly must
  rewind the report with the guest, or counts accumulate over iterations the
  guest never executed.

Two details that matter and are easy to get wrong:

- The dict key is the tuple `(proc, signal, pc_int)`, which is not JSON. But
  `pc` is stored in each row as a hex *string*, so the key round-trips exactly
  via `int(rec["pc"], 16)` — and it must, or a post-restore repeat of a
  pre-restore crash opens a second record instead of incrementing the first.
- `time` is seconds since emulation start on the timeline the delivery
  happened on. A restored run is a different timeline. Rebasing it (as
  `netbinds` does for socket lifetimes) would be wrong here because the value
  is an event instant, not a duration; carried rows should be tagged instead.

**Status: implemented in the working tree** (`pyplugins/analysis/crashes.py`,
+57 lines, uncommitted) — see §4.

### G6 — a negative is still uninformative *(inherited from CRASHES.md)*

Unchanged and unaddressed: the crash channel is blind to kernel-side death, so
"no crashes" cannot distinguish a robust target from a rotting guest. Run 48's
98 lines of panic/OOM with a byte-identical `crashes.yaml` remains the
evidence. A fuzzing campaign needs an independent health channel.

### G7 — a finding *lowers* the run score, and is not surfaced as a finding

`src/penguin/manager.py:166` scores `"crashes": -n_crashes` — crashes are
treated as a rehosting defect to minimise. Measured in this audit's crash run:

```
scores.txt:  crashes,-1.00
summary.json: "crashes": -1
```

For a fuzzing lane that inverts the objective: the run that found the bug
scores worse than the run that did not. `run_summary.py` also has no slot for
attribution — `summary.json` carries the bare `crashes.yaml` rows, so even a
populated `crashes_attributed.yaml` would not reach the run summary.

**Minimal change:** leave `calculate_score` alone (it is the rehosting-quality
metric and crashes genuinely are defects there) and give the fuzzing lane its
own objective; add an `attributed_crashes` key to `run_summary` so the
attribution reaches `summary.json`.

### G8 — deliveries, not deaths *(inherited, documented by the plugin itself)*

A process that catches SIGSEGV and survives is still recorded. For a fuzzer
this produces findings that are not crashes.

---

## 3. One attributed, reproducible crash — on a planted bug

**Read the heading.** This demonstrates the *pipeline*, using a victim written
for the purpose with a bug put there deliberately. It is not a finding about
the target, and it does not make the ~743 delivered inputs that found nothing
mean anything more than they did.

What it does establish is that every link in the chain works with shipped
Penguin machinery: input → crash → crash record → attribution → standalone
reproducer file → crash reproduced from that file alone.

### Where the evidence lives

`analysis/fastsnap/work/` is `.gitignore`d in full (deliberately — the lane
once swept a busybox into a public repo by that route), so the project tree
and its `results/` are **on disk only**, not in git. The two reusable source
files are copied up to the tracked level next to the other harness plugins:

- `analysis/fastsnap/crashattr.py` — the injector + joiner
- `analysis/fastsnap/crashattr_victim.c` — the planted-bug victim
- `analysis/fastsnap/work/attrib/README.md` — run-by-run index (untracked)

### Setup

`analysis/fastsnap/work/attrib/` — a mipsel/4.10 guest built from
`tests/integration/basic_target`'s empty rootfs (no vendor content anywhere).

- `proj/init.d/parsed.c` — the victim. Reads a request, then copies it into a
  16-byte stack buffer using a length byte taken from the request itself: the
  classic unvalidated-length stack overflow. It reads from `/dev/zero` rather
  than a socket on purpose — the harness rewrites the buffer at the `read()`
  return, so the descriptor is only a clock, and the experiment stays free of
  networking, which is not what is under test.
- `proj/plugins.d/crashattr.py` — the ~40-line injector+joiner of G3.
- `pyplugins/analysis/crashes.py` — **unmodified sensor**; it is the shipped
  plugin that produced `crashes.yaml` below (the §4 snapshot hooks are
  additive and not exercised by these runs).

The mutant at `seq 42` carries length byte `0x60` (96) and a filler of
word-aligned `0x44444440`, so the smashed return address is a 4-aligned
unmapped value. That makes the faulting PC *literally a function of the input
bytes*, which is what lets the attribution be checked from outside the
harness rather than taken on trust.

### Result — run `results/2`

Shipped sensor, `crashes.yaml`:

```yaml
crashes:
- proc: parsed
  pid: 231
  signal: 11
  signame: SIGSEGV
  pc: '0x44444440'      # == the input's filler word
  time: 7.43
  count: 1
```

The join, `crashes_attributed.yaml`:

```yaml
comm: parsed
inputs_delivered: 43
crashes:
- proc: parsed
  pid: 231
  signame: SIGSEGV
  pc: '0x44444440'
  attributed: true
  join: last-input-to-pid
  join_exact: true
  input_seq: 42
  input_sha256: 26905e4742cfc4f9fcd97ca7e25372e00eb7450c399a9fe1655a673f03f29374
  input_len: 96
  input_file: corpus/000042.bin
  input_to_crash_ms: 3.0
```

Harness controls from the same run:

```
crashattr: RESULTS inputs=43 crashes=1 attributed=1 reads_skipped_wrong_fd=1   <- CONTROL
crashattr: fd names seen: {'/igloo/dylibs/libgcc_s.so.1': 1, '/dev/zero': 43}  <- CONTROL
```

An independent repeat (`results/3`, separate boot, separate container) produced
the identical `pc`, `input_seq` and `input_sha256`.

### The reproducer actually reproduces — run `results/5`

`corpus/000042.bin` was copied out as a standalone 96-byte file and fed back on
a fresh boot with `replay_file:` (inject these bytes, nothing else):

```
crashattr: armed on comm='parsed' mode=REPLAY .../repro/crash_pc44444440.bin
           (96 B, sha256=26905e4742cfc4f9)
crashes:   SIGSEGV delivered to parsed (pid 231) at 0x44444440
crashattr: SIGSEGV in parsed (pid 231) at 0x44444440 <- input seq=0
           sha256=26905e4742cfc4f9 (3.0 ms after delivery)
```

`inputs_delivered: 1`. The crash arrives at **seq 0**, not seq 42 — so it is
caused by the bytes, not by the iteration count or by 42 iterations of
accumulated state. That is the property a reproducer has to have.

### Negative control — run `results/6`

The replay proves a crash can be reproduced. It does not, on its own, rule out
"this guest crashes anyway". So the same harness was pointed at a *benign*
input from the same corpus (`corpus/000041.bin`, 10 bytes, declared length
within the buffer):

```
crashattr: armed on comm='parsed' mode=REPLAY .../repro/benign_seq41.bin
           (10 B, sha256=82fbeac7765fd0d2)
crashattr: RESULTS inputs=64 crashes=0 attributed=0 reads_skipped_wrong_fd=1   <- CONTROL
crashattr: fd names seen: {'/igloo/dylibs/libgcc_s.so.1': 1, '/dev/zero': 64}  <- CONTROL
```

`crashes.yaml` is `crashes: []`. This is the control that makes the positive
result mean something: the harness was demonstrably armed (64 injections, and
the fd histogram shows every one landed on the request descriptor), the victim
ran to completion — all 64 iterations, against 43 in the crash run, because it
was not killed partway — and no crash occurred. The difference between the two
runs is the input bytes and nothing else.

### What each failed attempt taught (the gaps in §2 are measured, not guessed)

Three runs failed before one worked, and each failure is one of the gaps
above. They are listed because a harness that fails this way produces an
artifact indistinguishable from a clean run.

| run | symptom on disk | actual cause | gap |
|---|---|---|---|
| `results/0` | victim never started: `Error loading shared library libgcc_s.so.1: Exec format error` | injection rewrote the dynamic loader's own read of its ELF headers — `comm_filter` does not exclude the loader | G2 |
| `results/1` | `inputs_delivered: 0`, no error | fd→name cache keyed by fd *number*; the loader closed fd 3 and the victim reopened it, so the cache returned a stale `.so` path forever | G2 |
| `results/4` | ran with wrong args, silently | `plugins.d/*.py` **replaces** the plugin's args from `config.yaml` and every `patch_*.yaml` with a `<name>.yaml` sidecar (`penguin_config/__init__.py:481-487`). The `replay_file` set in the patch was discarded; the only signal was a WARNING that reads like a benign override note | new, see below |

**New footgun worth recording (G9).** For a plugin loaded from `plugins.d/`,
args written under `plugins: <name>:` in a patch are silently dropped — the
drop-in loop does `config["plugins"][plugin_name] = args`, an assignment, not a
merge, where `args` is the sidecar YAML or `{}`. This lane's own harness
plugins are unaffected because they are loaded via `plugin_path`, not
`plugins.d/`; anyone prototyping a fuzz harness the documented local way
(`docs/pyplugin_architecture.md`: "drop `myplugin.py` into `plugins.d/`, then
enable it in `config.yaml`") will hit it. Minimal change: merge the sidecar
over the existing entry instead of replacing it, or upgrade the warning to
name the keys being discarded.

---

## 4. The restore gap: what `crashes.py` needs, and whether tests can cover it

### The change

Implemented in the working tree (uncommitted), `pyplugins/analysis/crashes.py`,
+57 lines, purely additive — four methods and one field:

```python
def save_state(self):                 # -> {"records": [...]} or None
def load_state(self, data): ...       # stash only
def on_restore(self, tag): ...        # rebuild self.records, tag pre_restore, rewrite
def reset_state(self): ...            # rewind to empty (restore-many)
```

plus `self._restore_data = None` in `__init__`. This is `netbinds.py`'s shape,
which is the established convention here (`vpn.py` and `nvram2.py` are the
other implementers; the contract is documented on `Plugin` in
`plugin_manager.py:230-276`).

Three decisions inside it that are not arbitrary:

- **Key round-trip.** `self.records` is keyed `(proc, signal, pc_int)`, which
  is not JSON. `pc` is persisted per row as a hex string, so `on_restore`
  rebuilds the key with `int(rec["pc"], 16)`. If that is not exact, a
  post-restore repeat of a pre-restore crash opens a *second* record instead
  of incrementing the first — the dedup silently breaks in the one place it
  matters.
- **`time` is not rebased.** It is an event instant on the pre-snapshot
  timeline, not a duration; carried rows get `pre_restore: true` instead.
- **`save_state` returns `None` when idle**, so the sidecar is not written for
  a run with no crashes (matching `netbinds`).

### Can the 9 tests cover it host-side, with no guest? Yes — and they now do.

`tests/unit/test_crashes_plugin.py` drives the plugin through
`penguin.testing.load_pyplugin` with a fake `signals` sibling and synthetic
`signal_deliver` events. Snapshot hooks are plain methods on the instance, so
they are directly callable — and `tests/unit/test_netbinds_lifecycle.py`
already establishes the pattern: build a *producer* instance, `save_state()`,
build a *separate consumer* instance, `load_state()` + `on_restore()`. Two
instances rather than one is the point: it covers the cross-process path a
real restore takes.

Five tests added (9 → 14, all passing in 0.38 s, no PANDA, no boot):

| test | what would break without it |
|---|---|
| `test_save_state_is_none_when_no_crashes` | an empty sidecar written for every clean run |
| `test_restore_rehydrates_records_into_a_fresh_instance` | pre-snapshot crashes vanish from the restored run's report; also asserts the `json.dumps/loads` sidecar round-trip and the `pre_restore` tag |
| `test_restored_records_keep_deduping_against_new_deliveries` | the key-rebuild bug above: a repeat opens a second record |
| `test_reset_state_rewinds_the_report` | restore-many accumulates counts for iterations the guest never ran |
| `test_load_state_without_restore_does_not_touch_the_report` | a plugin applying state in `load_state` clobbers a live report before `on_restore` |

**But these tests pass over a hook nothing calls.** G4 is the blocker: in this
lane's reset loop no restore reaches `on_restore` or `reset_state` at all.
Shipping G5 without G4 produces exactly the failure shape `CRASHES.md` is about
— a mechanism that is present, tested, and never exercised.

---

## 5. What this did NOT establish

- **Nothing about the target's bugs.** The attributed crash is a planted
  overflow in a victim written for this experiment. The target's ~743 fuzzed
  requests still produced zero crashes, and that remains the state of the
  evidence.
- **The attribution was never run against the target.** `crashattr.py` was
  exercised only on the synthetic victim. On a real concurrent server the
  `(pid, last input)` join is a heuristic, and how often it is wrong is
  **unmeasured**. A ground-truth check (e.g. a victim that crashes on a
  distinguishable input while several are in flight) was not run.
- **The restore hooks were never exercised against a guest.** The five new
  tests are host-side only. No run in this audit took a snapshot, restored, and
  observed `crashes.yaml` rewind — precisely because G4 means nothing would
  have called them. The integration fixture was not extended.
- **G4's fix is described, not implemented.** No change was made to
  `snapshot.py` or `notrap.py`. The three defects are read off the source and
  confirmed by grep (no subscribers to Snapshot's `on_restore` event; no
  callers of `reset_state` anywhere), not by running a restore and observing
  silence.
- **No measurement of how often the sensor is right.** `CRASHES.md`'s
  deliveries-not-deaths caveat is untouched: nothing here checks whether a
  recorded delivery actually killed the process.
- **The synthetic victim is easy mode for attribution.** Single-threaded, one
  input per parse, one fatal signal ever, crash 3 ms after delivery. Each of
  those is a property a real target need not have, and each one makes the join
  harder.

## 6. Summary

| link in the chain | status |
|---|---|
| generate an input | **exists** (`fuzzdrive`, seeded, with controls) |
| deliver it into the guest | **exists** (`mem.write_bytes` + `syscall.retval`; ~743 delivered) |
| aim the injection at the right descriptor | **missing** — `comm_filter` alone breaks the loader (G2) |
| keep the harness armed under default scoping | **fragile** — `analysis_scope:firmware` silently disarms it (G1) |
| observe a fatal signal | **exists and works** (`crashes.py`; `CRASHES.md`) |
| name the input that caused it | **was missing** (G3); demonstrated once, ~40 lines |
| write a standalone reproducer | **was missing**; demonstrated once, and it reproduces |
| rewind the report when the guest rewinds | **missing at two levels** — plugin hooks (G5, now written + tested) *and* a restore that calls them (G4, not fixed) |
| tell a real finding from a corrupted guest | **missing** (G6, unchanged from `CRASHES.md`) |
| surface the finding as a finding | **inverted** — a crash *lowers* the run score (G7) |

The pipeline is now proven to be constructible: every link ran once, on a
planted bug, with shipped machinery. Nothing here is evidence that it has ever
found anything.
