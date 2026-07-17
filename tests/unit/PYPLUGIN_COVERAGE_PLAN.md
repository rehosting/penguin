# Plan: host-side coverage for pyplugins

## Why

The host-side suite covers config/schema/init-discovery well (structure.py 99%,
arch_registry 99%, templating 96%, the init finders 78–96%). It does **not**
cover plugin *runtime behaviour*: a coverage run over `pyplugins/` reports
**~11%**, and almost all of that is import-time (class/`Args` definitions run
during discovery) — no event-handling or file-writing logic executes.

Yet a large share of the guest-boot matrix asserts on **a file the host writes**
from a plugin: `netbinds.csv` shaping, `pseudofiles_failures.yaml`
ranking/suggest, and (in the sibling Phase-0 workspaces) `crashes.yaml` dedup and
`summary.json` aggregation. That logic is host-side; the guest only produces the
raw event stream. Testing it should not require a per-arch boot.

**Decision (fixed):** the logic stays in `pyplugins/`. We build a harness that
reaches *in* and drives each plugin against a recorded event trace. No logic
moves to `src/`.

## Mechanism: `penguin.testing.load_pyplugin`  ✅ BUILT

Implemented in `src/penguin/testing/` (`harness.py`), with a reference test in
`tests/unit/test_pyplugin_harness.py`. It stands up a **null backend** (no PANDA,
no guest):

- `NullManager` — records `subscribe`/`register`/`publish`/`portalcall`; resolves
  registered doubles by name; unknown siblings (`plugins.Events`, `plugins.mem`,
  …) become a recording `RecorderStub`. Never recurses into loading.
- `NullPanda` — `self.panda` stand-in with a configurable `endianness`; records
  callback registrations.
- The plugin is loaded via the **real loader** (`plugin_manager._exec_plugin_module`,
  which binds `plugins` during import) and constructed via the real `Plugin`
  protocol (`__new__` → `__preinit__` → `__init__`), then returned as a
  `LoadedPlugin` you drive with `.dispatch(event, ...)` / `.finalize()`.

This subsumes the old per-file `sys.modules` stubbing (one shim per test → one
harness) and rides the existing loader rather than reinventing one.

> Note: the original spec named `test_binary_patch.py::_load_live_image` as the
> shim to replace, but that file is **not in this tree**. `netbinds` is the
> landed reference proof instead (see below).

**Record → replay:** capture a portal/event trace from one real boot, check it
in as a fixture, and feed it to the in-place plugin; assert on the file it
writes. One capture → many fast host tests across event edge-cases a single boot
never hits.

### The line (scope)

- **In scope:** plugins that only *consume events and write host files* — the
  `analysis/` writers and the pseudofile models. Identity decorators + test
  doubles are faithful enough here.
- **Out of scope (stays a `tests/integration/` fixture):** any plugin that
  round-trips through the guest (hypercall request → guest action → response).
  The harness can't fake that faithfully; draw this line explicitly per plugin.

## Prioritized targets (by measured gap × host-writable value)

Ordered most-valuable first. Percentages are current host coverage.

1. ✅ **`analysis/netbinds.py`** — done (`test_pyplugin_harness.py`): IPv4 and
   IPv6 (the latter via a `mem` double), dedup, lifecycle CSV.
2. ✅ **`analysis/env.py`** (`EnvTracker`) — done (`test_env_tracker.py`): getenv
   tracking, config-known filtering, uboot capture via strstr, YAML on teardown.
3. ✅ **`analysis/health.py`** — done (`test_health.py`): distinct bind/exec/
   device-open tallies to health_final.yaml + device/proc lists.
4. **Pseudofile models** ✅ done — the `hyperfile/models/*` read/write/seek/ioctl
   models (what backs `read/write/ioctl/lseek: {model: ...}` and decides the bytes
   a modelled `/dev`·`/proc`·`/sys` file serves — the host-side logic a huge share
   of the guest-boot matrix ultimately exercises). Covered via the new
   `load_module` seam (these are plain mixin classes, not `Plugin` subclasses) +
   the pump with `kffi`/`mem` doubles: `test_read_models.py` (const/zero/one/empty,
   cycle, sequence advance+hold+wrap, stateful, const-map, default → read 19→59%),
   `test_write_models.py` (discard/return-const/unhandled, record overwrite +
   gap-pad, default → write 26→44%), `test_seek_models.py` (SEEK_SET/CUR/END,
   clamp/EINVAL, unsupported/ESPIPE → seek 43→66%), `test_ioctl_models.py`
   (zero/unhandled/return-const, write-data-arg, dispatcher exact/string/wildcard/
   ENOTTY, compat dispatcher → ioctl 33→76%). Remaining misses are the
   External{VFS,Legacy}/FromPlugin adapters (they call *other* plugins — a
   guest-round-trip/plugin-graph concern) and file-backed variants. The
   `pseudofiles_failures.yaml` ranking/`suggest` heuristics in
   `init/pseudofile_patches.py` (78%, provenance already covered by
   `test_pseudofile_models.py`) remain as a smaller follow-on.

   **Composition + registration** ✅ done — `test_pseudofile_composition.py`
   (`hyperfile/pseudofiles.py` 14→54%). Two layers above the models:
   *composition* — `_create_dynamic_class` assembles the right model mixins into
   one class (asserted on the resulting MRO) with the right kwargs, plus the
   per-domain resolvers (`_resolve_mixin`, `_create_ioctl_handler`,
   `_translate_kwargs`, `_normalize_ioctl_conf`, `_resolve_known_size`); and
   *passing to the kernel* — `_populate_hf_config` routes each path prefix
   (`/dev`→devfs, `/proc`→procfs, `/proc/sys`→sysctl, `/sys`→sysfs) to the correct
   subsystem registrar with the composed instance, and defers `/dev/mtd*`·
   `/proc/mtd` to the native MTD subsystem. Loaded with the new `call_init=False`
   seam (the plugin's `__init__` inits the tracker + reads config); routing is
   verified with recording registrar doubles. This deliberately asserts *structure*
   (which mixins compose, which registrar fires) — the model *behavior* is already
   covered by the four `test_*_models.py`, so the layers stay separately tested.
   Remaining pseudofiles.py misses are the plugin-backing (`file:Class`) import
   path and the `from_plugin` style-detection (both guest/plugin-graph concerns).

   **Registrars** ✅ done — the subsystem registrars `_populate_hf_config` routes
   to are now covered directly: `hyperfile/procfs.py` (2→82%, `test_procfs.py`),
   `hyperfile/sysfs.py` (2→85%, `test_sysfs.py`), `hyperfile/sysctl.py` (2→74%,
   `test_sysctl.py`), alongside the pre-existing `test_devfs.py`. Each asserts the
   queue/dedup/validation of `register_*`, the dir/file `PortalCmd`s emitted by
   `_get_or_create_*_dir` / `_register_*` (real op numbers via `real_isf=`), and
   the install-budget drain of the interrupt handler. See the "Real ISF enums"
   note below for the shared shape.
5. ✅ **`analysis/ficd.py`** — done (`test_ficd.py`): Levenshtein unique/not-unique
   dedup + ifin-not-reached YAML on teardown (drives `on_exec` directly; the
   execve syscall handler just feeds it).
6. **`loggers/`** — `exec_logger.py` ✅ done (`test_exec_logger.py`, via a `DB`
   double); `db.py` ✅ done (`test_db.py`, 18→96% — real SQLite round-trip:
   add_event → uninit flush/join → read back with SQLAlchemy, incl. the
   polymorphic split-insert and unsigned-address sanitization); `rw_logger.py`
   ✅ done (`test_rw_logger.py`, 20→83%) — the first **portal-generator** plugin
   driven through the harness's syscall pump (see "syscall pump" below): its
   `read`/`write` `yield from` `plugins.mem`/`plugins.OSI`, satisfied by generator
   doubles, with `panda.ffi.cast` modelled as identity.
7. **`interventions/`** — `mount.py` ✅ done (`test_mount.py`, the exec-driven
   log path); `kmods.py` ✅ done (`test_kmods.py`, 21→75% — name/allow/deny +
   modules.log, plus the `init_module`/`finit_module` **generator** handlers via
   the syscall pump); `lifeguard.py` ✅ done (`test_lifeguard.py`, 20→82% —
   signal classification syscall-only vs delivery, delivery-drop + CSV,
   no-subscription case, plus the `kill` syscall-send **generator** interception
   via the pump + a `_Proto` double with `arg_value`); `nvram2.py` ✅ done
   (`test_nvram2.py`, 18→31% — get-hit/miss, set, clear, tmpfs-key
   normalization, logging-mask query). Nvram2's `__init__` compiles lib_inject
   via `clang-20` (host-impossible), so it loads with the new **`call_init=False`**
   seam and the test sets the handful of attributes the handlers use; the ~140
   lines of remaining misses are that `add_lib_inject_*`/`prep_config` build
   machinery, genuinely out of host scope (needs the toolchain image / a
   `tests/integration/` fixture). Note the syscall-**return** hooks (e.g. mount's
   `post_mount`) also run through the pump now via `dispatch_syscall(...,
   on_return=True)`.
   **Core/actuation also covered** (not originally listed, done opportunistically
   as clean non-boundary wins): `core/readiness.py` ✅ (`test_readiness.py`,
   26→100% — igloo_init/netbind marker files + single-publish dedup) and
   `actuation/nmap.py` ✅ (`test_nmap.py`, 27→88% — UDP short-circuit, scan-command
   construction incl. the custom-nmap redirect branch, subprocess cleanup, via a
   patched `subprocess.Popen`).
8. **Sibling Phase-0 plugins** as they land on this branch:
   - ✅ **`analysis/crashes.py`** (draft 01) — done (`test_crashes_plugin.py`):
     fatal signal-delivery events → `crashes.yaml`, dedup on (proc, signal, pc)
     with count, first-occurrence pid/time, watched-set filtering, and
     `event.drop` skipping; driven through the harness by dispatching
     `signal_deliver` with synthetic events and a `signals` double for the
     per-arch name→number resolution. `manager.calculate_score`'s crashes
     category is covered separately by `test_manager_score.py`. The guest
     round-trip (dequeue_signal kretprobe → SignalMonitor) stays the
     `tests/integration/` fixture (`crashes.yaml`).
   - ✅ **`hyperfile/pseudofile_tracker.py`** (draft 03, PR #879) — done
     (`test_pseudofile_tracker.py`, behind the FFI-enum boundary via
     `real_isf=`): the -ENOENT open/stat and -ENOTTY ioctl **generator**
     handlers via the syscall pump with `mem`/`osi` doubles (caller
     attribution, O_ACCMODE intent, relative-dfd resolution, `/proc/PID`
     collapse, TTY/proc ioctl filters), the pure ranking/suggest helpers
     (`impact_score` tiers, `suggest_models`, `load_crashes` tolerance,
     `count_crashing_callers` exact-vs-by-name), `record_default_hit`
     provenance (the Pseudofiles `default_hit_cb` contract), the eager flush
     (#175 durability), and end-to-end `pseudofiles_failures.yaml` ranking
     with the crashes.yaml join. Guest round-trip (real ENOENT delivery,
     crash → crashes.yaml production) stays in `tests/integration/` fixtures
     (`pseudofile_missing`/`pseudofile_ioctl`/`pseudofile_ext_ops`).
   - ✅ **`summary.json`** (draft 02, `src/penguin/run_summary.py`) — done
     (`test_run_summary.py`). Not a pyplugin — the post-run host aggregator —
     so the harness's role is the *producer* side: the real
     `analysis/netbinds.py` is loaded with `load_pyplugin`, driven with bind
     events, finalized, and `write_run_summary` aggregates the directory the
     plugin actually wrote (so CSV-shape drift breaks the test, not just the
     fixture). Direct fixtures cover the artifact shapes (draft 01
     `crashes.yaml`, draft 03 ranked `pseudofiles_failures.yaml`) and the
     formats main doesn't produce yet — draft 05 lifecycle columns
     (transient/pending excluded from `binds`), draft 06 `waitgraph.yaml` —
     plus absent-producer null semantics and malformed-row tolerance.
9. **`analysis/interfaces.py` + the `apis.syscalls`-importing class** ✅ done
   (`test_interfaces.py`, `analysis/interfaces.py` 4→93%) — the FFI-enum boundary,
   crossed with the **`real_isf=`** load mode. `from apis.syscalls import
   ValueFilter` transitively imports `apis/__init__` → `hyper.portal` →
   `hyper.consts` (builds enums from `plugins.kffi.get_enum_dict(...)` and wraps
   them in `ConstDictWrapper`) and `wrappers.ptregs_wrap` → `dwarffi` (in the
   `[test]` extra).

   **How it works:** `load_pyplugin(..., real_isf=<path>)` registers a real
   `dwarffi`-backed `kffi` double (`RealKffi`) built from the actual published
   `igloo.ko` ISF, then clears any cached `hyper.consts` so the **genuine**
   `hyper/consts.py` imports and builds against real values via
   `get_enum_dict`/`get_type`. So the whole runtime path is exercised — real
   `dwarffi`, real `consts.py`, real `ConstDictWrapper`, real `hyper.portal` — and
   every `PortalCmd` carries its **true** op number. This also exposes the full
   driver type universe (structs, not just the seven enums), so type-reading
   plugins work too. The one enum with no host-reachable ISF home
   (`igloo_base_hypercalls`, defined in igloo_base) is supplied by `RealKffi` as a
   single ABI-fixed constant.
10. ✅ **`core/live_image.py` — `binary_patch` logic** — done
    (`test_binary_patch.py`). The host-side half of the `static_files`
    `binary_patch` action (Phase-0 draft 04: `expect`/`on_mismatch` verify,
    idempotent re-runs, `why`/`tag` provenance, multi-edit `patches`, and
    composing patches onto a placed `host_file`/`inline_file`). Loaded in place
    with `load_pyplugin` (`proj_dir`/`conf` args + `outdir`), controlling the
    one sibling it calls, `static_fs`, with a `doubles={"static_fs": …}` entry
    for the out-of-bounds size check. Covers hex parsing (0x/space forms),
    `_verify_entry` policy matrix incl. length-mismatch/past-EOF/`base_offset`,
    `_normalize_patch_entries`, `_synth_file_patch_action` (compose + glob
    rejection), `_apply_binary_patch` (disjoint/overlap/contained-overlap +
    out-of-window & negative-offset rejection), the `_patch_window` windowed
    offset math, `_check_patch_within_file` bounds check (fits/exceeds/unknown/
    errors→skip), and the `_on_batch_patch_hypercall` handler's success,
    windowed round-trip, and **fail→return-`-1` abort contract** (asserts the
    staged window is left untouched and the tag/why land in
    `binary_patches.yaml`). This replaces the file's original hand-rolled
    `sys.modules`-stub loader — the case that motivated the harness.
11. ✅ **`src/penguin/stubs.py` — `lib_inject.stubs` codegen** — done
    (`test_stubs.py`, draft 07). The declarative `lib_inject.stubs` section
    (force a library/object symbol to return a constant) compiles to a generated
    C shim + a `--defsym` alias, reusing the existing `nvram2` lib_inject build.
    The codegen is a pure host-side module, so it is fully unit-tested here:
    schema validation (`structure.StubAction`: require `return`/`guard_null_args`,
    guard-index bounds, unknown-key rejection), `generate()` output (plain return,
    `type` override, `guard_null_args` call-through via `dlsym(RTLD_NEXT,...)` with
    no `dlsym` leaking into plain stubs), glob expansion against an injected
    symbol resolver, the missing/ambiguous/stripped-library and no-match hard
    errors, the duplicate-symbol and `stubs`↔`aliases` precedence conflicts, and
    `write_files` regeneration. The assembly-**body** form (`symbol@offset:
    {body: asm}`) is also covered: `parse_symbol_key`, `generate_patches`
    (offset+delta, mode/expect passthrough, glob rejection), `_vaddr_to_file_offset`,
    `merge_patches_into_static_files` (create/append/normalize/conflict), and that
    the synthesized `binary_patch` validates against the real `StaticFiles`
    schema. The `nvram2` glue that writes `lib_inject.d/.generated/`, runs the
    `clang-20` cross-compile, and resolves symbol offsets from the rootfs stays
    out of host scope (same toolchain-image boundary noted for `nvram2.py` above)
    — covered by the generated-C `-fsyntax-only` check and a `tests/integration/`
    boot fixture, not host unit tests.

    **Out of scope — stays a `tests/integration/` fixture (`live_image.yaml`):**
    the real guest round-trip (the batch hypercall's `hyp_file_op --range`
    transport, whose reply drives the write-back) and keystone `asm`
    assembly (a native-toolchain concern; `import keystone` is soft so the
    plugin still loads host-side, and `_gen_asm_patch_bytes` guards on it).

10. **`apis/net.py` — netdev auto-registration decision** ✅ done
    (`test_net.py`, `real_isf=` load — net.py imports `hyper.portal` →
    `hyper.consts`). Covers `ensure_netdev_from_path()` /
    `_is_runtime_created_iface()`: firmware-built bridges/bonds/VLANs (incl. dotted
    sub-interfaces and VLAN-over-bond) get **no** auto-created stub, ordinary NICs
    still do (across every conf/neigh/sysfs path family), the explicit `netdevs`
    config bypasses suppression (escape hatch), and the special-name/invalid-name/
    non-network-path/idempotency edges. This is the host-side reproduction of the
    all-arch guest failure that motivated PR #872's fix.

### Harness capabilities (as landed)

`load_pyplugin` currently handles: module/class-body decorators
(`@plugins.portalcall`, `@plugins.subscribe(pub, event)` decorator form), sibling
test doubles via `doubles={name: obj}` (e.g. `mem`, `kffi`), sibling-package
imports (`from apis import ...` — pyplugins root goes on `sys.path`), and binding
class-body-subscribed handlers to the instance on `dispatch`.

**Syscall pump (landed).** `@plugins.syscalls.syscall(...)` registrations are now
recorded (`NullManager.syscalls` / `.syscall_hooks`), and
`LoadedPlugin.dispatch_syscall(name, *args, on_return=…)` finds the matching hook
and runs its **generator** to completion via `penguin.testing.drive`. Sibling
API calls the generator makes (`plugins.mem.read_bytes`, `plugins.osi.*`) are
satisfied by generator *doubles* that `yield from ()` and `return` a canned
value; `panda.ffi.cast` is modelled as identity so `int(cast("target_long", fd))`
works. Proven on `rw_logger` (read/write) and `kmods`
(init_module/finit_module). The `apis.syscalls` FFI-enum boundary is handled via
`real_isf=` (see below).

**Module loader (landed).** `penguin.testing.load_module(path, doubles=…)` imports
a pyplugin *module* (under its real dotted name so `from .base import …` resolves)
with the null manager bound as `plugins`, and returns `(module, manager)`. Use it
for testable logic that lives in plain classes/functions rather than a `Plugin`
subclass — the `hyperfile/models/*` read/write/seek/ioctl mixins are driven this
way: instantiate the model, `drive()` its generator method, resolve
`plugins.kffi`/`plugins.mem` against doubles. It force-sets `module.plugins` after
import so a module already cached by an earlier test still resolves against the
current doubles.

**Real ISF enums (landed).** `load_pyplugin(..., real_isf=<path>)` /
`load_module(..., real_isf=<path>)` register a real `dwarffi`-backed `kffi` double
(`RealKffi`) built from the actual published `igloo.ko` ISF and clear cached
`hyper.consts` so the genuine module rebuilds against **real** enum values — the
same path `apis.kffi` uses at runtime. No checked-in fixture: the ISF is the
source of truth, pinned to the driver release, so it can't drift. The
`igloo_ko_isf` pytest fixture (in `conftest.py`) resolves the ISF via
`penguin.testing.resolve_igloo_ko_isf` — env `PENGUIN_TEST_IGLOO_KO_ISF` → local
cache → **download `igloo_driver.tar.gz` for the Dockerfile-pinned
`IGLOO_DRIVER_VERSION`** (not `:latest`) and extract one arch → nix store — and
`skip`s cleanly when offline with nothing cached. The one enum absent from the
driver ISF (`igloo_base_hypercalls`) is supplied by `RealKffi` as a single
ABI-fixed constant. Enums/most driver types are arch-invariant, so one arch
(`armel`) suffices. Proven on `analysis/interfaces` (4→93%), `core/scope` (7→93%),
and the four pseudofile **registrars** (the kernel-facing half of the pseudofile
stack) — `hyperfile/devfs` (3→45%), `hyperfile/procfs` (2→82%,
`test_procfs.py`), `hyperfile/sysfs` (2→85%, `test_sysfs.py`), `hyperfile/sysctl`
(2→74%, `test_sysctl.py`) — plus `test_real_consts.py` for the mechanism. The
registrar tests all follow the devfs shape: a duck-typed `*File` double (so the
fops/ops-struct callback build stays a no-op — that path is a guest concern), a
`RealKffi` subclass whose `new` returns a fixed request blob, and assertions that
`_get_or_create_*_dir` / `_register_*` emit the **right** `PortalCmd` op (real op
number) with the request bytes as payload. `test_sysctl.py` additionally guards
`_reject_reason` — the `/proc/sys/fs/binfmt_misc` panic guard that must not
regress.

## Sequencing

1. ✅ **Build `penguin.testing.load_pyplugin`** (null backend + test doubles).
   Done — `src/penguin/testing/`.
2. ✅ **Reference proof (netbinds)** — `tests/unit/test_pyplugin_harness.py`
   drives netbinds in place: setup+bind events → assert `netbinds.csv` row,
   `on_bind` publish, dedup, and lifecycle CSV on `finalize()`. No emulation.
3. **Pin a trace-capture format** (open) so tests replay a real recorded event
   stream instead of hand-built `dispatch(...)` calls: reuse the loggers /
   `syscalls_logger` output, or a purpose-built capture. Must be stable enough to
   check in as a fixture. netbinds' event set is the first candidate.
4. **Work down the target list** — one plugin per PR, each joining the fast
   `unit_tests` job (no matrix, no emulation). For siblings a plugin talks to
   (e.g. netbinds' `plugins.mem` on the IPv6 path), register a small hand-written
   double via `load_pyplugin(..., doubles={...})`.
5. ✅ **Retired `test_selects_kvm`'s xfail** — done, but *not* by importing
   `apis.hypercall` host-side (that still needs the target-9 enum capture).
   Instead `test_kvm_runner_final.py` drives the real `run_config` through backend
   selection + QEMU-argv assembly and stops deterministically at
   `plugins.initialize` (the first post-selection step) via a sentinel exception,
   *before* the `from apis.hypercall import Hypercall` boundary. It asserts the
   real outputs — `KVMQemu.from_installation("kvm", arch)` called, `-accel kvm` in
   the argv, `"system"` mode + no accel for qemu/default, panda rejected — so we
   get confidence the KVM path is wired without launching KVM or crossing the
   boundary. 1 xfail → 4 passing tests.

## Cross-repo ABI tests that depend on an *unreleased* driver op

`test_osi_bulk.py` covers `OSI.get_all_procs` (the bulk process walk behind
`HYPER_OP_OSI_PROC_ALL`) against the **real** driver ISF. That op is added by
igloo_driver #88; a host plugin that calls it is *incompatible with any pinned
driver release that predates it*.

**Rule (matches the "ISF is source of truth" doctrine in `docs/testing.md`):**
such a test **FAILS, it does not skip**, when the pinned ISF lacks the op. A skip
reads as green and would let host code that can't run against its own pinned
driver merge silently. The failure is the forcing function — bump
`IGLOO_DRIVER_VERSION` (Dockerfile) to a release carrying the op and the test
goes green with no edit. See `_assert_pinned_driver_has_bulk_op`.

- **Expected state on branch `workspace/proctree-ux` / PR #897:** these 2 tests
  are **intentionally RED** until (a) a driver release is cut from igloo_driver
  `main` (post-#88-merge) carrying the op and (b) #897 bumps the pin to it. Do
  not "fix" them by reverting to a skip. As of the last check, released tags
  (≤ v0.0.88) predate the op, so a new release must be cut first.
- Only a *totally unresolvable* ISF (offline, nothing cached) skips — that is
  genuinely untestable and distinct from "pinned driver predates the op".
- We deliberately did **not** add a fake-enum "logic only" variant that always
  runs (purist call): no checked-in/faked enum values, the real ISF stays the
  single source of truth.

## Open questions

- **Null-backend fidelity:** how far can identity decorators + test doubles go
  before tests stop reflecting real behaviour? Draw the in/out line per plugin.
- **Trace format:** loggers output vs purpose-built; must be diffable and stable.
- Every plugin ported host-side should have its guest-boot fixture re-scoped
  (kept as a thin smoke, or retired) so we don't pay for both.

## Related

- Draft 21 (`~/workspace/iglootodo/planning/21-test-suite-triage.md`) — Bucket 3.
- The packaging + `unit_tests` CI job (this branch) are the prerequisites: no
  point testing plugins in-place if those tests don't run in CI.
