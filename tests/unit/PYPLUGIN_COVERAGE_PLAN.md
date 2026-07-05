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
8. **Sibling Phase-0 plugins** as they land on this branch: `crashes.yaml`
   (draft 01) and `summary.json` (draft 02) aggregation — the harness is their
   natural host-side test.
9. **`analysis/interfaces.py` + the `apis.syscalls`-importing class** — ⚠️ **past
   the cheap boundary; separate follow-on.** `from apis.syscalls import
   ValueFilter` transitively imports the API/portal stack: `apis/__init__` →
   `hyper.portal` → `hyper.consts` (builds enums from
   `plugins.kffi.get_enum_dict(...)` at import) and `wrappers.ptregs_wrap` →
   `dwarffi`. Loading it needs (a) `dwarffi` installed and (b) a `kffi` double
   returning the **real** `value_filter_type` enum members
   (`ValueFilter.__init__` reads `vft.SYSCALLS_HC_FILTER_EXACT` as a default-arg
   at class-definition time). Faking those faithfully = maintaining the C enum
   tables. Unlock the whole class together: a checked-in enum-table fixture (or a
   lightweight real-kffi shim) as a `kffi` double + the API-layer deps in `[test]`.
   **Finding (investigated):** the loader *does* make a `kffi` double reachable at
   import (`_exec_plugin_module` swaps `penguin.plugins` to our null manager, so
   `hyper.consts`' module-body `plugins.kffi.get_enum_dict(name)` would hit it).
   The real blocker is the **source of truth**: those 7 enums (`HYPER_OP`,
   `value_filter_type`, `hyperfs_ops`, …) are defined in the kernel/igloo_driver
   DWARF, *not* anywhere in this repo — so a hand-authored fixture is unverifiable
   guesswork that bit-rots against the kernel. Do this only with a capture step
   that dumps the live enum dicts from a real run into a checked-in JSON fixture
   (regenerable), not by hardcoding values. Deferred until that capture exists.

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
(init_module/finit_module). Not yet handled: faithful FFI enums at import (the
`apis.syscalls` interfaces boundary above).

**Module loader (landed).** `penguin.testing.load_module(path, doubles=…)` imports
a pyplugin *module* (under its real dotted name so `from .base import …` resolves)
with the null manager bound as `plugins`, and returns `(module, manager)`. Use it
for testable logic that lives in plain classes/functions rather than a `Plugin`
subclass — the `hyperfile/models/*` read/write/seek/ioctl mixins are driven this
way: instantiate the model, `drive()` its generator method, resolve
`plugins.kffi`/`plugins.mem` against doubles. It force-sets `module.plugins` after
import so a module already cached by an earlier test still resolves against the
current doubles.

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
