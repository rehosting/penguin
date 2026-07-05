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
4. **Pseudofile ranking/suggest** — `init/pseudofile_patches.py` (78%) and
   `hyperfile/models/*` are partly covered by `test_pseudofile_models.py`; extend
   to the ranking/`suggest` heuristics written into `pseudofiles_failures.yaml`.
5. ✅ **`analysis/ficd.py`** — done (`test_ficd.py`): Levenshtein unique/not-unique
   dedup + ifin-not-reached YAML on teardown (drives `on_exec` directly; the
   execve syscall handler just feeds it).
6. **`loggers/`** — `exec_logger.py` ✅ done (`test_exec_logger.py`, via a `DB`
   double); `db.py` ✅ done (`test_db.py`, 18→96% — real SQLite round-trip:
   add_event → uninit flush/join → read back with SQLAlchemy, incl. the
   polymorphic split-insert and unsigned-address sanitization). Remaining:
   `rw_logger.py` (20%) — its `read`/`write` are **portal generators** reaching
   `plugins.mem`/`plugins.OSI` + `self.panda.ffi.cast`, so it needs the
   portal-read pump (see target 9 / harness gaps) before it's a clean target.
7. **`interventions/`** — `mount.py` ✅ done (`test_mount.py`, the exec-driven
   log path); `kmods.py` ✅ done (`test_kmods.py`, 21→46% — name extraction,
   allow/deny classification, modules.log writer); `lifeguard.py` ✅ done
   (`test_lifeguard.py`, 20→51% — signal classification syscall-only vs delivery,
   delivery-drop + CSV, no-subscription case). Their remaining misses are the
   syscall-send **generator** handlers (out of scope). `nvram2.py` (18%) is
   **not** a cheap target: its `__init__` compiles lib_inject via `clang-20`
   (subprocess, needs the toolchain image), so it can't be loaded host-side
   without either the toolchain or a manual bypass-`__init__` construction — the
   pure `on_nvram_*`/`log_write` handlers are testable but only after that. Note
   the syscall-return hooks (e.g. mount's `post_mount`) are portal **generators**,
   still out of scope until the harness gains a portal-read pump.
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

### Harness capabilities (as landed)

`load_pyplugin` currently handles: module/class-body decorators
(`@plugins.portalcall`, `@plugins.subscribe(pub, event)` decorator form), sibling
test doubles via `doubles={name: obj}` (e.g. `mem`, `kffi`), sibling-package
imports (`from apis import ...` — pyplugins root goes on `sys.path`), and binding
class-body-subscribed handlers to the instance on `dispatch`. Not yet handled:
driving a `@plugins.syscalls.syscall` **generator** handler (needs a portal-read
pump), and faithful FFI enums at import (the interfaces boundary above).

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
5. **Retire `test_selects_kvm`'s xfail** — the harness's null manager is the
   mechanism that unblocks importing `apis.hypercall` standalone; revisit that
   test once the harness handles the hypercall import path.

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
