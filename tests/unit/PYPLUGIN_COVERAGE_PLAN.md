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
3. **Pseudofile ranking/suggest** — `init/pseudofile_patches.py` (78%) and
   `hyperfile/models/*` are partly covered by `test_pseudofile_models.py`; extend
   to the ranking/`suggest` heuristics written into `pseudofiles_failures.yaml`.
4. **`analysis/health.py`** (73, 18%), **`analysis/interfaces.py`**,
   **`analysis/ficd.py`** — event → file writers. `interfaces` uses a
   `@plugins.syscalls.syscall` generator + `plugins.mem.read_str`, so it needs a
   `mem` double (see netbinds IPv6) and exercises the portalcall/syscall path.
4. **`loggers/`** (`db.py` 18%, `rw_logger.py` 20%, `exec_logger.py` 26%) —
   pairs with the record/replay seam (same trace feeds both the logger and the
   `core.strace`/`core.ltrace` replacement work).
5. **`interventions/`** (`nvram2.py` 18%, `lifeguard.py` 20%, `kmods.py` 21%,
   `mount.py` 27%) — where each is host-decidable vs guest-round-trip needs the
   per-plugin scope call above.
6. **Sibling Phase-0 plugins** as they land on this branch: `crashes.yaml`
   (draft 01) and `summary.json` (draft 02) aggregation — the harness is their
   natural host-side test.

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
