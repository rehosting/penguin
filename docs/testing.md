# Testing pyplugins host-side

Most Penguin behaviour that matters — the files a plugin writes, the events it
emits, the portal commands it issues — is **host-side Python logic**. The guest
only produces the raw event stream. So that logic can be tested by a fast,
host-only unit test in `tests/unit/`, with **no PANDA, no guest, and no per-arch
boot**, using the `penguin.testing` harness.

**When you add or change a pyplugin, add a host test for its host-side logic.**
These tests run in the `unit_tests` CI job (a bare runner, no emulator, no
matrix), so they gate every PR and stay fast.

## The one rule: what is testable host-side

Draw the line per plugin:

- **In scope — test it here.** A plugin (or model) that *consumes events and
  writes host files*, or *decides which portal command to emit*. The
  `analysis/` writers, the `hyperfile/models/*` read/write/seek/ioctl models,
  the pseudofile registrars (`devfs`/`procfs`/`sysfs`/`sysctl`), the loggers.
- **Out of scope — leave it a `tests/integration/` fixture.** Anything that
  round-trips through the guest: a hypercall request whose *reply* drives the
  next step, guest-side struct packing, a native-toolchain build. The harness
  can fake the *shape* of the round-trip (see `drive(responses=...)`), but not
  the guest's real behaviour. Don't pretend it can.

When in doubt, test the part that is pure host logic and stub the guest edge.

## The harness (`penguin.testing`)

A pyplugin can't just be imported and instantiated: its module and class body
reference the live `plugins` manager (`@plugins.portalcall(...)`,
`plugins.subscribe(...)`, sibling `plugins.<name>` calls) that is normally
late-bound against a running portal. The harness stands up a **null backend**
so the *real* loader and the *real* `Plugin` construction protocol run against
doubles you control.

### `load_pyplugin(...)` — construct a plugin, ready to drive

```python
from penguin.testing import load_pyplugin

lp = load_pyplugin(
    "pyplugins/analysis/netbinds.py",
    outdir=tmp_path,                     # where the plugin writes its files
    args={"shutdown_on_www": False},     # the conf['plugins'][name] block
    doubles={"mem": my_mem_double},      # sibling plugins you want to control
)
lp.dispatch("igloo_ipv4_bind", cpu=None, port=port_be, is_steam=True)
lp.finalize()                            # runs uninit() -> flushes final files
assert "httpd" in (tmp_path / "netbinds.csv").read_text()
```

- **`doubles=`** maps a sibling name (`mem`, `kffi`, `portal`, …) to a test
  double. Any sibling you *don't* provide resolves to a `RecorderStub`: a
  recording no-op that's safe to call/decorate/index, so unrelated sibling
  calls don't blow up. Inspect what got called via `lp.calls`.
- **`lp.dispatch(event, ...)`** invokes every handler the plugin subscribed to
  that event (class-body `@plugins.subscribe` handlers are bound to the
  instance for you). `lp.subscriptions` / `lp.published` expose what the plugin
  wired up and emitted.
- **`lp.finalize()`** runs the plugin's `uninit()` — many plugins flush their
  final output file there.
- **`call_init=False`** stops construction after `__preinit__` (skips
  `__init__`). Use it when `__init__` does host-impossible I/O (e.g. `nvram2`
  shells out to `clang-20`): the class still imports so class-body decorators
  register, and your test sets the handful of attributes the handlers need.

### `drive(gen, responses=..., collect=True)` — run a portal generator

Many handlers are generators that `yield` a `PortalCmd` (or `yield from` a
sibling API) and resume on the reply. `drive` pumps such a generator to
completion:

```python
from penguin.testing import drive
import hyper.consts as consts

ret, yielded = drive(lp.plugin._get_or_create_proc_dir("a/b"),
                     responses=[10, 20], collect=True)
# responses are fed to successive yields (the "guest replies")
assert [c.op for c in yielded] == [           # assert the RIGHT commands issued
    consts.HYPER_OP.HYPER_OP_PROCFS_CREATE_OR_LOOKUP_DIR,
    consts.HYPER_OP.HYPER_OP_PROCFS_CREATE_OR_LOOKUP_DIR,
]
assert ret == 20                              # deepest id threaded back out
```

Compare `cmd.op` against the enum *member*, not a literal — see `real_isf=`.

### `dispatch_syscall(...)` — drive a `@syscalls.syscall` hook

`@plugins.syscalls.syscall(...)` registrations are recorded; drive one (they're
portal generators) with:

```python
lp.dispatch_syscall("kill", regs, proto, sysno, sig, on_return=False,
                    responses=[...])
```

Sibling API calls the handler makes (`plugins.mem.read_bytes`, `plugins.osi.*`)
are satisfied by *generator doubles* that `yield from ()` and `return` a canned
value; `panda.ffi.cast` is modelled as identity.

### `load_module(...)` — for logic that isn't a `Plugin`

Some testable logic lives in plain classes (e.g. the `hyperfile/models/*`
mixins), not a `Plugin` subclass. `load_module(path, doubles=...)` imports the
*module* under its real dotted name (so `from .base import …` resolves) with the
null manager bound as `plugins`, and returns `(module, manager)`. Instantiate
the class and `drive()` its generator methods directly.

## Plugins behind the FFI-enum boundary: `real_isf=`

A plugin that imports `hyper.portal` / `hyper.consts` / `apis.syscalls`
transitively builds its enums (`HYPER_OP`, `value_filter_type`, …) from the
driver's **ISF** (the DWARF-derived symbol format `apis.kffi` reads at runtime).
To let the *genuine* `hyper.consts` build with **real** enum values, pass
`real_isf=`:

```python
def test_something(tmp_path, igloo_ko_isf):        # session fixture (see below)
    lp = load_pyplugin(DEVFS, outdir=tmp_path, real_isf=igloo_ko_isf)
    import hyper.consts as consts
    # cmd.op now carries the true op number from the driver's DWARF
    assert cmd.op == consts.HYPER_OP.HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR
```

- The **`igloo_ko_isf` pytest fixture** (in `tests/unit/conftest.py`) resolves
  the ISF — `PENGUIN_TEST_IGLOO_KO_ISF` env var → local cache → **download
  `igloo_driver.tar.gz` for the `IGLOO_DRIVER_VERSION` pinned in the
  Dockerfile** (not `:latest`) and extract one arch → nix store — and `skip`s
  cleanly when offline with nothing cached. Take it as a test argument.
- **No checked-in enum fixture.** The ISF *is* the source of truth, pinned to
  the driver release, so the enums can't drift out of date. This also loads the
  whole driver type universe (structs, not just enums), so type-reading plugins
  work. Enums/most driver types are arch-invariant, so one arch (`armel`)
  suffices.
- If your plugin also calls `kffi.new(...)` / `kffi.callback(...)` (struct
  packing — a guest ABI concern), subclass `RealKffi` and stub just those to
  return a fixed blob, then pass it as `doubles={"kffi": MyKffi([isf])}`. The
  `real_isf=` value still makes `hyper.consts` real; your subclass wins for the
  packing methods. See `test_devfs.py` for the canonical shape.

The `[test]` extra in `src/pyproject.toml` provides `dwarffi` (matching the
Dockerfile pin), so the ISF loads with the same reader the image uses.

## Running the tests

Everything runs on a bare host with only the `[test]` extra — no image:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e './src[test]' -e './pengutils'      # pengutils is a sibling package
pytest tests/unit -q
# coverage over plugin logic:
pip install pytest-cov
pytest tests/unit --cov=pyplugins --cov-report=term-missing:skip-covered
```

Validate in a **fresh** venv with only the `[test]` extra (not your working
venv), so a missing dependency can't hide behind something already installed.

## Where to look for patterns

- `tests/unit/test_pyplugin_harness.py` — the reference proof (netbinds: events
  → `netbinds.csv`, dedup, lifecycle CSV on `finalize()`).
- `tests/unit/test_devfs.py` / `test_procfs.py` / `test_sysfs.py` /
  `test_sysctl.py` — the pseudofile registrars: `real_isf=` + a `RealKffi`
  subclass + asserting the right `PortalCmd` op.
- `tests/unit/test_read_models.py` (and `write`/`seek`/`ioctl`) — `load_module`
  driving the pseudofile model mixins.
- `tests/unit/test_real_consts.py` — the `real_isf=` mechanism itself.
- `tests/unit/PYPLUGIN_COVERAGE_PLAN.md` — the living status/tracker of what is
  covered and what is deliberately out of scope, and why.
