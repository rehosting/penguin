# Host-side pytest suite (`tests/unit/`)

The `test_*.py` files here are a fast, **host-side** pytest suite: no PANDA, no
guest boot, no emulation. They cover config schema, compose networking,
binary-patch logic, init sequencing, KVM dispatch, static analyses, refresh,
cmdline sizing, and pseudofile models — in seconds. CI runs them in the
`unit_tests` job of `.github/workflows/build.yaml`, a fast lane that fails a PR
long before the slow per-arch guest-boot matrix (`tests/integration/`) would.

Run locally after an editable install of the two modules we own:

```sh
pip install -e "src[test]" -e "pengutils[test]"   # from the penguin/ repo root
python3 -m pytest tests/unit/ pengutils/
```

The `[test]` extras pull the package's runtime deps (pydantic, coloredlogs,
pyelftools, networkx, …) plus `pytest`. The suite runs entirely host-side —
**no emulator, no guest image, no Docker**. `conftest.py` puts the repo root on
`sys.path` because `pyplugins/` is loaded by path at runtime and is deliberately
not packaged. `penguin/version.txt` is generated at container build time; when
absent, `penguin.__init__` falls back to `0.0.0+dev`.
`pengutils/` ships a small starter suite (`pengutils/tests/`) and is included in
the invocation so tests added there run automatically.

## Layout

- `tests/unit/` — this suite (host-side, fast, in the `unit_tests` CI job).
- `tests/integration/` — guest-boot fixtures (`test_target/`, `basic_target/`,
  `compose/`); slow, per-arch, run by the `run_tests`/`run_compose` CI jobs.

## Driving pyplugins in place

`penguin.testing.load_pyplugin` loads a pyplugin against a null backend (no
PANDA, no guest) and returns it ready to drive — so a plugin's host-side logic
(the files it writes, events it emits) can be unit-tested here instead of via a
guest boot. See `test_pyplugin_harness.py` for the reference use against
`analysis/netbinds.py`, and [`PYPLUGIN_COVERAGE_PLAN.md`](PYPLUGIN_COVERAGE_PLAN.md)
for the design, the in/out-of-scope line, and the prioritized target list.
