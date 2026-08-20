"""The lib_inject build must warn when a stub and a drop-in own one symbol.

A `lib_inject.stubs` entry compiles to a generated shim plus a linker
`--defsym` alias. If `lib_inject.d/` also defines that symbol by hand, the
alias silently wins and the hand-written function is left in the .so with
nothing pointing at it -- while *two* real definitions would be a hard
"duplicate symbol" error. So the stub machinery suppresses a diagnostic the
toolchain already gives; these tests cover restoring it.

The check runs as a *separate* link. The artifact link writes the .so to stdout
(`-o -`) and lld writes its --trace-symbol report to stdout too, so putting the
trace flags on the artifact link corrupts the library on every architecture --
test_artifact_link_never_carries_trace_flags pins that.

`add_lib_inject_for_abi` shells out to clang-20, which is host-impossible, so
the linker calls are faked and real, captured --trace-symbol output is replayed.
"""
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from penguin.abi_info import arch_abi_info
from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
NVRAM2 = REPO_ROOT / "pyplugins" / "interventions" / "nvram2.py"

ARCH = "armel"

# Real ld.lld output for a stubbed `nvram_get` that a drop-in also defines.
# lld writes this to stdout; GNU ld writes its equivalent to stderr.
TRACE_CONFLICT = (
    b"dropin.o: definition of nvram_get\n"
    b"<internal>: definition of nvram_get\n"
    b"--defsym: definition of nvram_get\n"
)
# Same link with no drop-in definition: only the synthetic providers.
TRACE_CLEAN = (
    b"<internal>: definition of nvram_get\n"
    b"--defsym: definition of nvram_get\n"
)
GNU_TRACE_CONFLICT = b"/usr/bin/ld: dropin.o: definition of nvram_get\n"

FAKE_SO = b"\x7fELF fake shared object"


@pytest.fixture
def nvram2(tmp_path):
    """nvram2's module namespace, via the pyplugin harness.

    The harness execs plugin modules under a synthetic name and does not put
    them in sys.modules, so reach the module globals through the class.
    """
    lp = load_pyplugin(str(NVRAM2), outdir=tmp_path, call_init=False)
    return type(lp.plugin).__init__.__globals__


def _project(tmp_path, dropin_source=None):
    proj = tmp_path / "proj"
    (proj / "lib_inject.d").mkdir(parents=True)
    if dropin_source is not None:
        (proj / "lib_inject.d" / "mine.c").write_text(dropin_source)
    return proj


def _build(nvram2, proj, tmp_path, trace=b"", trace_stream="stdout", stubs=None):
    """Run the lib_inject build with faked linker calls.

    Returns (links, build_log) where `links` is every argv the build ran, in
    order: the artifact link first, then the trace link if there was one.
    `trace` is replayed on `trace_stream` for the *second* call only.
    """
    config = {
        "core": {"arch": ARCH},
        "lib_inject": {"stubs": stubs if stubs is not None
                       else {"libfoo.so": {"nvram_get": {"return": 0}}}},
        "static_files": {},
    }
    links = []

    def fake_run(args, **kwargs):
        links.append(list(args))
        if len(links) == 1:
            # The artifact link: the .so comes back on stdout.
            return SimpleNamespace(returncode=0, stdout=FAKE_SO, stderr=b"")
        payload = {"stdout": b"", "stderr": b""}
        payload[trace_stream] = trace
        return SimpleNamespace(returncode=0, **payload)

    log = tmp_path / "lib_inject_build.log"
    abi = list(arch_abi_info(ARCH)["abis"])[0]
    # nvram2 holds the shared subprocess module, so patching it there is enough.
    with patch("subprocess.run", fake_run):
        nvram2["add_lib_inject_for_abi"](
            config, abi, str(tmp_path / "cache"),
            proj_dir=str(proj), build_log_path=str(log),
        )
    return links, (log.read_text() if log.exists() else ""), config


def test_conflict_is_reported(nvram2, tmp_path, capsys):
    proj = _project(tmp_path, "long nvram_get(long a) { return 1; }\n")
    _, build_log, _ = _build(nvram2, proj, tmp_path, TRACE_CONFLICT)

    for sink in (capsys.readouterr().out, build_log):
        assert "nvram_get" in sink
        assert "lib_inject.d" in sink
        assert "dead code" in sink


def test_conflict_reported_from_stderr_too(nvram2, tmp_path, capsys):
    """GNU ld writes the trace to stderr rather than stdout."""
    proj = _project(tmp_path, "long nvram_get(long a) { return 1; }\n")
    _, build_log, _ = _build(nvram2, proj, tmp_path, GNU_TRACE_CONFLICT,
                             trace_stream="stderr")
    assert "nvram_get" in build_log
    assert "dead code" in capsys.readouterr().out


def test_clean_build_says_nothing(nvram2, tmp_path, capsys):
    proj = _project(tmp_path, "long unrelated(void) { return 1; }\n")
    _, build_log, _ = _build(nvram2, proj, tmp_path, TRACE_CLEAN)

    assert "WARNING" not in capsys.readouterr().out
    assert "WARNING" not in build_log


def test_artifact_link_never_carries_trace_flags(nvram2, tmp_path):
    """The regression guard.

    The artifact link writes the .so to stdout, and lld writes --trace-symbol
    reports to stdout, so a trace flag on this link lands *inside* the shared
    library. That silently broke LD_PRELOAD on every architecture.
    """
    proj = _project(tmp_path, "long nvram_get(long a) { return 1; }\n")
    links, _, config = _build(nvram2, proj, tmp_path, TRACE_CONFLICT)

    artifact_link = links[0]
    assert not [a for a in artifact_link if "trace-symbol" in a]
    # ... and it is still the link that writes the library to stdout, which is
    # exactly why a trace flag here would corrupt it.
    assert artifact_link[artifact_link.index("-o") + 1] == "-"
    abi = list(arch_abi_info(ARCH)["abis"])[0]
    stored = config["static_files"][f"/igloo/lib_inject_{abi}.so"]["contents"]
    assert stored == FAKE_SO


def test_trace_link_is_separate_and_discards_its_output(nvram2, tmp_path):
    proj = _project(tmp_path, "long nvram_get(long a) { return 1; }\n")
    links, _, _ = _build(nvram2, proj, tmp_path, TRACE_CONFLICT)

    assert len(links) == 2
    trace_link = links[1]
    assert "-Wl,--trace-symbol=nvram_get" in trace_link
    # Never writes a library: output goes to /dev/null, not stdout.
    assert "-o" in trace_link
    assert trace_link[trace_link.index("-o") + 1] == os.devnull
    assert "-" not in trace_link[trace_link.index("-o") + 1:]


def test_no_extra_link_without_dropins(nvram2, tmp_path):
    """Nothing can collide, so only the artifact link runs."""
    proj = _project(tmp_path)
    links, _, _ = _build(nvram2, proj, tmp_path, TRACE_CLEAN)
    assert len(links) == 1


def test_no_extra_link_without_stubs(nvram2, tmp_path):
    proj = _project(tmp_path, "long nvram_get(long a) { return 1; }\n")
    links, _, _ = _build(nvram2, proj, tmp_path, TRACE_CLEAN, stubs={})
    assert len(links) == 1


def test_artifact_link_cache_key_is_unaffected(nvram2, tmp_path):
    """The trace flags must not perturb the cached .so's identity."""
    proj_with = _project(tmp_path / "a", "long nvram_get(long a) { return 1; }\n")
    links_with, _, _ = _build(nvram2, proj_with, tmp_path / "a", TRACE_CONFLICT)
    # The artifact link's argv is what feeds the cache key; it must contain no
    # trace flags regardless of drop-ins. (Match on "trace-symbol", not
    # "trace": the build legitimately compiles inject_ltrace.c.)
    assert not [a for a in links_with[0] if "trace-symbol" in a]
