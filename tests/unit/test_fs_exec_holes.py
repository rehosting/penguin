"""Adversarial tests for fs.exec_program.

Unprobed until now, and it is the one call in this module that has a side effect
in the guest. The two findings that matter both change WHICH COMMAND RUNS while
reporting success, which is a worse outcome than anything on the read paths: a
read that returns wrong bytes is a wrong answer, an exec that runs a wrong
command is a wrong action.

The wire format is a flat NUL-separated blob -- exe\\0 argv...\\0\\0 envp...\\0\\0\\0
-- so anything that can end a C string early, or make the blob outgrow the
portal region, edits the command in transit.
"""
import pytest
from pathlib import Path
from penguin.testing import RealKffi, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
FS = str(REPO_ROOT / "pyplugins" / "apis" / "fs.py")

REGION = 4072


class _KFFI(RealKffi):
    def sizeof(self, t):
        return self.ffi.sizeof(t)

    def from_buffer(self, t, buf, instance_offset_in_buffer=0):
        return self.ffi.from_buffer(t, bytearray(buf),
                                    offset=instance_offset_in_buffer)


class _Portal:
    regions_size = REGION


@pytest.fixture
def fs(tmp_path, igloo_ko_isf):
    lp = load_pyplugin(FS, outdir=tmp_path, real_isf=igloo_ko_isf,
                       doubles={"portal": _Portal(),
                                "kffi": _KFFI([igloo_ko_isf])})
    return lp.plugin


def _run(gen, response=0):
    """Return (result, the blob that would have gone to the guest)."""
    try:
        cmd = gen.send(None)
    except Exception as e:
        return ("RAISED", type(e).__name__, str(e)), None
    try:
        gen.send(response)
    except StopIteration as e:
        return e.value, bytes(cmd.data)
    except Exception as e:
        return ("RAISED", type(e).__name__, str(e)), bytes(cmd.data)
    return ("HUNG",), bytes(cmd.data)


# --------------------------------------------------------------------------- #
# Runs the wrong command, and says it succeeded.
# --------------------------------------------------------------------------- #

def test_a_nul_inside_an_argument_is_refused(fs):
    """An embedded NUL splits one argument into two.

    The blob is NUL-separated, so argv=["sh", "-c", "a\\0b"] does not pass a
    literal NUL through -- it ends the argument at "a" and makes "b" a separate
    argument. Anything built from guest-derived or config-derived strings can
    therefore have arguments appended to it, silently, with a return code of 0.
    """
    r, blob = _run(fs.exec_program(argv=["/bin/sh", "-c", "echo hi\0; rm -rf /"]))
    assert r[0] == "RAISED", f"accepted an embedded NUL: blob={blob!r}"
    assert "NUL" in r[2] or "null" in r[2]


def test_a_nul_in_an_env_value_is_refused(fs):
    r, _ = _run(fs.exec_program(argv=["/bin/sh"], envp={"A": "x\0y"}))
    assert r[0] == "RAISED", r
    assert "NUL" in r[2] or "null" in r[2]


def test_a_blob_too_big_for_the_region_is_refused_not_truncated(fs):
    """Truncation does not fail: it runs a shorter command.

    The blob goes into one portal region. Overflowing it drops whatever falls
    off the end -- the tail of an argument, or entire arguments -- so a long
    argv turns into a different, shorter command line that still executes.
    """
    r, _ = _run(fs.exec_program(argv=["/bin/sh", "-c", "x" * REGION]))
    assert r[0] == "RAISED", r
    assert str(REGION) in r[2]
    assert "truncat" in r[2] or "region" in r[2]


# --------------------------------------------------------------------------- #
# Silent failure.
# --------------------------------------------------------------------------- #

def test_a_failed_exec_is_not_reported_as_success(fs):
    """A refused exec returned None.

    None is not a return code. `if not result` reads it as success, `result == 0`
    reads it as failure, and nothing reads it as "the exec never happened" --
    the same conflation this module fixed for reads and then for writes.
    """
    r, _ = _run(fs.exec_program(argv=["/bin/nope"]), response=None)
    assert r[0] == "RAISED", f"None returned as a result: {r!r}"


# --------------------------------------------------------------------------- #
# Confusing diagnostics.
# --------------------------------------------------------------------------- #

def test_no_program_at_all_says_so(fs):
    """`exe_path = argv[0]` on a missing argv raised TypeError: 'NoneType' object
    is not subscriptable, from inside a filesystem API, which reads as a bug in
    the plugin rather than as a missing argument."""
    r, _ = _run(fs.exec_program())
    assert r[0] == "RAISED", r
    assert r[1] == "PortalFileError", r
    assert "argv" in r[2] or "exe_path" in r[2]


def test_an_empty_argv_says_so(fs):
    r, _ = _run(fs.exec_program(argv=[]))
    assert r[0] == "RAISED", r
    assert r[1] == "PortalFileError", r


def test_unencodable_argument_is_refused_clearly(fs):
    r, _ = _run(fs.exec_program(argv=["/bin/echo", "☃"]))
    assert r[0] == "RAISED", r
    assert r[1] == "PortalFileError", r
    assert "latin-1" in r[2] or "encodable" in r[2]


# --------------------------------------------------------------------------- #
# Confirmed not a hole -- kept so the wire format cannot drift silently.
# --------------------------------------------------------------------------- #

def test_the_wire_format_is_what_the_driver_parses(fs):
    """exe\\0 argv...\\0 \\0 envp...\\0 \\0 \\0, in that order."""
    r, blob = _run(fs.exec_program(exe_path="/bin/sh",
                                   argv=["sh", "-c", "true"],
                                   envp={"PATH": "/bin"}))
    assert r == 0
    assert blob == (b"/bin/sh\0" + b"sh\0-c\0true\0" + b"\0"
                    + b"PATH=/bin\0" + b"\0" + b"\0")


def test_argv_zero_is_used_when_no_exe_path_is_given(fs):
    r, blob = _run(fs.exec_program(argv=["/bin/true"]))
    assert r == 0
    assert blob.startswith(b"/bin/true\0/bin/true\0")
