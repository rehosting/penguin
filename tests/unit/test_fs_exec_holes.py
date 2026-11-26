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


# --------------------------------------------------------------------------- #
# The driver's own limits. Found by reading portal_exec.c after bounding the
# blob against the region -- which was necessary and not sufficient: a blob that
# fits the region can still exceed the limits inside it, and every one of these
# truncates rather than failing.
# --------------------------------------------------------------------------- #

def test_an_over_long_exe_path_is_refused(fs):
    """handle_op_exec copies exe_path into char[256] with strncpy(sizeof - 1).

    A longer path is truncated there, and call_usermodehelper then runs whatever
    the shortened path names -- a different binary, or nothing. The blob check
    does not catch it: 300 bytes fits the 4072-byte region comfortably.
    """
    r, _ = _run(fs.exec_program(exe_path="/usr/bin/" + "a" * 300,
                                argv=["x"]))
    assert r[0] == "RAISED", f"accepted a 309-byte exe_path: {r!r}"
    assert "255" in r[2]


def test_more_than_fifteen_arguments_is_refused(fs):
    """The driver parses at most 15 argv entries (`for (i = 0; i < 15 ...)`).

    Argument 16 onward are silently dropped and the program runs with a
    truncated command line. Nothing about the blob is malformed, so nothing
    fails -- the command is just quietly not the one that was asked for.
    """
    r, _ = _run(fs.exec_program(argv=["/bin/echo"] + [str(n) for n in range(20)]))
    assert r[0] == "RAISED", f"accepted 21 arguments: {r!r}"
    assert "15" in r[2]


def test_more_than_fifteen_env_vars_is_refused(fs):
    r, _ = _run(fs.exec_program(argv=["/bin/env"],
                                envp={f"K{n}": "v" for n in range(20)}))
    assert r[0] == "RAISED", r
    assert "15" in r[2]


def test_exactly_the_limits_is_allowed(fs):
    """The boundary is inclusive, so a valid command is not refused.

    Worth asserting: an off-by-one the strict way is a plugin that cannot run
    a command the driver would have run fine, which is a regression introduced
    by a safety check.
    """
    r, blob = _run(fs.exec_program(exe_path="/x" * 100,          # 200 bytes
                                   argv=[str(n) for n in range(15)],
                                   envp={f"K{n}": "v" for n in range(15)}))
    assert r == 0, r
    assert blob is not None


# --------------------------------------------------------------------------- #
# Round-trip against the driver's parse.
#
# The parse below is a TRANSCRIPTION of handle_op_exec in
# igloo_driver/src/portal/portal_exec.c -- deliberately literal, so a reviewer
# can check it against the C by eye. It is here because the blob builder and the
# parser are two halves of one wire format maintained in two repos, and nothing
# checked that they agree. An off-by-one in the driver's walk does not fail
# loudly: it shifts the argument list, and the program runs with the wrong argv.
# --------------------------------------------------------------------------- #

EXEC_MAX_ARGS = 15
EXEC_PATH_BUF = 256


def _driver_parse(blob, region=REGION):
    """Mirror of handle_op_exec. Returns (exe, argv, envp) or ('ERR', errno)."""
    end = len(blob)

    def nxt(p):
        q = p
        while q < end and blob[q] != 0:
            q += 1
        return q + 1 if q < end else None

    n = nxt(0)
    if n is None or n > EXEC_PATH_BUF:
        return "ERR", "ENAMETOOLONG"
    exe = blob[:n - 1].decode("latin-1")

    argv, p, i = [], n, 0
    while i < EXEC_MAX_ARGS and p < end and blob[p] != 0:
        q = nxt(p)
        if q is None:
            return "ERR", "EINVAL"
        argv.append(blob[p:q - 1].decode("latin-1"))
        p, i = q, i + 1
    if p >= end:
        return "ERR", "EINVAL"
    if i == EXEC_MAX_ARGS and blob[p] != 0:
        return "ERR", "E2BIG"

    envp, p, i = [], p + 1, 0
    while i < EXEC_MAX_ARGS and p < end and blob[p] != 0:
        q = nxt(p)
        if q is None:
            return "ERR", "EINVAL"
        envp.append(blob[p:q - 1].decode("latin-1"))
        p, i = q, i + 1
    if i == EXEC_MAX_ARGS and p < end and blob[p] != 0:
        return "ERR", "E2BIG"
    return exe, argv, envp


@pytest.mark.parametrize("exe,argv,envp", [
    ("/bin/sh", ["sh", "-c", "true"], {"PATH": "/bin"}),
    ("/bin/true", ["/bin/true"], {}),                     # no env at all
    ("/bin/true", [], {"A": "1"}),                        # no argv at all
    ("/bin/true", [], {}),                                # neither
    ("/x" * 100, [str(n) for n in range(15)],             # both at the limit
     {f"K{n}": "v" for n in range(15)}),
    ("/bin/echo", ["a=b", "-"], {"E": ""}),               # empty env VALUE is fine
])
def test_the_driver_recovers_exactly_what_the_host_sent(fs, exe, argv, envp):
    """Every boundary the two halves could disagree on.

    The empty-argv and empty-envp cases are the ones that matter: the driver
    steps over the argv terminator with `env_buf = arg_buf + 1`, so if the
    builder ever emitted one NUL too few or too many there, the environment
    would be parsed out of the middle of the argument list.
    """
    r, blob = _run(fs.exec_program(exe_path=exe, argv=argv, envp=envp))
    assert r == 0, r
    got_exe, got_argv, got_envp = _driver_parse(blob)
    assert got_exe == exe
    assert got_argv == list(argv)
    assert got_envp == [f"{k}={v}" for k, v in envp.items()]


def test_the_host_refuses_exactly_what_the_driver_would_refuse(fs):
    """The host's limits must not be looser than the driver's.

    Looser means the driver refuses a call the host allowed, which surfaces as a
    bare negative return code from exec_program rather than as an explanation.
    """
    # one past each limit: the host must raise before the blob is ever built
    for kwargs in ({"exe_path": "/" + "a" * EXEC_PATH_BUF, "argv": ["x"]},
                   {"argv": ["/bin/x"] + ["a"] * EXEC_MAX_ARGS},
                   {"argv": ["/bin/x"],
                    "envp": {f"K{n}": "v" for n in range(EXEC_MAX_ARGS + 1)}}):
        r, _ = _run(fs.exec_program(**kwargs))
        assert r[0] == "RAISED", f"host allowed {kwargs!r}, driver would not"


def test_an_empty_argument_is_refused_because_it_cannot_be_carried(fs):
    """Found by round-tripping, not by inspecting the format.

    An empty argument's NUL is the same byte that terminates the argument list,
    so the driver stops there and reads everything after it as the ENVIRONMENT.
    argv=["a", "", "-x"] therefore runs `a` with NO arguments and "-x" in its
    environment -- two wrong things at once, silently, with a return code of 0.
    Empty arguments are legitimate (sh -c '...' '' passes one), so this is a
    limitation of the wire format that has to be reported.
    """
    r, _ = _run(fs.exec_program(argv=["/bin/a", "", "-x"]))
    assert r[0] == "RAISED", f"accepted an empty argument: {r!r}"
    assert "empty string" in r[2]
    # the message must say where the dropped arguments would have gone
    assert "environment" in r[2]


def test_an_empty_env_value_is_still_allowed(fs):
    """K= is a real, common thing to want, and it is representable.

    Asserted so the empty-argument fix does not get generalised into rejecting
    empty env values, which would be a regression: "E=" is non-empty on the
    wire, so it round-trips fine.
    """
    r, blob = _run(fs.exec_program(argv=["/bin/env"], envp={"E": ""}))
    assert r == 0
    assert _driver_parse(blob)[2] == ["E="]
