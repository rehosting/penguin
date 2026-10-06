"""Adversarial probes of OSI's per-process string decoding: argv, environ, fds.

These are the three things epic B's process tree is *made of*, and all three
arrive as a flat byte blob that the host has to re-cut into structure. Each
probe here targets the re-cutting, not the transport: the transport is already
covered by test_osi_bulk.py.

What they found, in the order the datapath sees it:

1. ``get_env`` **raised** ``ValueError`` on ordinary environments. It built a
   dict with ``{k: v for k, v in (s.split("=") for s in ...)}``. ``split("=")``
   is unbounded, so any entry whose *value* contained ``=`` unpacked to three
   parts ("too many values") and any entry with no ``=`` at all unpacked to one
   ("not enough values"). ``LS_COLORS=rs=0:di=01;34`` is the canonical example
   and is present in nearly every interactive environment; a base64 value
   ending in ``==`` did it too. The exception escaped into whichever plugin had
   asked for the environment. FIXED: ``partition("=")`` splits on the first
   separator only -- which is what execve means by an entry -- and a nameless
   entry is skipped rather than aborting the walk.

2. ``get_args`` cannot reproduce argv, because the boundaries were destroyed
   before the host ever saw them. The driver's ``handle_op_read_procargs``
   rewrites every NUL separator to a space (matching ``get_mm_cmdline``), and
   ``get_args`` then does ``str.split()`` to get the list back. That round trip
   is lossy in five distinct ways -- see the table in
   ``test_get_args_cannot_reproduce_argv``. The information is not
   irrecoverable in principle: the driver sets ``header.size`` to the true
   length, so it could leave the NULs alone and let the host split on ``b"\\0"``
   exactly. The conversion is pure loss with nothing bought.

   NOT FIXED: that is a wire-format decision, not a cleanup. Its probes assert
   the current lossy behaviour *and* the exact behaviour a fix would produce,
   so a fix flips a documented assertion rather than silently changing an
   untested one.

3. ``get_fds`` paginated by *counting*. The driver walks fds by number and
   resumes at ``start_fd``, so ``current_fd += batch_count`` treated an fd
   *number* as an *index*. For a dense fd table the two agree. For a sparse one
   -- any process that has closed fds, or holds a few low fds plus a block of
   high ones -- the next request restarted inside the window just read, so
   entries came back duplicated while the fds past the batch were never
   requested at all. FIXED: advance to ``highest fd decoded + 1``, exact
   because the driver walks in ascending order, and needing no ABI change.

   The driver *also* reports where it stopped, in ``header.addr``, and
   portal.py discards that for HYPER_RESP_READ_OK.
   ``test_driver_resume_cursor_and_host_cursor_agree_on_coverage`` shows both
   cursors cover the same fds, so plumbing ``addr`` through would buy nothing.
"""
import struct
from pathlib import Path

import pytest

from penguin.testing import RealKffi, drive, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
OSI = str(REPO_ROOT / "pyplugins" / "apis" / "osi.py")

# struct osi_result_header { u64 result_count, total_count; } -- 16 bytes.
# struct osi_fd_entry     { u64 fd, name_offset; }            -- 16 bytes.
FD_HDR = 16
FD_ENT = 16
# handle_op_read_fds: max_fds = (CHUNK_SIZE / 2) / sizeof(struct osi_fd_entry),
# where CHUNK_SIZE is PAGE_SIZE - sizeof(region_header) and region_header is
# {u32 op, u32 pid, u64 addr, u64 size} == 24 bytes, so 4096 - 24 on a 4K page.
# The exact value does not matter to these probes, only that a batch can fill,
# so each test passes its own small max_fds.
CHUNK_SIZE = 4096 - 24
DRIVER_MAX_FDS = (CHUNK_SIZE // 2) // FD_ENT


class _KFFI(RealKffi):
    """Real dwarffi-backed kffi exposing the sizeof/from_buffer osi.py uses."""

    def sizeof(self, type_name):
        return self.ffi.sizeof(type_name)

    def from_buffer(self, type_name, buf, instance_offset_in_buffer=0):
        return self.ffi.from_buffer(type_name, bytearray(buf),
                                    offset=instance_offset_in_buffer)


def _load(tmp_path, isf):
    """osi.py imports hyper.consts at module scope, so every probe here needs a
    real driver ISF -- there is no stub path."""
    return load_pyplugin(OSI, outdir=tmp_path, real_isf=isf,
                         doubles={"kffi": _KFFI([isf])})


# ---------------------------------------------------------------------------
# 1. get_env
# ---------------------------------------------------------------------------

def _environ(*entries):
    """Pack entries the way the guest stack holds environ: NUL-terminated."""
    return b"".join(e + b"\0" for e in entries)


@pytest.mark.parametrize("label,blob,expected", [
    ("a value containing '=' -- LS_COLORS is like this everywhere",
     _environ(b"LS_COLORS=rs=0:di=01;34:ln=01;36"),
     {"LS_COLORS": "rs=0:di=01;34:ln=01;36"}),
    ("a base64 value with '=' padding",
     _environ(b"TOKEN=YWJjZA==", b"PATH=/bin"),
     {"TOKEN": "YWJjZA==", "PATH": "/bin"}),
    ("an entry with no '=' at all is skipped, not fatal",
     _environ(b"BOGUS", b"PATH=/bin"),
     {"PATH": "/bin"}),
    ("the driver's failure sentinel, if it ever reached the host",
     b"UNKNOWN_PROCENV", {}),
    ("one '=' per entry, nothing exotic",
     _environ(b"PATH=/bin", b"HOME=/root", b"EMPTY="),
     {"PATH": "/bin", "HOME": "/root", "EMPTY": ""}),
    ("a value that is itself an assignment list",
     _environ(b"MAKEFLAGS=-j4 CC=gcc V=1"),
     {"MAKEFLAGS": "-j4 CC=gcc V=1"}),
])
def test_get_env_handles_ordinary_environments(tmp_path, igloo_ko_isf, label,
                                               blob, expected):
    """Every case here except the last two used to raise ValueError.

    The old body unpacked an unbounded ``split("=")`` into exactly two names,
    so a value containing ``=`` raised "too many values" and an entry without
    ``=`` raised "not enough values". Neither is malformed input from the
    kernel's point of view -- the environ block is copied verbatim from what
    execve was handed -- so neither may be an error. The exception escaped into
    the caller: syscalls_logger, lifeguard, anything on the process-tree path.
    """
    lp = _load(tmp_path, igloo_ko_isf)
    assert drive(lp.plugin.get_env(pid=1), responses=[blob]) == expected, label


def test_get_env_keeps_the_last_value_for_a_duplicated_name(tmp_path,
                                                            igloo_ko_isf):
    """A duplicated name is legal in an environ block, and dict semantics keep
    the last. Pinned so the partition() rewrite is not read as changing it."""
    lp = _load(tmp_path, igloo_ko_isf)
    env = drive(lp.plugin.get_env(pid=1),
                responses=[_environ(b"PATH=/bin", b"PATH=/usr/bin")])
    assert env == {"PATH": "/usr/bin"}


def test_get_env_returns_empty_when_the_read_failed(tmp_path, igloo_ko_isf):
    """READ_FAIL reaches the plugin as None, so the sentinel never surfaces.

    Worth pinning: handle_op_read_procenv's failure path *writes* the literal
    string ``UNKNOWN_PROCENV`` into the region, but portal.py drops the payload
    for HYPER_RESP_READ_FAIL and returns None, so that sentinel is unreachable
    dead weight rather than a fabricated environment. The parametrized probe
    above covers what would happen if portal.py ever started forwarding failed
    payloads: an empty dict, not a raise.
    """
    lp = _load(tmp_path, igloo_ko_isf)
    assert drive(lp.plugin.get_env(pid=1), responses=[None]) == {}


# ---------------------------------------------------------------------------
# 2. get_args -- NOT fixed; these assert the loss
# ---------------------------------------------------------------------------

def _driver_procargs(argv):
    """Mirror handle_op_read_procargs: copy the argv block, NUL -> space.

    The driver copies ``[arg_start, arg_end)`` verbatim, then rewrites every
    NUL below the last byte to a space, then NUL-terminates. That is the whole
    transform; everything the host gets has already been through it.
    """
    blob = bytearray(b"".join(a + b"\0" for a in argv))
    for i in range(len(blob) - 1):
        if blob[i] == 0:
            blob[i] = 0x20
    return bytes(blob)


@pytest.mark.parametrize("argv,expected,why", [
    ([b"httpd", b"-p", b"80"], ["httpd", "-p", "80"],
     "no argument contains whitespace, so the round trip happens to work"),
    ([b"sh", b"-c", b"echo hi > /tmp/x"],
     ["sh", "-c", "echo", "hi", ">", "/tmp/x"],
     "a space inside an argument becomes an argument boundary -- and 'sh -c' "
     "is how essentially every init script runs"),
    ([b"prog", b"", b"-x"], ["prog", "-x"],
     "an empty argument leaves two adjacent separators, which split() eats"),
    ([b"prog", b"a\tb"], ["prog", "a", "b"],
     "str.split() with no argument splits on any whitespace, not just space"),
    ([b"prog", b"--msg=one\ntwo"], ["prog", "--msg=one", "two"],
     "a newline inside an argument splits it too"),
    ([b"prog", b"\xa0x"], ["prog", "x"],
     "latin-1 decodes byte 0xA0 to U+00A0 NO-BREAK SPACE, which str.split() "
     "treats as whitespace -- so a UTF-8 argument is cut at its 0xA0 bytes"),
    ([b"prog", b"a\x01b"], ["prog"],
     "the isprintable() filter drops a whole argument containing a control "
     "byte, silently shifting every later argument's index"),
])
def test_get_args_cannot_reproduce_argv(tmp_path, igloo_ko_isf, argv,
                                        expected, why):
    """Pin exactly how much of argv survives driver + host.

    ``expected`` is what the plugin returns *today*. Where it differs from
    ``argv`` the difference is unrecoverable host-side, because the NULs that
    marked the boundaries are gone by the time the host sees the blob.
    """
    lp = _load(tmp_path, igloo_ko_isf)
    got = drive(lp.plugin.get_args(pid=1), responses=[_driver_procargs(argv)])
    assert got == expected, why


def test_argv_boundaries_are_recoverable_if_the_driver_keeps_the_nuls(
        tmp_path, igloo_ko_isf):
    """The information loss is a choice, not a limit of the wire format.

    ``header.size`` already carries the true blob length, so the host does not
    need the separators to be printable. Splitting the *unconverted* blob on
    NUL reproduces argv byte-exactly for every case the parametrized probe
    above mangles -- including the empty argument and the embedded newline.
    This is the assertion a driver-side fix should make get_args satisfy.
    """
    hard = [b"sh", b"-c", b"echo hi", b"", b"a\tb", b"--msg=one\ntwo"]
    raw = b"".join(a + b"\0" for a in hard)          # what the driver copied
    exact = [s.decode("latin-1") for s in raw.split(b"\0")[:-1]]
    assert exact == [a.decode("latin-1") for a in hard]

    lossy = drive(_load(tmp_path, igloo_ko_isf).plugin.get_args(pid=1),
                  responses=[_driver_procargs(hard)])
    assert lossy != exact
    assert len(lossy) > len(exact)                    # split, not merged


def test_get_proc_name_inherits_the_argv_split(tmp_path, igloo_ko_isf):
    """get_proc_name is argv[0], so it is only as good as get_args.

    argv[0] rarely contains whitespace, so this is usually right -- but when it
    does, the process *name* is truncated at the first space rather than the
    whole argument being kept.
    """
    lp = _load(tmp_path, igloo_ko_isf)
    name = drive(lp.plugin.get_proc_name(pid=1),
                 responses=[_driver_procargs([b"/opt/My App/httpd", b"-f"])])
    assert name == "/opt/My"


def test_get_proc_name_falls_back_when_the_read_failed(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert drive(lp.plugin.get_proc_name(pid=1), responses=[None]) == "[???]"


# ---------------------------------------------------------------------------
# 3. get_fds pagination
# ---------------------------------------------------------------------------

def _driver_read_fds(open_fds, start_fd, max_fds=DRIVER_MAX_FDS,
                     chunk_size=CHUNK_SIZE):
    """Mirror handle_op_read_fds for one request.

    Returns ``(payload, resume_fd)``. ``resume_fd`` is what the driver writes
    to ``header.addr`` when it stops early -- the fd it fetched but did not
    store -- and 0 when it walked to the end. The host does not read it; see
    the cross-check at the bottom of this file.
    """
    total = len(open_fds)
    string_offset = FD_HDR + max_fds * FD_ENT
    entries, strings, resume = [], bytearray(), 0
    for fd in sorted(open_fds):
        if fd < start_fd:
            continue
        if len(entries) >= max_fds:
            resume = fd
            break
        name = f"/dev/fd-{fd}".encode()
        if string_offset + len(name) + 1 > chunk_size:
            resume = fd
            break
        entries.append((fd, string_offset))
        strings += name + b"\0"
        string_offset += len(name) + 1

    buf = bytearray(struct.pack("<QQ", len(entries), total))
    buf += b"".join(struct.pack("<QQ", fd, off) for fd, off in entries)
    buf += b"\0" * (FD_HDR + max_fds * FD_ENT - len(buf))
    buf += strings
    return bytes(buf), resume


def _run_get_fds(lp, open_fds, max_fds=DRIVER_MAX_FDS):
    """Pump get_fds, answering each request from the simulated driver.

    Hand-rolled rather than using ``drive`` because the response depends on the
    ``start_fd`` in the request, which is the whole subject here.
    """
    gen = lp.plugin.get_fds(pid=1)
    requests, resumes = [], []
    try:
        cmd = gen.send(None)
        while True:
            requests.append(cmd.addr)
            payload, resume = _driver_read_fds(open_fds, cmd.addr, max_fds)
            resumes.append(resume)
            if len(requests) > 32:                    # runaway guard
                pytest.fail(f"get_fds did not terminate: requests={requests}")
            cmd = gen.send(payload)
    except StopIteration as e:
        return e.value, requests, resumes


def test_get_fds_is_correct_for_a_dense_table(tmp_path, igloo_ko_isf):
    """One batch, no pagination: the common case, and it always worked."""
    lp = _load(tmp_path, igloo_ko_isf)
    fds, requests, _ = _run_get_fds(lp, [0, 1, 2, 3])
    assert [f.fd for f in fds] == [0, 1, 2, 3]
    assert [f.name for f in fds] == [f"/dev/fd-{n}" for n in range(4)]
    assert requests == [0]


def test_get_fds_paginates_a_dense_table_correctly(tmp_path, igloo_ko_isf):
    """When the table is dense, 'advance by count' and 'advance to the next fd'
    coincide -- which is why the old arithmetic looked right."""
    lp = _load(tmp_path, igloo_ko_isf)
    dense = list(range(10))
    fds, requests, _ = _run_get_fds(lp, dense, max_fds=4)
    assert [f.fd for f in fds] == dense
    assert requests == [0, 4, 8]


def test_get_fds_is_correct_for_a_sparse_table(tmp_path, igloo_ko_isf):
    """The case that used to come back duplicated *and* incomplete.

    ``current_fd += batch_count`` treated an fd number as an index. For a
    process holding stdio plus a block of high fds, the driver filled its first
    batch at fd 100 and the host then asked to resume at fd 4 -- re-reading the
    same window (fds 100-103 came back twice) while fds 104-109 were never
    requested at all. Advancing to ``highest fd decoded + 1`` is exact, because
    the driver walks fds in ascending order.
    """
    lp = _load(tmp_path, igloo_ko_isf)
    sparse = [0, 1, 2] + list(range(100, 110))       # 13 fds, very sparse
    fds, requests, resumes = _run_get_fds(lp, sparse, max_fds=4)
    got = [f.fd for f in fds]

    assert got == sparse, f"fds mis-paginated: {got}"
    assert len(got) == len(set(got)), f"duplicate fds reported: {got}"
    assert [f.name for f in fds] == [f"/dev/fd-{n}" for n in sparse]

    # Every resume lands at or before the fd the driver itself stopped at, so
    # nothing is skipped even though the two cursors are not equal.
    assert requests == [0, 101, 105, 109]
    for asked, driver_stopped_at in zip(requests[1:], resumes):
        assert driver_stopped_at == 0 or asked <= driver_stopped_at


def test_get_fds_advances_past_a_single_huge_fd(tmp_path, igloo_ko_isf):
    """One fd far above the batch size. The cursor jumps to it in one hop
    rather than crawling; and, unlike the old arithmetic, it does not overshoot
    the gap and lose it."""
    lp = _load(tmp_path, igloo_ko_isf)
    fds, requests, _ = _run_get_fds(lp, [0, 1, 1000000], max_fds=2)
    assert [f.fd for f in fds] == [0, 1, 1000000]
    assert requests == [0, 2]


def test_get_fds_stops_if_a_batch_decodes_nothing(tmp_path, igloo_ko_isf):
    """A batch that claims entries but yields none has no high-water mark.

    Advancing by the claimed count used to paper over this; advancing by the
    last fd seen cannot, so the loop must stop explicitly rather than
    re-request the same window forever. Simulated with a truncated payload:
    result_count says 4, the buffer holds no entries at all.
    """
    lp = _load(tmp_path, igloo_ko_isf)
    gen = lp.plugin.get_fds(pid=1)
    truncated = struct.pack("<QQ", 4, 99)            # header only, no entries
    requests = []
    try:
        cmd = gen.send(None)
        for _ in range(8):
            requests.append(cmd.addr)
            cmd = gen.send(truncated)
    except StopIteration as e:
        assert e.value == []
        assert requests == [0], f"looped instead of stopping: {requests}"
        return
    pytest.fail(f"get_fds did not terminate: requests={requests}")


def test_driver_resume_cursor_and_host_cursor_agree_on_coverage(tmp_path,
                                                                igloo_ko_isf):
    """Cross-check the host's cursor against the driver's own, same table.

    The driver reports the fd it stopped at in ``header.addr``, and portal.py
    discards that for HYPER_RESP_READ_OK. Walking the simulated driver by its
    own cursor produces exactly what the plugin produces, so not reading
    ``header.addr`` costs no coverage and no ABI change is owed here.
    """
    sparse = [0, 1, 2] + list(range(100, 110))
    by_driver_cursor, start = [], 0
    while True:
        payload, resume = _driver_read_fds(sparse, start, max_fds=4)
        count = struct.unpack_from("<Q", payload, 0)[0]
        for i in range(count):
            fd, _off = struct.unpack_from("<QQ", payload, FD_HDR + i * FD_ENT)
            by_driver_cursor.append(fd)
        if not resume:
            break
        start = resume
    assert by_driver_cursor == sparse

    lp = _load(tmp_path, igloo_ko_isf)
    by_host, _, _ = _run_get_fds(lp, sparse, max_fds=4)
    assert [f.fd for f in by_host] == by_driver_cursor
