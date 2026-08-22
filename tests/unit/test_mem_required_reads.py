"""``mem`` reads never fail -- and ``required=True`` is how a caller opts out.

The default contract is deliberate: unreadable guest memory is reported as NUL
bytes rather than an exception, so a plugin can dereference a bad pointer
without a guard and hundreds of call sites stay free of try/except. The cost is
that a fabricated zero is indistinguishable from a real one, which is fine for
a log line and not fine for a decision.

Every probe below is a pair: what the default returns (fabricated), and what
``required=True`` returns for the same failure (``None``). Both halves are
pinned, so a change to either is a change to a documented assertion.

Note the `None` returns these make reachable were already documented -- the
`if len(data) != 4: return None` guards in read_int/read_long/read_byte/
read_word could never fire, because read_bytes always padded to length.

mem.py imports the real HYPER_OP enum, so every test needs the pinned driver
ISF. ``__init__`` is skipped (it does `panda.bits // 8` on a recorder stub);
the handful of attributes the readers touch are set directly, which is the
harness's documented pattern for exactly this.
"""
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
MEM = str(REPO_ROOT / "pyplugins" / "apis" / "mem.py")

# read_str's own constants, restated so the probes can compute chunk sizes.
PORTAL_CHUNK_SIZE = 0x1000 - 48
SAFE_MAX = 4096 - 24


def _load(tmp_path, isf, bits=64, rsize=4072):
    lp = load_pyplugin(MEM, outdir=tmp_path, real_isf=isf, call_init=False)
    m = lp.plugin
    m.endian_format = "<"
    m.endian_str = "little"
    # The whole point is to exercise the portal path, so keep PANDA out of it.
    m.try_panda = False
    m._get_cpu = lambda: None
    m._rsize = rsize
    m.ptr_size = bits // 8
    m.ptr_typ = f"uint{bits}_t"
    m.addr_mask = 0xFFFFFFFF if bits == 32 else 0xFFFFFFFFFFFFFFFF
    # __init__ normally binds read_ptr to read_int/read_long; do it here since
    # __init__ did not run.
    m.read_ptr = m.read_int if bits == 32 else m.read_long
    return m


def _drive(gen, responses):
    """Run a portal generator, feeding `responses` to successive yields."""
    it = iter(responses)
    try:
        gen.send(None)
        while True:
            gen.send(next(it, None))
    except StopIteration as e:
        return e.value


# --------------------------------------------------------------------------
# read_bytes -- the primitive every other reader sits on
# --------------------------------------------------------------------------

def test_read_bytes_fabricates_zeros_for_a_failed_read(tmp_path, igloo_ko_isf):
    """The default contract. A portal READ_FAIL arrives as None (portal.py
    drops the payload), and comes back as data."""
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read_bytes(0x1000, 8), [None]) == b"\x00" * 8


def test_read_bytes_required_reports_the_failure(tmp_path, igloo_ko_isf):
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read_bytes(0x1000, 8, required=True), [None]) is None


def test_read_bytes_pads_a_short_read_and_required_does_not(tmp_path, igloo_ko_isf):
    """A HYPER_RESP_READ_PARTIAL arrives short: the driver reports exactly how
    much was readable, and the default pads that information away."""
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read_bytes(0x1000, 8), [b"ab"]) == b"ab" + b"\x00" * 6
    assert _drive(m.read_bytes(0x1000, 8, required=True), [b"ab"]) is None


def test_read_bytes_success_is_identical_in_both_modes(tmp_path, igloo_ko_isf):
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read_bytes(0x1000, 4), [b"wxyz"]) == b"wxyz"
    assert _drive(m.read_bytes(0x1000, 4, required=True), [b"wxyz"]) == b"wxyz"


def test_read_bytes_multi_chunk_failure(tmp_path, igloo_ko_isf):
    """The slow path chunks by rsize; a failure in any chunk must not be
    papered over by the chunks that succeeded around it."""
    m = _load(tmp_path, igloo_ko_isf, rsize=4)
    ok = _drive(m.read_bytes(0x1000, 12), [b"aaaa", None, b"cccc"])
    assert ok == b"aaaa" + b"\x00" * 4 + b"cccc"
    strict = _drive(m.read_bytes(0x1000, 12, required=True),
                    [b"aaaa", None, b"cccc"])
    assert strict is None


# --------------------------------------------------------------------------
# scalars -- where the unreachable `None` guards become reachable
# --------------------------------------------------------------------------

@pytest.mark.parametrize("reader,width,zero", [
    ("read_byte", 1, 0),
    ("read_word", 2, 0),
    ("read_int", 4, 0),
    ("read_long", 8, 0),
])
def test_scalars_read_unmapped_memory_as_zero(tmp_path, igloo_ko_isf,
                                              reader, width, zero):
    """An unmapped address is reported as the value 0, which is a perfectly
    ordinary thing for the memory to contain."""
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(getattr(m, reader)(0x1000), [None]) == zero


@pytest.mark.parametrize("reader", ["read_byte", "read_word",
                                    "read_int", "read_long"])
def test_scalars_required_return_none(tmp_path, igloo_ko_isf, reader):
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(getattr(m, reader)(0x1000, required=True), [None]) is None


def test_read_ptr_forwards_required_through_the_init_binding(tmp_path, igloo_ko_isf):
    """read_ptr is bound to read_int/read_long at construction, so `required`
    has to survive the indirection rather than being swallowed by it."""
    m64 = _load(tmp_path, igloo_ko_isf, bits=64)
    assert _drive(m64.read_ptr(0x1000), [None]) == 0
    assert _drive(m64.read_ptr(0x1000, required=True), [None]) is None

    m32 = _load(tmp_path, igloo_ko_isf, bits=32)
    assert _drive(m32.read_ptr(0x1000), [None]) == 0
    assert _drive(m32.read_ptr(0x1000, required=True), [None]) is None


def test_a_fabricated_pointer_is_indistinguishable_from_NULL(tmp_path, igloo_ko_isf):
    """The concrete reason `required` exists for pointers: these two cases are
    the same value by default and different values with it."""
    m = _load(tmp_path, igloo_ko_isf)
    real_null = _drive(m.read_ptr(0x1000), [b"\x00" * 8])
    unreadable = _drive(m.read_ptr(0x1000), [None])
    assert real_null == unreadable == 0

    real_null = _drive(m.read_ptr(0x1000, required=True), [b"\x00" * 8])
    unreadable = _drive(m.read_ptr(0x1000, required=True), [None])
    assert real_null == 0
    assert unreadable is None


# --------------------------------------------------------------------------
# read_str -- two distinct truncations
# --------------------------------------------------------------------------

def test_read_str_returns_a_partial_string_when_a_page_is_unreadable(
        tmp_path, igloo_ko_isf):
    """read_str walks page by page so it can cross page boundaries, which makes
    "the next page is unmapped" the expected failure -- and by default it comes
    back as a complete-looking short string."""
    m = _load(tmp_path, igloo_ko_isf)
    # First chunk fills to the page boundary with no NUL, second read fails.
    first = b"A" * PORTAL_CHUNK_SIZE
    assert _drive(m.read_str(0x1000), [first, None]) == "A" * PORTAL_CHUNK_SIZE
    assert _drive(m.read_str(0x1000, required=True), [first, None]) is None


def test_read_str_truncates_at_the_cap_without_saying_so(tmp_path, igloo_ko_isf):
    """SAFE_MAX is one portal region, which is smaller than PATH_MAX (4096) --
    so a long path is truncated and reads as whole."""
    m = _load(tmp_path, igloo_ko_isf)
    first = b"B" * PORTAL_CHUNK_SIZE
    second = b"B" * (SAFE_MAX - PORTAL_CHUNK_SIZE)
    out = _drive(m.read_str(0x1000), [first, second])
    assert out == "B" * SAFE_MAX
    assert len(out) < 4096, "the cap is below PATH_MAX -- that is the point"
    assert _drive(m.read_str(0x1000, required=True), [first, second]) is None


def test_read_str_success_is_identical_in_both_modes(tmp_path, igloo_ko_isf):
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read_str(0x1000), [b"/bin/sh\x00rest"]) == "/bin/sh"
    assert _drive(m.read_str(0x1000, required=True),
                  [b"/bin/sh\x00rest"]) == "/bin/sh"


def test_read_str_of_a_null_pointer(tmp_path, igloo_ko_isf):
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read_str(0), []) == ""
    assert _drive(m.read_str(0, required=True), []) is None


def test_read_utf8_str_propagates_required(tmp_path, igloo_ko_isf):
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read_utf8_str(0x1000), [None]) == ""
    assert _drive(m.read_utf8_str(0x1000, required=True), [None]) is None


# --------------------------------------------------------------------------
# lists and arrays
# --------------------------------------------------------------------------

def test_read_ptrlist_stops_at_an_unreadable_slot_and_calls_it_the_end(
        tmp_path, igloo_ko_isf):
    """The zero-fill makes an unreadable slot look like the NULL terminator, so
    the walk ends early and reports a short list as a complete one."""
    m = _load(tmp_path, igloo_ko_isf)
    resp = [(1).to_bytes(8, "little"), (2).to_bytes(8, "little"), None]
    assert _drive(m.read_ptrlist(0x1000, 8), list(resp)) == [1, 2]
    assert _drive(m.read_ptrlist(0x1000, 8, required=True), list(resp)) is None


def test_read_ptrlist_a_real_terminator_still_ends_the_list(tmp_path, igloo_ko_isf):
    """`required` must not turn a legitimate NULL terminator into a failure."""
    m = _load(tmp_path, igloo_ko_isf)
    resp = [(1).to_bytes(8, "little"), (0).to_bytes(8, "little")]
    assert _drive(m.read_ptrlist(0x1000, 8, required=True), list(resp)) == [1]


def test_read_char_ptrlist_required_reaches_the_strings(tmp_path, igloo_ko_isf):
    """required has to propagate two levels: through the pointer walk and into
    each string read underneath it."""
    m = _load(tmp_path, igloo_ko_isf)
    # One good pointer, terminator, then the string read behind it fails.
    resp = [(0x2000).to_bytes(8, "little"), (0).to_bytes(8, "little"), None]
    assert _drive(m.read_char_ptrlist(0x1000, 4), list(resp)) == [""]
    assert _drive(m.read_char_ptrlist(0x1000, 4, required=True),
                  list(resp)) is None


@pytest.mark.parametrize("reader,count", [
    ("read_int_array", 3),
    ("read_long_array", 3),
    ("read_uint64_array", 3),
])
def test_arrays_read_unmapped_memory_as_an_array_of_zeros(
        tmp_path, igloo_ko_isf, reader, count):
    """Not `[]` -- an array of zeros.

    These readers guard with `if len(data) != N * count: return []`, and that
    guard is as unreachable as the scalar ones: read_bytes pads to full length,
    so the unpack always succeeds and produces zeros. An unreadable array is
    therefore a plausible all-zero array, and the documented empty-list failure
    return never happens.
    """
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(getattr(m, reader)(0x1000, count), [None]) == [0] * count
    assert _drive(getattr(m, reader)(0x1000, count, required=True),
                  [None]) is None


# --------------------------------------------------------------------------
# memcmp -- the one case where the default answer is certainly wrong
# --------------------------------------------------------------------------

def test_memcmp_calls_two_unreadable_regions_equal(tmp_path, igloo_ko_isf):
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.memcmp(0x1000, 0x2000, 16), [None, None]) is True
    assert _drive(m.memcmp(0x1000, 0x2000, 16, required=True),
                  [None, None]) is None


def test_memcmp_still_compares_readable_regions(tmp_path, igloo_ko_isf):
    m = _load(tmp_path, igloo_ko_isf)
    same = [b"a" * 4, b"a" * 4]
    diff = [b"a" * 4, b"b" * 4]
    assert _drive(m.memcmp(0x1000, 0x2000, 4, required=True), same) is True
    assert _drive(m.memcmp(0x1000, 0x2000, 4, required=True), diff) is False


# --------------------------------------------------------------------------
# the smart dispatcher
# --------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs,default", [
    ({"size": 4, "fmt": bytes}, b"\x00" * 4),
    ({"fmt": str}, ""),
    ({"size": 4, "fmt": int}, 0),
    ({"size": 8, "fmt": "ptr"}, 0),
    ({"size": 2, "fmt": list}, [0, 0]),
])
def test_read_dispatcher_forwards_required(tmp_path, igloo_ko_isf,
                                           kwargs, default):
    """`read` picks a reader by format; `required` has to survive every branch,
    not just the ones that happen to be tested elsewhere."""
    m = _load(tmp_path, igloo_ko_isf)
    assert _drive(m.read(0x1000, **kwargs), [None]) == default
    assert _drive(m.read(0x1000, required=True, **kwargs), [None]) is None
