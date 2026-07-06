"""Host-side unit tests for the ``binary_patch`` logic in the LiveImage plugin,
driven through the ``penguin.testing`` harness — no PANDA, no guest, no per-arch
boot.

This file was the original hand-rolled ``sys.modules``-stub hack that motivated
the harness; it now loads the real plugin in place via ``load_pyplugin`` and
controls the one sibling it touches (``static_fs``) with a ``doubles=`` entry.

Scope (per ``docs/testing.md``): the host-side patch *logic* is what runs on the
host — hex parsing, ``expect``/``on_mismatch`` verification, idempotent re-runs,
multi-edit application with overlap + bounds rejection, the windowed-transfer
offset math, provenance records, and the batch-hypercall handler's abort
contract against a pre-staged window. The guest round-trip itself (the real
``hyp_file_op --range`` transport) and keystone ``asm`` assembly stay
``tests/integration`` fixtures (``live_image.yaml``): they need the guest / a
native toolchain, which the harness cannot fake faithfully.
"""
from pathlib import Path

import pytest
import yaml

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_IMAGE = REPO_ROOT / "pyplugins" / "core" / "live_image.py"

ORIG = b"\x01\x02\x03\x04rest"


def _load(tmp_path, conf=None, doubles=None):
    """Construct a real LiveImage via the harness. ``proj_dir``/``conf`` satisfy
    ``__init__``; ``outdir`` (wired into ``get_arg('outdir')``) is where the
    provenance report lands."""
    return load_pyplugin(
        str(LIVE_IMAGE),
        outdir=tmp_path,
        args={"proj_dir": str(tmp_path), "conf": conf or {}},
        doubles=doubles or {},
    )


@pytest.fixture
def li(tmp_path):
    """A real, harness-constructed LiveImage instance (no framework stubbing)."""
    return _load(tmp_path).plugin


class _FakeStaticFs:
    """Double for the one sibling ``_check_patch_within_file`` calls. ``size``
    is what ``get_size`` returns; if it is an Exception instance, raising it
    models the defensive 'size can't be determined' path."""

    def __init__(self, size):
        self._size = size

    def get_size(self, path, transparent=frozenset()):
        if isinstance(self._size, Exception):
            raise self._size
        return self._size


# --- _parse_hex -----------------------------------------------------------
@pytest.mark.parametrize("text,expected", [
    ("aabb", b"\xaa\xbb"),
    ("AA BB", b"\xaa\xbb"),
    ("0xaabb", b"\xaa\xbb"),
    ("0X AA BB", b"\xaa\xbb"),
    ("  deadbeef  ", b"\xde\xad\xbe\xef"),
])
def test_parse_hex_accepts_prefix_and_spaces(li, text, expected):
    assert li._parse_hex(text) == expected


@pytest.mark.parametrize("bad", ["zz", "abc", "0xzz"])
def test_parse_hex_rejects_bad(li, bad):
    with pytest.raises(ValueError):
        li._parse_hex(bad)


# --- _verify_entry (expect / on_mismatch) ---------------------------------
def test_verify_no_expect_applies(li):
    assert li._verify_entry(ORIG, {"file_offset": 0}, b"\xaa") == ("applied", "")


def test_verify_match_applies(li):
    st, _ = li._verify_entry(ORIG, {"file_offset": 0, "expect": "01020304"}, b"\xaa")
    assert st == "applied"


def test_verify_expect_shorter_than_patch(li):
    # verify 2 bytes, patch writes 4 — allowed, they need not match in length
    st, _ = li._verify_entry(ORIG, {"file_offset": 0, "expect": "0102"},
                             b"\xaa\xbb\xcc\xdd")
    assert st == "applied"


def test_verify_mismatch_default_fails(li):
    st, detail = li._verify_entry(ORIG, {"file_offset": 0, "expect": "ffff"}, b"\xaa")
    assert st == "failed"
    assert "expected ffff" in detail and "found 0102" in detail


def test_verify_mismatch_skip(li):
    st, _ = li._verify_entry(ORIG, {"file_offset": 0, "expect": "ffff",
                                    "on_mismatch": "skip"}, b"\xaa")
    assert st == "skipped"


def test_verify_mismatch_warn_applies(li):
    st, detail = li._verify_entry(ORIG, {"file_offset": 0, "expect": "ffff",
                                         "on_mismatch": "warn"}, b"\xaa")
    assert st == "applied"
    assert "patched despite mismatch" in detail


def test_verify_already_patched_idempotent_skip_under_fail(li):
    already = b"\xaa\xbb\xcc\xddrest"
    st, detail = li._verify_entry(already, {"file_offset": 0, "expect": "01020304"},
                                  b"\xaa\xbb\xcc\xdd")  # default fail
    assert st == "skipped"
    assert "already patched" in detail


def test_verify_expect_past_eof_reports(li):
    st, detail = li._verify_entry(b"\x01", {"file_offset": 100, "expect": "bb"}, b"\xaa")
    assert st == "failed"
    assert "<EOF>" in detail and "file is 1 bytes" in detail


# --- _normalize_patch_entries ---------------------------------------------
def test_normalize_inline_single(li):
    entries, err = li._normalize_patch_entries(
        {"file_offset": 4, "hex_bytes": "aa"})
    assert err is None and len(entries) == 1 and entries[0]["file_offset"] == 4


def test_normalize_patches_list(li):
    entries, err = li._normalize_patch_entries(
        {"patches": [{"file_offset": 0, "hex_bytes": "aa"},
                     {"file_offset": 8, "asm": "nop"}]})
    assert err is None and len(entries) == 2


def test_normalize_both_forms_errors(li):
    entries, err = li._normalize_patch_entries(
        {"file_offset": 0, "hex_bytes": "aa", "patches": [{"file_offset": 8}]})
    assert entries is None and "action level" in err


def test_normalize_empty_needs_offset_or_list(li):
    entries, err = li._normalize_patch_entries({"hex_bytes": "aa"})
    assert entries is None and "file_offset" in err


def test_normalize_action_level_fields_with_patches_rejected(li):
    # per-edit fields at the action level are silently meaningless with patches;
    # the applier must reject the mix rather than drop them
    entries, err = li._normalize_patch_entries(
        {"expect": "0102", "why": "oops", "patches": [{"file_offset": 0, "hex_bytes": "aa"}]})
    assert entries is None and "action level" in err


def test_normalize_inline_keeps_all_fields(li):
    # a new/late field on the action flows through to the inline entry
    entries, err = li._normalize_patch_entries(
        {"type": "binary_patch", "file_offset": 4, "hex_bytes": "aa",
         "expect": "01", "why": "w", "tag": "t", "on_mismatch": "warn"})
    assert err is None
    e = entries[0]
    assert "type" not in e and e["on_mismatch"] == "warn" and e["why"] == "w"


# --- _synth_file_patch_action (compose: patch a placed file) --------------
def test_synth_none_without_patches(li):
    # a plain host_file/inline_file with no patches produces nothing to queue
    assert li._synth_file_patch_action(
        "/foo", {"type": "host_file", "host_path": "x"}) is None
    assert li._synth_file_patch_action(
        "/foo", {"type": "inline_file", "contents": "x"}) is None


def test_synth_builds_binary_patch_action(li):
    patches = [{"file_offset": 0, "hex_bytes": "50", "expect": "4f"}]
    synth = li._synth_file_patch_action(
        "/testfile7.bin", {"type": "inline_file", "contents": "ORIGINAL",
                           "patches": patches})
    assert synth["type"] == "binary_patch"
    assert synth["patches"] == patches
    # it must feed the existing pipeline cleanly (no action-level-mix error)
    entries, err = li._normalize_patch_entries(synth)
    assert err is None and len(entries) == 1 and entries[0]["file_offset"] == 0


def test_synth_copies_patches_list(li):
    # the synthetic action must not alias the config's list
    patches = [{"file_offset": 0, "hex_bytes": "aa"}]
    synth = li._synth_file_patch_action(
        "/f", {"type": "host_file", "host_path": "x", "patches": patches})
    assert synth["patches"] is not patches and synth["patches"] == patches


@pytest.mark.parametrize("file_path,action", [
    ("/dir/*", {"type": "host_file", "host_path": "src/bin",
                "patches": [{"file_offset": 0, "hex_bytes": "aa"}]}),
    ("/dir/f?", {"type": "host_file", "host_path": "src/bin",
                 "patches": [{"file_offset": 0, "hex_bytes": "aa"}]}),
    ("/f", {"type": "host_file", "host_path": "src/*.bin",
            "patches": [{"file_offset": 0, "hex_bytes": "aa"}]}),
    ("/f", {"type": "host_file", "host_path": "src/b?n",
            "patches": [{"file_offset": 0, "hex_bytes": "aa"}]}),
])
def test_synth_rejects_glob_targets(li, file_path, action):
    with pytest.raises(ValueError, match="ambiguous"):
        li._synth_file_patch_action(file_path, action)


# --- _entry_patch_bytes ---------------------------------------------------
def test_entry_bytes_hex(li):
    pb, err = li._entry_patch_bytes({"file_offset": 0, "hex_bytes": "0x aa bb"})
    assert err is None and pb == b"\xaa\xbb"


def test_entry_bytes_both_hex_and_asm_errors(li):
    pb, err = li._entry_patch_bytes({"file_offset": 0, "hex_bytes": "aa", "asm": "nop"})
    assert pb is None and "exactly one" in err


def test_entry_bytes_neither_errors(li):
    pb, err = li._entry_patch_bytes({"file_offset": 0})
    assert pb is None and "exactly one" in err


# --- _apply_binary_patch (whole action) -----------------------------------
def test_apply_single_inline(li):
    new, recs, failed = li._apply_binary_patch(
        ORIG, {"file_offset": 0, "hex_bytes": "aabbccdd"})
    assert not failed and new == b"\xaa\xbb\xcc\xddrest"
    assert recs[0]["result"] == "applied"


def test_apply_multiple_disjoint_offsets(li):
    orig = b"\x00" * 16
    new, recs, failed = li._apply_binary_patch(orig, {"patches": [
        {"file_offset": 0, "hex_bytes": "aabb", "tag": "t", "why": "first"},
        {"file_offset": 8, "hex_bytes": "ccdd", "tag": "t", "why": "second"},
    ]})
    assert not failed
    assert new == b"\xaa\xbb" + b"\x00" * 6 + b"\xcc\xdd" + b"\x00" * 6
    assert [r["result"] for r in recs] == ["applied", "applied"]
    assert recs[0]["why"] == "first" and recs[1]["file_offset"] == "0x8"


def test_apply_overlapping_offsets_rejected(li):
    orig = b"\x00" * 16
    new, recs, failed = li._apply_binary_patch(orig, {"patches": [
        {"file_offset": 0, "hex_bytes": "aabbccdd"},   # covers 0..4
        {"file_offset": 2, "hex_bytes": "eeff"},        # covers 2..4 -> overlaps
    ]})
    assert failed and new is None
    assert all(r["result"] == "failed" for r in recs)
    assert any("overlaps" in r.get("detail", "") for r in recs)


def test_apply_contained_overlap_rejected(li):
    # a small edit fully inside a larger edit's range must be flagged even
    # though it is not adjacent to it once ranges are sorted by start
    orig = b"\x00" * 32
    new, recs, failed = li._apply_binary_patch(orig, {"patches": [
        {"file_offset": 0, "hex_bytes": "aabbccddeeff00112233"},  # 0..10
        {"file_offset": 20, "hex_bytes": "0102"},                 # 20..22 (disjoint)
        {"file_offset": 4, "hex_bytes": "99"},                    # 4..5, inside 0..10
    ]})
    assert failed and new is None
    by_off = {r["file_offset"]: r["result"] for r in recs}
    assert by_off["0x0"] == "failed" and by_off["0x4"] == "failed"
    assert by_off["0x14"] == "applied"  # the disjoint one is not falsely flagged


def test_apply_offset_past_end_fails_not_corrupts(li):
    # an offset past the end of the buffer must fail cleanly rather than let
    # bytearray slice-assignment silently append the patch at the wrong place
    orig = b"\x00\x01"
    new, recs, failed = li._apply_binary_patch(
        orig, {"file_offset": 5, "hex_bytes": "aabb"})
    assert failed and new is None
    assert "outside" in recs[0]["detail"]


def test_apply_short_window_fails_not_corrupts(li):
    # the guest may return a shorter window than declared (file smaller than
    # the patch expected + no expect guard); the edit at the far end must fail,
    # not land appended at the end of the short read
    window = b"AB"                       # declared window was longer
    new, recs, failed = li._apply_binary_patch(
        window, {"patches": [{"file_offset": 8, "hex_bytes": "cc"}]},
        base_offset=8)                   # offset 8, base 8 -> pos 0, fits len-2 buffer
    assert not failed
    # now a far offset within the same declared window but past the short read
    new2, recs2, failed2 = li._apply_binary_patch(
        window, {"patches": [{"file_offset": 16, "hex_bytes": "cc"}]},
        base_offset=8)                   # pos 8 into a 2-byte buffer -> out of range
    assert failed2 and new2 is None
    assert "outside" in recs2[0]["detail"]


def test_apply_one_failed_policy_aborts_whole_file(li):
    orig = b"\x00" * 16
    new, recs, failed = li._apply_binary_patch(orig, {"patches": [
        {"file_offset": 0, "hex_bytes": "aabb"},                       # ok
        {"file_offset": 8, "hex_bytes": "ccdd", "expect": "ffff"},     # mismatch, fail
    ]})
    assert failed and new is None  # nothing written back when any edit fails


def test_apply_skip_leaves_region_untouched_but_applies_others(li):
    orig = b"\xde\xad" + b"\x00" * 14
    new, recs, failed = li._apply_binary_patch(orig, {"patches": [
        {"file_offset": 0, "hex_bytes": "aabb", "expect": "ffff", "on_mismatch": "skip"},
        {"file_offset": 8, "hex_bytes": "ccdd"},
    ]})
    assert not failed
    assert new[:2] == b"\xde\xad"        # skipped edit left original bytes
    assert new[8:10] == b"\xcc\xdd"      # other edit applied
    assert recs[0]["result"] == "skipped"


def test_apply_with_base_offset(li):
    # original_content is only the window starting at base_offset=0x100
    window = b"\xde\xad"
    new, recs, failed = li._apply_binary_patch(
        window, {"file_offset": 0x100, "hex_bytes": "aabb", "expect": "dead",
                 "tag": "t", "why": "w"}, base_offset=0x100)
    assert not failed and new == b"\xaa\xbb"
    assert recs[0]["file_offset"] == "0x100"   # provenance offset stays absolute


def test_verify_with_base_offset(li):
    window = b"\x01\x02\x03\x04"
    st, _ = li._verify_entry(window, {"file_offset": 0x1000, "expect": "0304"},
                             b"\xff\xff", base_offset=0x1000 - 2)
    assert st == "applied"  # expect '0304' checked at window pos 2


# --- windowed transfer (ranged hyp_file_op) -------------------------------
def test_patch_window_inline_single(li):
    assert li._patch_window({"file_offset": 0x10, "hex_bytes": "aabbccdd"}) == (0x10, 4)


def test_patch_window_expect_extends_span(li):
    # window must cover the longer of the patch (1 byte) and expect (4 bytes)
    assert li._patch_window(
        {"file_offset": 0x10, "hex_bytes": "aa", "expect": "01020304"}) == (0x10, 4)


def test_patch_window_multi_disjoint(li):
    base, length = li._patch_window({"patches": [
        {"file_offset": 0, "hex_bytes": "aabb"},   # 0..2
        {"file_offset": 8, "hex_bytes": "cc"},     # 8..9
    ]})
    assert (base, length) == (0, 9)


def test_patch_window_raises_on_bad_edit(li):
    with pytest.raises(ValueError):
        li._patch_window({"file_offset": 0, "hex_bytes": "aa", "asm": "nop"})


# --- bounds check against the static filesystem (static_fs double) --------
@pytest.mark.parametrize("base,win,size,expected", [
    (0, 4, None, False),   # unknown size -> never flagged
    (0, 4, 4, False),      # exactly fits
    (0, 4, 3, True),       # 1 byte past EOF
    (0x10, 4, 0x13, True),  # window 0x10..0x14 exceeds size 0x13
    (0x10, 4, 0x14, False),  # window 0x10..0x14 exactly fits size 0x14
])
def test_window_exceeds_size(li, base, win, size, expected):
    assert li._window_exceeds_size(base, win, size) is expected


def test_check_within_file_raises_when_out_of_bounds(tmp_path):
    li = _load(tmp_path, doubles={"static_fs": _FakeStaticFs(3)}).plugin
    with pytest.raises(ValueError, match="exceeds file size"):
        li._check_patch_within_file("/bin/foo", 0, 4)


def test_check_within_file_ok_when_fits(tmp_path):
    li = _load(tmp_path, doubles={"static_fs": _FakeStaticFs(64)}).plugin
    li._check_patch_within_file("/bin/foo", 0x10, 4)  # no raise


def test_check_within_file_skips_when_size_unknown(tmp_path):
    li = _load(tmp_path, doubles={"static_fs": _FakeStaticFs(None)}).plugin
    li._check_patch_within_file("/bin/foo", 0, 999999)  # None -> skipped, no raise


def test_check_within_file_skips_when_get_size_raises(tmp_path):
    # the defensive path: if the size can't be determined (static_fs errors),
    # skip the check rather than fail the build
    li = _load(tmp_path,
               doubles={"static_fs": _FakeStaticFs(RuntimeError("no fs"))}).plugin
    li._check_patch_within_file("/bin/foo", 0, 999999)  # no raise


# --- batch-hypercall handler: apply staged window + write provenance ------
def _prep_handler(li, tmp_path, queue, base_offsets=None):
    """Stage each queued patch's ``_content`` as ``patch_<i>`` under a staged
    dir the handler reads, and point the plugin at it. ``outdir`` (where the
    report lands) is already wired to ``tmp_path`` by the harness."""
    li.staged_dir = str(tmp_path)
    li.patch_queue = [(path, action) for path, action, _ in _queue_files(queue)]
    li._patch_base_offset = base_offsets or {}
    for i, (_path, _action, content) in enumerate(_queue_files(queue)):
        (tmp_path / f"patch_{i}").write_bytes(content)


def _queue_files(queue):
    # yield (path, action-without-_content, staged-content) from the seeded queue
    for path, action in queue:
        action = dict(action)
        yield path, action, action.pop("_content")


def test_handler_windowed_roundtrip(li, tmp_path):
    # staged file is the 2-byte window at offset 0x100; handler applies with the
    # recorded base offset and writes the patched window back.
    queue = [("/bin/foo", {"file_offset": 0x100, "hex_bytes": "aabb",
                           "expect": "0102", "tag": "t", "why": "w",
                           "_content": b"\x01\x02"})]
    _prep_handler(li, tmp_path, queue, base_offsets={0: 0x100})
    rc = li._on_batch_patch_hypercall()
    assert rc == 0
    assert (tmp_path / "patch_0").read_bytes() == b"\xaa\xbb"
    report = yaml.safe_load((tmp_path / "binary_patches.yaml").read_text())
    assert report[0]["result"] == "applied" and report[0]["file_offset"] == "0x100"


def test_handler_success_writes_file_and_report(li, tmp_path):
    queue = [("/bin/foo", {"file_offset": 0, "hex_bytes": "aabb",
                           "tag": "grp", "why": "flip", "_content": b"\x01\x02\x03"})]
    _prep_handler(li, tmp_path, queue)
    rc = li._on_batch_patch_hypercall()
    assert rc == 0
    assert (tmp_path / "patch_0").read_bytes() == b"\xaa\xbb\x03"
    report = yaml.safe_load((tmp_path / "binary_patches.yaml").read_text())
    assert report[0]["result"] == "applied"
    assert report[0]["tag"] == "grp" and report[0]["file"] == "/bin/foo"


def test_handler_fail_policy_aborts_and_names_patch(li, tmp_path):
    # default on_mismatch: fail with a mismatched expect -> handler returns -1
    queue = [("/bin/foo", {"file_offset": 0, "hex_bytes": "aabb", "expect": "ffff",
                           "tag": "secureboot", "why": "nop the check",
                           "_content": b"\x01\x02\x03"})]
    _prep_handler(li, tmp_path, queue)
    rc = li._on_batch_patch_hypercall()
    assert rc == -1  # this exit code halts the image build via run_or_report
    # the staged file must NOT have been patched (no half-applied write-back)
    assert (tmp_path / "patch_0").read_bytes() == b"\x01\x02\x03"
    report = yaml.safe_load((tmp_path / "binary_patches.yaml").read_text())
    assert report[0]["result"] == "failed"
    assert report[0]["tag"] == "secureboot" and report[0]["why"] == "nop the check"
