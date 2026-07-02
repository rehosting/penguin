"""Host-side unit tests for the binary_patch applier in the LiveImage plugin.

These exercise the byte-level patch logic directly, without booting a guest:
expect/on_mismatch policy, idempotent re-runs, length-mismatch and past-EOF
verification, multi-patch-per-file application with overlap detection, hex
parsing (0x prefix / spaces), and the fail-policy *abort contract* — that a
mismatched ``expect`` under the default ``fail`` policy makes the batch
hypercall return -1 (which, via send_portalcall's exit code and run_or_report,
halts the image build) and records the offending patch's tag/why.

Importing the pyplugin standalone requires stubbing the plugin framework and
keystone, which is done below before the module is loaded.
"""
import importlib.util
import os
import sys
import types

import pytest
import yaml

_HERE = os.path.dirname(__file__)
_LIVE_IMAGE = os.path.abspath(
    os.path.join(_HERE, "../../pyplugins/core/live_image.py"))


def _load_live_image():
    """Load pyplugins/core/live_image.py with the plugin framework stubbed.

    The module decorates methods with ``@plugins.portalcall.portalcall(...)``
    and imports keystone at top level; neither is available (or wanted) for a
    pure host-side unit test, so we stub them before executing the module.
    """
    class _Portalcall:
        def portalcall(self, magic):
            return lambda f: f  # identity: leave the method directly callable

    class _Plugins:
        portalcall = _Portalcall()

    class _Plugin:
        def __init_subclass__(cls, **kw):
            pass

    penguin_stub = types.ModuleType("penguin")
    penguin_stub.Plugin = _Plugin
    penguin_stub.plugins = _Plugins()
    penguin_stub.yaml = yaml

    pm = types.ModuleType("penguin.plugin_manager")
    pm.resolve_bound_method_from_class = lambda x: x
    defaults = types.ModuleType("penguin.defaults")
    defaults.static_dir = "/nonexistent"
    utils = types.ModuleType("penguin.utils")
    utils.get_arch_subdir = lambda c: "x86_64"
    boot_env = types.ModuleType("penguin.boot_env")
    boot_env.partition_boot_env = lambda *a, **k: ({}, {})
    boot_env.render_env_blob = lambda *a, **k: b""

    # live_image imports normalize_hex_string from the schema module; load the
    # real one (it only needs pydantic, not the full penguin package).
    pc_pkg = types.ModuleType("penguin.penguin_config")
    sspec = importlib.util.spec_from_file_location(
        "penguin.penguin_config.structure",
        os.path.abspath(os.path.join(_HERE, "../../src/penguin/penguin_config/structure.py")))
    structure = importlib.util.module_from_spec(sspec)

    saved = {k: sys.modules.get(k) for k in
             ("penguin", "penguin.plugin_manager", "penguin.defaults",
              "penguin.utils", "penguin.boot_env", "penguin.penguin_config",
              "penguin.penguin_config.structure", "keystone")}
    sys.modules["penguin"] = penguin_stub
    sys.modules["penguin.plugin_manager"] = pm
    sys.modules["penguin.defaults"] = defaults
    sys.modules["penguin.utils"] = utils
    sys.modules["penguin.boot_env"] = boot_env
    sys.modules["penguin.penguin_config"] = pc_pkg
    sys.modules["penguin.penguin_config.structure"] = structure
    sspec.loader.exec_module(structure)
    sys.modules.setdefault("keystone", types.ModuleType("keystone"))
    try:
        spec = importlib.util.spec_from_file_location("live_image_mod", _LIVE_IMAGE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


LI = _load_live_image().LiveImage


@pytest.fixture
def li():
    """A bare LiveImage instance with a stub logger, bypassing __init__."""
    inst = object.__new__(LI)
    inst.logger = types.SimpleNamespace(
        info=lambda *a, **k: None, warning=lambda *a, **k: None,
        error=lambda *a, **k: None, debug=lambda *a, **k: None)
    return inst


ORIG = b"\x01\x02\x03\x04rest"


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


# --- abort contract at the hypercall handler (#2) -------------------------
def _prep_handler(li, tmp_path, queue, base_offsets=None):
    li.staged_dir = str(tmp_path)
    li.patch_queue = queue
    li._patch_base_offset = base_offsets or {}
    li.get_arg = lambda k: str(tmp_path) if k == "outdir" else None
    for i, (path, action, content) in enumerate(queue_files(queue)):
        (tmp_path / f"patch_{i}").write_bytes(content)


def queue_files(queue):
    # helper: yield (path, action, staged-content) using the action's own seed
    for path, action in queue:
        yield path, action, action.pop("_content")


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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
