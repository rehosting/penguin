"""
Unit tests for declarative ``lib_inject.stubs``: schema validation and the
schema -> C-shim/alias codegen in ``penguin.stubs``.

Everything here is pure host-side logic: no rootfs, kernel, or container. Glob
expansion is exercised with an injected fake symbol resolver; the production
rootfs resolver's not-found / ambiguous paths are tested with an in-memory tar.
"""

import tarfile
from pathlib import Path

import pytest

from penguin import stubs
from penguin.penguin_config import structure
from pydantic import ValidationError


# --------------------------------------------------------------------------- #
# schema validation
# --------------------------------------------------------------------------- #
def _validate(section):
    """Validate a `stubs` section the way it hangs off lib_inject."""
    return structure.LibInject.model_validate({"stubs": section})


def test_schema_return_only():
    _validate({"libX.so": {"foo": {"return": 0}}})


def test_schema_return_alias_populates_field():
    a = structure.StubAction.model_validate({"return": 42})
    assert a.return_ == 42
    assert a.type == "long"  # default


def test_schema_type_override_and_guard():
    _validate({"libc.so": {"memcpy": {"guard_null_args": [0, 1], "return": 0}}})
    _validate({"libX.so": {"bar": {"return": 5, "type": "int"}}})


def test_schema_requires_return_or_guard():
    with pytest.raises(ValidationError):
        _validate({"libX.so": {"foo": {"type": "int"}}})


def test_schema_guard_index_bounds():
    with pytest.raises(ValidationError):
        _validate({"libc.so": {"memcpy": {"guard_null_args": [8]}}})
    with pytest.raises(ValidationError):
        _validate({"libc.so": {"memcpy": {"guard_null_args": [-1]}}})


def test_schema_forbids_unknown_key():
    with pytest.raises(ValidationError):
        _validate({"libX.so": {"foo": {"return": 0, "bogus": 1}}})


# --------------------------------------------------------------------------- #
# codegen: plain return
# --------------------------------------------------------------------------- #
def test_generate_return_only():
    files, aliases = stubs.generate({"libX.so": {"foo": {"return": 0}}})
    assert aliases == {"foo": "__igloo_stub_foo"}
    src = files["stub_foo.c"]
    assert "long __igloo_stub_foo()" in src
    assert "return (long)0;" in src
    assert "dlsym" not in src  # no call-through machinery for a plain stub


def test_generate_type_override():
    files, _ = stubs.generate({"libX.so": {"bar": {"return": 5, "type": "int"}}})
    src = files["stub_bar.c"]
    assert "int __igloo_stub_bar()" in src
    assert "return (int)5;" in src


def test_generate_accepts_validated_model():
    a = structure.StubAction.model_validate({"return": 3, "type": "int"})
    files, _ = stubs.generate({"libX.so": {"foo": a}})
    assert "int __igloo_stub_foo()" in files["stub_foo.c"]
    assert "return (int)3;" in files["stub_foo.c"]


# --------------------------------------------------------------------------- #
# codegen: guard_null_args (call-through)
# --------------------------------------------------------------------------- #
def test_generate_guard_call_through():
    files, aliases = stubs.generate(
        {"libc.so": {"memcpy": {"guard_null_args": [0, 1], "return": 0}}}
    )
    assert aliases == {"memcpy": "__igloo_stub_memcpy"}
    src = files["stub_memcpy.c"]
    assert 'dlsym(RTLD_NEXT, "memcpy")' in src
    assert "a0 == 0 || a1 == 0" in src
    assert "return (long)0;" in src           # NULL path
    assert "__igloo_real_memcpy(a0, a1" in src  # call-through path


def test_generate_guard_defaults_return_zero():
    files, _ = stubs.generate({"libc.so": {"strcmp": {"guard_null_args": [0]}}})
    src = files["stub_strcmp.c"]
    assert "a0 == 0" in src
    assert "return (long)0;" in src


# --------------------------------------------------------------------------- #
# glob expansion
# --------------------------------------------------------------------------- #
def test_generate_glob_expands():
    def resolver(lib):
        return {"nvram_get", "nvram_set", "unrelated"}

    files, aliases = stubs.generate(
        {"libnvram.so": {"nvram_*": {"return": 0}}}, resolver=resolver
    )
    assert set(aliases) == {"nvram_get", "nvram_set"}
    assert set(files) == {"stub_nvram_get.c", "stub_nvram_set.c"}


def test_generate_glob_no_match_errors():
    def resolver(lib):
        return {"aaa"}

    with pytest.raises(stubs.StubError):
        stubs.generate({"lib.so": {"zzz_*": {"return": 0}}}, resolver=resolver)


def test_generate_glob_without_resolver_errors():
    with pytest.raises(stubs.StubError):
        stubs.generate({"l.so": {"z_*": {"return": 0}}})


# --------------------------------------------------------------------------- #
# conflicts / precedence
# --------------------------------------------------------------------------- #
def test_generate_duplicate_symbol_errors():
    with pytest.raises(stubs.StubError):
        stubs.generate(
            {"a.so": {"foo": {"return": 0}}, "b.so": {"foo": {"return": 1}}}
        )


def test_precedence_conflict_errors():
    with pytest.raises(stubs.StubError):
        stubs.check_precedence({"l.so": {"foo": {"return": 0}}}, {"foo": "x"})
    with pytest.raises(stubs.StubError):
        stubs.generate(
            {"l.so": {"foo": {"return": 0}}}, existing_aliases={"foo": "x"}
        )


def test_precedence_no_conflict_ok():
    stubs.check_precedence({"l.so": {"foo": {"return": 0}}}, {"other": "x"})


# --------------------------------------------------------------------------- #
# file writing
# --------------------------------------------------------------------------- #
def test_write_files_and_regenerates(tmp_path):
    gen = tmp_path / "gen"
    paths = stubs.write_files(gen, {"stub_foo.c": "a\n", "notes.txt": "x\n"})
    assert [Path(p).name for p in paths] == ["stub_foo.c"]  # only .c returned
    assert (gen / "stub_foo.c").read_text() == "a\n"
    # a second build with a different stub set wipes the stale file
    stubs.write_files(gen, {"stub_bar.c": "b\n"})
    assert not (gen / "stub_foo.c").exists()
    assert (gen / "stub_bar.c").read_text() == "b\n"


# --------------------------------------------------------------------------- #
# production rootfs resolver: not-found / ambiguous
# --------------------------------------------------------------------------- #
def _make_tar(tmp_path, arcnames):
    tarp = tmp_path / "fs.tar.gz"
    src = tmp_path / "blob"
    src.write_bytes(b"not-an-elf")
    with tarfile.open(tarp, "w:gz") as tf:
        for name in arcnames:
            tf.add(src, arcname=name)
    return str(tarp)


def test_resolver_missing_library_errors(tmp_path):
    tarp = _make_tar(tmp_path, ["./bin/sh"])
    resolve = stubs.make_fs_resolver(tarp)
    with pytest.raises(stubs.StubError):
        resolve("/lib/libc.so")
    with pytest.raises(stubs.StubError):
        resolve("libc.so")


def test_resolver_ambiguous_basename_errors(tmp_path):
    tarp = _make_tar(tmp_path, ["./lib/libX.so", "./usr/lib/libX.so"])
    resolve = stubs.make_fs_resolver(tarp)
    with pytest.raises(stubs.StubError):
        resolve("libX.so")


# --------------------------------------------------------------------------- #
# assembly-body form (sym@addr: {body: ...})
# --------------------------------------------------------------------------- #
def test_schema_body_only():
    _validate({"libX.so": {"hw_probe": {"body": "movs r0, #0\nbx lr", "mode": "thumb"}}})


def test_schema_body_and_return_mutually_exclusive():
    with pytest.raises(ValidationError):
        _validate({"libX.so": {"foo": {"body": "nop", "return": 0}}})


def test_schema_mode_expect_require_body():
    with pytest.raises(ValidationError):
        _validate({"libX.so": {"foo": {"return": 0, "mode": "thumb"}}})
    with pytest.raises(ValidationError):
        _validate({"libX.so": {"foo": {"return": 0, "expect": "00000000"}}})


def test_parse_symbol_key():
    assert stubs.parse_symbol_key("foo") == ("foo", 0)
    assert stubs.parse_symbol_key("foo@0x10") == ("foo", 16)
    assert stubs.parse_symbol_key("foo@16") == ("foo", 16)
    with pytest.raises(stubs.StubError):
        stubs.parse_symbol_key("foo@")
    with pytest.raises(stubs.StubError):
        stubs.parse_symbol_key("foo@nothex")


def test_generate_patches_basic():
    # fake resolver: symbol -> (guest_path, base_offset)
    def resolver(lib, sym):
        return ("/usr/lib/libX.so", 0x1000)

    patches = stubs.generate_patches(
        {"libX.so": {
            "hw_probe": {"body": "movs r0, #0", "mode": "thumb"},
            "check@0x8": {"body": "nop", "expect": "00000000"},
        }},
        resolver,
    )
    assert set(patches) == {"/usr/lib/libX.so"}
    entries = {e["file_offset"]: e for e in patches["/usr/lib/libX.so"]}
    assert entries[0x1000]["asm"] == "movs r0, #0"
    assert entries[0x1000]["mode"] == "thumb"
    assert entries[0x1008]["asm"] == "nop"           # base + 0x8
    assert entries[0x1008]["expect"] == "00000000"
    assert all(e["tag"] == "stubs" for e in patches["/usr/lib/libX.so"])


def test_generate_patches_rejects_glob():
    def resolver(lib, sym):
        return ("/x", 0)

    with pytest.raises(stubs.StubError):
        stubs.generate_patches({"libX.so": {"chk_*": {"body": "nop"}}}, resolver)


def test_generate_ignores_body_stubs():
    # a mixed config: generate() (shim path) sees only the return stub
    files, aliases = stubs.generate(
        {"libX.so": {"foo": {"return": 0}, "bar": {"body": "nop"}}}
    )
    assert aliases == {"foo": "__igloo_stub_foo"}
    assert set(files) == {"stub_foo.c"}


def test_expand_rejects_at_in_return_key():
    with pytest.raises(stubs.StubError):
        stubs.generate({"libX.so": {"foo@0x4": {"return": 0}}})


def test_vaddr_to_file_offset():
    class _Elf:
        def __init__(self, segs):
            self._segs = segs

        def iter_segments(self):
            return self._segs

    seg = {"p_type": "PT_LOAD", "p_vaddr": 0x1000, "p_filesz": 0x200, "p_offset": 0x400}
    elf = _Elf([seg])
    assert stubs._vaddr_to_file_offset(elf, 0x1050) == 0x450
    with pytest.raises(stubs.StubError):
        stubs._vaddr_to_file_offset(elf, 0x9999)


def test_merge_patches_into_static_files():
    sf = {}
    stubs.merge_patches_into_static_files(sf, {"/a": [{"file_offset": 0, "asm": "nop"}]})
    assert sf["/a"]["type"] == "binary_patch"
    assert len(sf["/a"]["patches"]) == 1
    # append to existing binary_patch
    stubs.merge_patches_into_static_files(sf, {"/a": [{"file_offset": 4, "asm": "nop"}]})
    assert len(sf["/a"]["patches"]) == 2
    # normalize a single-edit action, then append
    sf2 = {"/b": {"type": "binary_patch", "file_offset": 0, "hex_bytes": "90"}}
    stubs.merge_patches_into_static_files(sf2, {"/b": [{"file_offset": 8, "asm": "nop"}]})
    assert len(sf2["/b"]["patches"]) == 2
    # conflict on a non-binary_patch action
    with pytest.raises(stubs.StubError):
        stubs.merge_patches_into_static_files(
            {"/c": {"type": "inline_file", "contents": "x"}},
            {"/c": [{"file_offset": 0, "asm": "nop"}]},
        )
