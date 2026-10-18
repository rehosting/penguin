"""Host-side tests for the kernel layout QEMU's OSI walks read
(pyplugins/compat/osi_layout.py): built from an ISF, for the syscall
engine's fd-path and exe filters and for HostOSI."""
from pathlib import Path
from types import SimpleNamespace

import cffi
import pytest

from penguin.testing import load_module
from osi_fakes import SYMS, modern_isf, old_isf, pre_cred_isf

PY = Path(__file__).resolve().parents[2] / "pyplugins"


@pytest.fixture(scope="module")
def ffi():
    qc, _ = load_module(str(PY / "compat" / "qemu_compat.py"))
    f = cffi.FFI()
    f.cdef("typedef _Bool bool; typedef struct CPUState CPUState;" + qc.PENGUIN_OSI_CDEF)
    return f


@pytest.fixture
def layout():
    mod, _ = load_module(str(PY / "compat" / "osi_layout.py"))
    mod._layout_set.clear()
    return mod


def _fields(ffi, t):
    return {name for name, _ in ffi.typeof(t).fields}


@pytest.mark.parametrize("isf", [modern_isf, old_isf, pre_cred_isf])
def test_layout_fills_exactly_the_c_struct(layout, ffi, isf):
    """every field of struct penguin_osi_layout, and nothing else: one the C
    side has and Python leaves out would read as 0, an offset that is there"""
    lay = layout.osi_layout(isf(), x86=True)
    assert set(lay) == _fields(ffi, "struct penguin_osi_layout")
    ffi.new("struct penguin_osi_layout *", lay)        # every value fits its type


def test_layout_modern_kernel(layout):
    lay = layout.osi_layout(modern_isf(), x86=True)
    assert lay["mm_mt_root"] == 0x48 and lay["mm_mmap"] == -1
    assert (lay["task_thread_node"], lay["signal_thread_head"]) == (0x5c0, 0x10)
    assert lay["task_thread_group"] == -1
    assert (lay["mr64_pivot"], lay["mr64_slot"], lay["mr64_pivots"]) == (8, 128, 15)
    assert (lay["ma64_pivots"], lay["ma64_meta_end"]) == (9, 8 + 9 * 8 + 160)
    assert (lay["maple_leaf_64"], lay["maple_range_64"], lay["maple_arange_64"]) == (1, 2, 3)
    assert lay["fs_pwd_dentry"] == 0x28 + 8 and lay["file_dentry"] == 0x18
    assert lay["dentry_hash_pprev"] == 0x10 and lay["dentry_name_name"] == 0x28
    assert lay["uts_release"] == SYMS["init_uts_ns"] + 4 + 130
    assert lay["stack_guard_gap"] and lay["pt_x86"] is True
    assert lay["kimg_start"] == SYMS["_text"] and lay["fn_sockfs_dname"] == SYMS["sockfs_dname"]
    assert lay["fn_dmabuffs_dname"] == 0 and lay["pt_page_offset_base"] == 0   # absent


def test_layout_old_kernel(layout):
    """version differences are field presence: -1, never a guess"""
    lay = layout.osi_layout(old_isf(), x86=False)
    assert lay["mm_mt_root"] == -1 and lay["mm_mmap"] == 0 and lay["vma_next"] == 0x10
    assert lay["task_thread_node"] == -1 and lay["task_thread_group"] == 0x4a0
    assert lay["mr64_pivot"] == -1 and lay["mr64_pivots"] == 0
    assert (lay["maple_leaf_64"], lay["maple_arange_64"]) == (-1, -1)
    assert lay["stack_guard_gap"] == 0 and lay["pt_x86"] is False


def test_layout_before_struct_cred_and_fs_paths(layout):
    """2.6.21: the ids are read from the task itself, fs_struct's pointers
    directly; a kernel with struct cred keeps reading through it"""
    lay = layout.osi_layout(pre_cred_isf(), x86=False)
    assert lay["ids_in_task"] == 1 and lay["task_cred"] == -1
    assert (lay["cred_uid"], lay["cred_euid"], lay["cred_gid"], lay["cred_egid"]) == (
        0x180, 0x184, 0x190, 0x194)
    assert (lay["fs_root_dentry"], lay["fs_root_mnt"]) == (0x8, 0x14)
    assert (lay["fs_pwd_dentry"], lay["fs_pwd_mnt"]) == (0xc, 0x18)
    old = layout.osi_layout(old_isf(), x86=False)
    assert old["ids_in_task"] == 0 and old["cred_uid"] == 4


def test_nested_field_missing_is_missing(layout):
    """a nested field with any part absent is absent, not a partial sum"""
    isf = old_isf()
    del isf.fields[("qstr", "name")]
    lay = layout.osi_layout(isf, x86=True)
    assert lay["dentry_name_name"] == -1 and lay["dentry_name_len"] == 0x24


def test_set_layout_once(layout, ffi):
    calls = []

    def set_layout(p):
        calls.append((p.task_pid, p.mm_mt_root, p.pt_x86, p.uts_release))
        return True
    panda = SimpleNamespace(ffi=ffi, lib=SimpleNamespace(penguin_osi_set_layout=set_layout),
                            arch_name="x86_64", bits=64, endianness="little")
    assert layout.set_osi_layout(panda, modern_isf())
    assert layout.set_osi_layout(panda, modern_isf())
    assert calls == [(0x100, 0x48, True, SYMS["init_uts_ns"] + 134)]


@pytest.mark.parametrize("bits,endian", [(32, "little"), (64, "big")])
def test_set_layout_refuses_unreadable_kernels(layout, ffi, bits, endian):
    """the walks read 64-bit little-endian kernels: no layout, so the
    engine's fd-path and exe filters never match, rather than misread"""
    def set_layout(p):
        raise AssertionError("no layout for this kernel")
    panda = SimpleNamespace(ffi=ffi, lib=SimpleNamespace(penguin_osi_set_layout=set_layout),
                            arch_name="mips64", bits=bits, endianness=endian)
    assert not layout.set_osi_layout(panda, modern_isf())
