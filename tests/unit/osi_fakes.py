"""Fakes shared by the OSI unit tests (test_osi_layout.py, test_hostosi.py):
an ISF as dwarffi answers for it, for a 6.x kernel (the maple tree) and a 4.x
one (the VMA list)."""
from types import SimpleNamespace


class FakeISF:
    """offsetof/get_symbol/get_enum over tables; a missing field raises, as
    dwarffi does"""

    def __init__(self, fields, symbols, enums=None):
        self.fields, self.symbols, self.enums = fields, symbols, enums or {}

    def offsetof(self, t, *path):
        return self.fields[(t.replace("struct ", ""),) + path]

    def get_symbol(self, name):
        a = self.symbols.get(name)
        return SimpleNamespace(address=a) if a else None

    def get_enum(self, name):
        c = self.enums.get(name)
        return SimpleNamespace(constants=c) if c is not None else None


COMMON = {
    ("task_struct", "pid"): 0x100, ("task_struct", "tgid"): 0x104,
    ("task_struct", "comm"): 0x200, ("task_struct", "real_parent"): 0x110,
    ("task_struct", "cred"): 0x118, ("task_struct", "mm"): 0x120,
    ("task_struct", "fs"): 0x128, ("task_struct", "files"): 0x130,
    ("task_struct", "start_time"): 0x138, ("task_struct", "tasks"): 0x140,
    ("task_struct", "signal"): 0x150,
    ("cred", "uid"): 4, ("cred", "gid"): 8, ("cred", "euid"): 20, ("cred", "egid"): 24,
    ("mm_struct", "pgd"): 0x48, ("mm_struct", "map_count"): 0x50,
    ("fs_struct", "root"): 0x18, ("fs_struct", "pwd"): 0x28,
    ("path", "mnt"): 0, ("path", "dentry"): 8,
    ("files_struct", "fdt"): 0x20, ("fdtable", "max_fds"): 0, ("fdtable", "fd"): 8,
    ("file", "f_path"): 0x10,
    ("dentry", "d_parent"): 0x18, ("dentry", "d_name"): 0x20, ("qstr", "len"): 4,
    ("qstr", "name"): 8, ("dentry", "d_op"): 0x60, ("dentry", "d_inode"): 0x30,
    ("dentry", "d_hash"): 0x8, ("hlist_bl_node", "pprev"): 8,
    ("inode", "i_ino"): 0x40,
    ("mount", "mnt"): 0x20, ("mount", "mnt_parent"): 0x10,
    ("mount", "mnt_mountpoint"): 0x18, ("vfsmount", "mnt_root"): 0,
    ("dentry_operations", "d_dname"): 0x40,
    ("vm_area_struct", "vm_start"): 0, ("vm_area_struct", "vm_end"): 8,
    ("vm_area_struct", "vm_flags"): 0x20, ("vm_area_struct", "vm_pgoff"): 0x78,
    ("vm_area_struct", "vm_file"): 0x80, ("vm_area_struct", "vm_ops"): 0x70,
    ("vm_area_struct", "vm_private_data"): 0x88, ("vm_area_struct", "vm_mm"): 0x10,
    ("vm_operations_struct", "name"): 0x60, ("vm_special_mapping", "name"): 0,
    ("uts_namespace", "name"): 4, ("new_utsname", "release"): 65 * 2,
}
MM = {("mm_struct", f): 0x100 + 8 * i for i, f in enumerate((
    "start_code", "end_code", "start_data", "end_data", "start_brk", "brk",
    "start_stack", "arg_start", "arg_end", "env_start", "env_end", "mmap_base",
    "task_size", "exe_file"))}
SYMS = {"init_task": 0xffffffff82e26940, "_text": 0xffffffff81000000,
        "_end": 0xffffffff83a30000, "init_uts_ns": 0xffffffff82c00000,
        "sockfs_dname": 0xffffffff81900000, "pipefs_dname": 0xffffffff81900100}


def modern_isf():
    """6.x: the maple tree, signal->thread_head, the guard gap"""
    f = {**COMMON, **MM}
    f.update({("mm_struct", "mm_mt"): 0x40, ("maple_tree", "ma_root"): 8,
              ("task_struct", "thread_node"): 0x5c0,
              ("signal_struct", "thread_head"): 0x10,
              ("maple_node", "mr64"): 0, ("maple_node", "ma64"): 0,
              ("maple_range_64", "pivot"): 8, ("maple_range_64", "slot"): 8 + 15 * 8,
              ("maple_range_64", "meta"): 8 + 15 * 8 + 15 * 8,
              ("maple_arange_64", "pivot"): 8, ("maple_arange_64", "slot"): 8 + 9 * 8,
              ("maple_arange_64", "meta"): 8 + 9 * 8 + 10 * 8 + 10 * 8,
              ("maple_metadata", "end"): 0})
    syms = dict(SYMS, stack_guard_gap=0xffffffff82a00000)
    enums = {"maple_type": {"maple_dense": 0, "maple_leaf_64": 1,
                            "maple_range_64": 2, "maple_arange_64": 3}}
    return FakeISF(f, syms, enums)


def old_isf():
    """4.x: the VMA list, thread_group; no maple tree, no guard gap"""
    f = {**COMMON, **MM}
    f.update({("mm_struct", "mmap"): 0, ("vm_area_struct", "vm_next"): 0x10,
              ("task_struct", "thread_group"): 0x4a0})
    return FakeISF(f, dict(SYMS))


def pre_cred_isf():
    """2.6.21: the ids in task_struct (no struct cred, 2.6.29), fs_struct's
    root/rootmnt pointers (no struct path in it, 2.6.25)"""
    f = {k: v for k, v in old_isf().fields.items()
         if k[0] != "cred" and k not in {("task_struct", "cred"), ("fs_struct", "root"),
                                         ("fs_struct", "pwd")}}
    f.update({("task_struct", "uid"): 0x180, ("task_struct", "euid"): 0x184,
              ("task_struct", "gid"): 0x190, ("task_struct", "egid"): 0x194,
              ("fs_struct", "root"): 0x8, ("fs_struct", "pwd"): 0xc,
              ("fs_struct", "rootmnt"): 0x14, ("fs_struct", "pwdmnt"): 0x18})
    return FakeISF(f, dict(SYMS))
