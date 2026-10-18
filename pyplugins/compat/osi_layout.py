"""
The kernel layout for QEMU's OSI walks
=======================================

``struct penguin_osi_layout`` (QEMU's ``include/system/penguin-osi.h``): the
offsets and symbols ``system/penguin-osi.c`` walks the kernel's structures
with, from the kernel's ISF (``plugins.kffi``).  A field this kernel lacks is
-1, a symbol it lacks 0: version differences are field presence, never a
guess.

Two users: the syscall engine's fd-path and exe filters (``compat/
syscall_trap.py``), and HostOSI (``apis/hostosi.py``).  The layout is given to
QEMU once.  Kernels: 64-bit little-endian (x86_64, aarch64), 32-bit ARM,
and MIPS32 of either endianness.
"""


def _off(isf, t: str, *path: str) -> int:
    """the offset of a (nested) field, -1 if this kernel has none or a lifted
    ISF's provenance does not trust it; an l1-graded field at its graded
    offset (compat/isf_trust.py)"""
    from compat.isf_trust import offset

    def isf_off(*p):
        try:
            return int(isf.offsetof(f"struct {t}", *p))
        except Exception:
            return -1
    if not path:
        return isf_off()
    own = isf_off(path[0])
    first = offset(t, path[0], own)
    if first < 0 or len(path) == 1:
        return first
    full = isf_off(*path)
    return -1 if full < 0 or own < 0 else first + (full - own)


def _sum(*offs: int) -> int:
    return -1 if any(o < 0 for o in offs) else sum(offs)


def _sym(isf, name: str) -> int:
    """a symbol's address from the ISF, else from the kernel's export table
    (compat/isf_trust.py), else 0"""
    from compat.isf_trust import exported
    s = isf.get_symbol(name)
    return int(getattr(s, "address", 0) or 0) if s else exported(name)


def _mount(o) -> dict:
    """struct mount's fields; before 3.3 there is none, and vfsmount holds
    them (a mount is its vfsmount: mnt at 0)"""
    if o("mount", "mnt") >= 0:
        return dict(mount_mnt=o("mount", "mnt"), mount_parent=o("mount", "mnt_parent"),
                    mount_mountpoint=o("mount", "mnt_mountpoint"))
    return dict(mount_mnt=0 if o("vfsmount", "mnt_parent") >= 0 else -1,
                mount_parent=o("vfsmount", "mnt_parent"),
                mount_mountpoint=o("vfsmount", "mnt_mountpoint"))


def osi_layout(isf, x86: bool, ptr_size: int = 8, big_endian: bool = False,
               mips32: bool = False) -> dict:
    """penguin_osi_layout's values for this kernel, from its ISF"""
    def o(t, *path):
        return _off(isf, t, *path)

    def s(name):
        return _sym(isf, name)

    path_mnt, path_dentry = o("path", "mnt"), o("path", "dentry")
    mr64, ma64 = o("maple_node", "mr64"), o("maple_node", "ma64")
    mr_piv, mr_slot = o("maple_range_64", "pivot"), o("maple_range_64", "slot")
    ma_piv, ma_slot = o("maple_arange_64", "pivot"), o("maple_arange_64", "slot")
    meta_end = o("maple_metadata", "end")
    mt = o("mm_struct", "mm_mt")
    lay = dict(
        task_pid=o("task_struct", "pid"), task_tgid=o("task_struct", "tgid"),
        task_comm=o("task_struct", "comm"),
        task_real_parent=o("task_struct", "real_parent"),
        task_cred=o("task_struct", "cred"), task_mm=o("task_struct", "mm"),
        task_fs=o("task_struct", "fs"), task_files=o("task_struct", "files"),
        task_start_time=o("task_struct", "start_time"),
        task_tasks=o("task_struct", "tasks"), task_signal=o("task_struct", "signal"),
        task_thread_node=o("task_struct", "thread_node"),
        task_thread_group=o("task_struct", "thread_group"),
        signal_thread_head=o("signal_struct", "thread_head"),
        cred_uid=o("cred", "uid"), cred_gid=o("cred", "gid"),
        cred_euid=o("cred", "euid"), cred_egid=o("cred", "egid"),
        mm_mt_root=_sum(mt, o("maple_tree", "ma_root")) if mt >= 0 else -1,
        mm_mmap=o("mm_struct", "mmap"),
        mm_context_flags=o("mm_struct", "context", "flags"),
        fs_root_mnt=_sum(o("fs_struct", "root"), path_mnt),
        fs_root_dentry=_sum(o("fs_struct", "root"), path_dentry),
        fs_pwd_mnt=_sum(o("fs_struct", "pwd"), path_mnt),
        fs_pwd_dentry=_sum(o("fs_struct", "pwd"), path_dentry),
        files_fdt=o("files_struct", "fdt"), fdt_max_fds=o("fdtable", "max_fds"),
        fdt_fd=o("fdtable", "fd"),
        file_mnt=_sum(o("file", "f_path"), path_mnt),
        file_dentry=_sum(o("file", "f_path"), path_dentry),
        dentry_parent=o("dentry", "d_parent"),
        dentry_name_len=_sum(o("dentry", "d_name"), o("qstr", "len")),
        dentry_name_name=_sum(o("dentry", "d_name"), o("qstr", "name")),
        dentry_op=o("dentry", "d_op"), dentry_inode=o("dentry", "d_inode"),
        # d_hash: an hlist_bl_node since 2.6.38, an hlist_node before
        dentry_hash_pprev=_sum(o("dentry", "d_hash"),
                               max(o("hlist_bl_node", "pprev"), o("hlist_node", "pprev"))),
        inode_ino=o("inode", "i_ino"),
        dentry_sb=o("dentry", "d_sb"), sb_magic=o("super_block", "s_magic"),
        **_mount(o),
        vfsmount_root=o("vfsmount", "mnt_root"),
        dops_dname=o("dentry_operations", "d_dname"),
        vma_start=o("vm_area_struct", "vm_start"), vma_end=o("vm_area_struct", "vm_end"),
        vma_flags=o("vm_area_struct", "vm_flags"), vma_pgoff=o("vm_area_struct", "vm_pgoff"),
        vma_file=o("vm_area_struct", "vm_file"), vma_ops=o("vm_area_struct", "vm_ops"),
        vma_private=o("vm_area_struct", "vm_private_data"),
        vma_mm=o("vm_area_struct", "vm_mm"), vma_next=o("vm_area_struct", "vm_next"),
        vmops_name=o("vm_operations_struct", "name"),
        special_mapping_name=o("vm_special_mapping", "name"),
        mr64_pivot=_sum(mr64, mr_piv), mr64_slot=_sum(mr64, mr_slot),
        mr64_meta_end=_sum(mr64, o("maple_range_64", "meta"), meta_end),
        mr64_pivots=(mr_slot - mr_piv) // 8 if mr_slot > mr_piv >= 0 else 0,
        ma64_pivot=_sum(ma64, ma_piv), ma64_slot=_sum(ma64, ma_slot),
        ma64_meta_end=_sum(ma64, o("maple_arange_64", "meta"), meta_end),
        ma64_pivots=(ma_slot - ma_piv) // 8 if ma_slot > ma_piv >= 0 else 0,
        init_task=s("init_task"), gate_vma=s("gate_vma"),
        fn_sockfs_dname=s("sockfs_dname"), fn_pipefs_dname=s("pipefs_dname"),
        fn_anon_inodefs_dname=s("anon_inodefs_dname"), fn_simple_dname=s("simple_dname"),
        fn_dmabuffs_dname=s("dmabuffs_dname"),
        fn_special_mapping_name=s("special_mapping_name"),
        fn_gate_vma_name=s("gate_vma_name"),
        pt_page_offset_base=s("page_offset_base"), pt_l5_enabled=s("__pgtable_l5_enabled"),
        pt_vabits_actual=s("vabits_actual"), pt_memstart_addr=s("memstart_addr"),
        pt_x86=x86,
        kimg_start=s("_text"), kimg_end=s("_end"),
        pt_phys_base=s("phys_base"), pt_kimage_voffset=s("kimage_voffset"))
    # /proc's rules no structure shows: the release string, the guard gap
    uts = s("init_uts_ns")
    rel = _sum(o("uts_namespace", "name"), o("new_utsname", "release"))
    lay["uts_release"] = uts + rel if uts and rel >= 0 else 0
    lay["stack_guard_gap"] = s("stack_guard_gap")
    mt_enum = isf.get_enum("maple_type")
    consts = getattr(mt_enum, "constants", None) or {}
    for k in ("maple_leaf_64", "maple_range_64", "maple_arange_64"):
        lay[k] = consts.get(k, -1)
    for f in ("pgd", "map_count", "start_code", "end_code", "start_data", "end_data",
              "start_brk", "brk", "start_stack", "arg_start", "arg_end", "env_start",
              "env_end", "mmap_base", "task_size", "exe_file"):
        lay[f"mm_{f}"] = o("mm_struct", f)
    lay["ptr_size"] = ptr_size
    lay["big_endian"], lay["mips32"] = int(big_endian), int(mips32)
    # PENGUIN_OSI_DROP=key,...: entries to leave out, as a kernel lifted with
    # less would (-1 an offset, 0 a symbol), to check the C side's fallbacks
    import os
    for k in filter(None, os.environ.get("PENGUIN_OSI_DROP", "").split(",")):
        if k in lay:
            lay[k] = 0 if k.startswith(("fn_", "pt_", "kimg_")) or k in (
                "init_task", "gate_vma", "uts_release", "stack_guard_gap") else -1
    return lay


_layout_set = []


def set_osi_layout(panda, isf) -> bool:
    """give QEMU's OSI walks (and the syscall engine's OSI filters) this
    kernel's layout, once; False for a kernel they cannot read (32-bit, or
    big-endian)"""
    if _layout_set:
        return _layout_set[0]
    big = getattr(panda, "endianness", "little") == "big"
    arm32 = panda.arch_name in ("arm", "armel") and panda.bits == 32 and not big
    mips32 = panda.arch_name in ("mips", "mipseb", "mipsel") and panda.bits == 32
    if not (arm32 or mips32 or (panda.bits == 64 and not big)):
        _layout_set.append(False)
        return False
    lay = panda.ffi.new("struct penguin_osi_layout *",
                        osi_layout(isf, panda.arch_name == "x86_64",
                                   4 if arm32 or mips32 else 8, big, mips32))
    ok = bool(panda.lib.penguin_osi_set_layout(lay))
    _layout_set.append(ok)
    return ok
