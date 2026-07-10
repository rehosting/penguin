"""Real-ISF coverage for OSI.get_all_procs (the bulk process-tree walk behind
HYPER_OP_OSI_PROC_ALL), driven host-side with no PANDA/guest.

This is the host<->driver ABI contract test: we pack a portal response the way
the driver's handle_op_osi_proc_all does (osi_result_header + a fixed-size
osi_proc_node array with inline comm) and assert the plugin decodes it back to
the right fields via the *real* driver ISF (dwarffi). It complements the pure
join-logic tests in test_processes.py, which stub OSI entirely.

Requires a driver ISF that actually carries the OSI_PROC_ALL op + osi_proc_node
struct. The Dockerfile-pinned release predates this feature, so the test skips
unless pointed (via PENGUIN_TEST_IGLOO_KO_ISF) at a driver build that has it;
once the driver pin is bumped it runs in CI automatically.
"""
import struct
from pathlib import Path

import pytest

from penguin.testing import RealKffi, drive, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
OSI = str(REPO_ROOT / "pyplugins" / "apis" / "osi.py")


class _KFFI(RealKffi):
    """Real dwarffi-backed kffi exposing the sizeof/from_buffer that osi.py
    uses (RealKffi itself only supplies enums)."""

    def sizeof(self, type_name):
        return self.ffi.sizeof(type_name)

    def from_buffer(self, type_name, buf, instance_offset_in_buffer=0):
        return self.ffi.from_buffer(type_name, bytearray(buf),
                                    offset=instance_offset_in_buffer)


def _node(pid, ppid, create_time, comm, uid=0, gid=0, euid=0, egid=0):
    # struct osi_proc_node { u64 pid, ppid, create_time; u32 uid,gid,euid,egid;
    #                        char comm[16]; }  -- little-endian, packed 56 bytes.
    return struct.pack("<QQQIIII16s", pid, ppid, create_time,
                       uid, gid, euid, egid, comm.encode())


def _load(tmp_path, isf):
    return load_pyplugin(OSI, outdir=tmp_path, real_isf=isf,
                         doubles={"kffi": _KFFI([isf])})


def _require_bulk_op(isf):
    import hyper.consts as consts
    if not hasattr(consts.HYPER_OP, "HYPER_OP_OSI_PROC_ALL"):
        pytest.skip("driver ISF predates HYPER_OP_OSI_PROC_ALL; point "
                    "PENGUIN_TEST_IGLOO_KO_ISF at a driver build that has it")
    return consts


def test_get_all_procs_decodes_real_node_layout(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    consts = _require_bulk_op(igloo_ko_isf)

    # One page carrying the whole set (result_count == total_count == 2).
    buf = (struct.pack("<QQ", 2, 2)
           + _node(1, 0, 100, "init")
           + _node(400, 1, 200, "httpd", uid=33))

    procs, yielded = drive(lp.plugin.get_all_procs(), responses=[buf], collect=True)

    # Right op issued, and the slim nodes decode to the right fields + comm.
    assert yielded[0].op == consts.HYPER_OP.HYPER_OP_OSI_PROC_ALL
    got = [(int(p.pid), int(p.ppid), int(p.create_time), int(p.uid), p.name)
           for p in procs]
    assert got == [(1, 0, 100, 0, "init"), (400, 1, 200, 33, "httpd")]


def test_get_all_procs_paginates(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    consts = _require_bulk_op(igloo_ko_isf)

    # total_count 3, but the first page returns only 2 -> host must ask again
    # (skip=2) for the remainder.
    page1 = struct.pack("<QQ", 2, 3) + _node(1, 0, 10, "init") + _node(2, 1, 20, "sh")
    page2 = struct.pack("<QQ", 1, 3) + _node(3, 1, 30, "httpd")

    procs, yielded = drive(lp.plugin.get_all_procs(),
                           responses=[page1, page2], collect=True)

    assert [c.op for c in yielded] == [
        consts.HYPER_OP.HYPER_OP_OSI_PROC_ALL,
        consts.HYPER_OP.HYPER_OP_OSI_PROC_ALL,
    ]
    # second request advanced skip past the first page
    assert yielded[1].addr == 2
    assert [int(p.pid) for p in procs] == [1, 2, 3]
