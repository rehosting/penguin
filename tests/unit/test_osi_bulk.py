"""Real-ISF coverage for OSI.get_all_procs (the bulk process-tree walk behind
HYPER_OP_OSI_PROC_ALL), driven host-side with no PANDA/guest.

This is the host<->driver ABI contract test: we pack a portal response the way
the driver's handle_op_osi_proc_all does (osi_result_header + a fixed-size
osi_proc_node array with inline comm) and assert the plugin decodes it back to
the right fields via the *real* driver ISF (dwarffi). It complements the pure
join-logic tests in test_processes.py, which stub OSI entirely.

Requires a driver ISF that actually carries the OSI_PROC_ALL op + osi_proc_node
struct. This is a hard requirement, not an optional one: if the pinned driver
lacks the op, penguin's get_all_procs is incompatible with the driver it ships
against, so the test FAILS (it does not skip -- see
_assert_pinned_driver_has_bulk_op). Bumping IGLOO_DRIVER_VERSION to a release
carrying the op turns it green with no edit here. Only a totally unresolvable
ISF (offline, nothing cached) skips, via the igloo_ko_isf fixture.
"""
import struct
from pathlib import Path

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


def _assert_pinned_driver_has_bulk_op(isf):
    """The pinned igloo_driver ISF MUST carry HYPER_OP_OSI_PROC_ALL.

    If it does not, penguin's OSI.get_all_procs is *incompatible with the driver
    it ships against* -- ``hop.HYPER_OP_OSI_PROC_ALL`` would ``AttributeError``
    at runtime. That is a real defect, not a "feature not built yet", so we FAIL
    loudly rather than ``skip`` (a skip reads as green and let the incompatible
    code merge). The failure is the forcing function: bump IGLOO_DRIVER_VERSION
    to a release carrying the op (this is exactly what PR #897 does), and the
    test goes green on its own with no edit here.

    Note the *fixture* still skips cleanly when no ISF resolves at all (offline,
    nothing cached) -- that is genuinely untestable, distinct from "ISF resolved
    but the pinned driver predates the op", which is the incompatibility we fail
    on.
    """
    import hyper.consts as consts
    assert hasattr(consts.HYPER_OP, "HYPER_OP_OSI_PROC_ALL"), (
        "pinned igloo_driver ISF lacks HYPER_OP_OSI_PROC_ALL: penguin's "
        "OSI.get_all_procs cannot run against the pinned driver. Bump "
        "IGLOO_DRIVER_VERSION (Dockerfile) to a release carrying the op -- "
        "see PR #897.")
    return consts


def test_get_all_procs_decodes_real_node_layout(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    consts = _assert_pinned_driver_has_bulk_op(igloo_ko_isf)

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
    consts = _assert_pinned_driver_has_bulk_op(igloo_ko_isf)

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
