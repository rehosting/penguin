"""Whether the HOST can read penguin's own modelled pseudofiles.

This exists because the rule turned out to be four source files deep, and I got
it wrong twice before reading them: once blaming hyperfs (the wrong filesystem
entirely) and once concluding a model should implement ONLY read_iter, which
returns -EIO on 4.10. So the rule is encoded here as executable truth-table
plus source citations, rather than as a comment someone else has to re-derive.

THE RULE, verified against both kernels in this tree
----------------------------------------------------
A modelled procfs file's guest-visible file_operations is chosen by PROCFS, not
by us -- what the model supplies only reaches procfs as a proc_ops/fops pair.

On 5.6+ (proc_ops era), fs/proc/inode.c:659-662 (6.13):

    if (de->proc_ops->proc_read_iter)
            inode->i_fop = &proc_iter_file_ops;   /* .read_iter, NO .read */
    else
            inode->i_fop = &proc_reg_file_ops;    /* .read, NO .read_iter */

and __kernel_read refuses any file with .read set or .read_iter missing
(fs/read_write.c). So on 6.13 the host can read the file IF AND ONLY IF the
model defines read_iter. Note what the selection does NOT look at: proc_read.
Defining both is therefore fine -- the file still lands on proc_iter_file_ops.

On 4.10, fs/proc/inode.c:455-465: a regular procfs file ALWAYS gets
proc_reg_file_ops, whatever the module supplied, and proc_reg_read
(inode.c:207-219) forwards only ``pde->proc_fops->read``:

        read = pde->proc_fops->read;
        if (read)
                rv = read(file, buf, count, ppos);
        return rv;                      /* rv is -EIO if there is no ->read */

4.10 has no guard in its read path (__vfs_read, fs/read_write.c:448-457), so the
host can read whatever the guest can -- which requires the model to define read.
read_iter alone is -EIO here.

Both kernels, therefore: a model must define BOTH.
"""
import importlib
import inspect
import sys
from pathlib import Path

import pytest

from penguin.testing import RealKffi

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPLUGINS = str(REPO_ROOT / "pyplugins")


def host_readable(defines_read: bool, defines_read_iter: bool, kernel):
    """Can the HOST read this modelled procfs file, per the rule above?

    Returns (ok, reason). `kernel` is a (major, minor) tuple.
    """
    if kernel >= (5, 6):
        if defines_read_iter:
            return True, ("proc_read_iter is set, so procfs picks "
                          "proc_iter_file_ops (.read_iter, no .read) and "
                          "__kernel_read accepts it")
        return False, ("no proc_read_iter, so procfs picks proc_reg_file_ops "
                       "(.read, no .read_iter) and __kernel_read refuses it "
                       "with EINVAL after zero bytes")
    if defines_read:
        return True, ("4.10 wraps every regular procfs file in "
                      "proc_reg_file_ops and has no guard in its read path")
    return False, ("4.10's proc_reg_read forwards only ->read, so a "
                   "read_iter-only model returns -EIO -- to the guest as well "
                   "as to us")


# --------------------------------------------------------------------------- #
# The rule itself. A truth table, so a change to it is a diff rather than a
# rediscovery.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("read,read_iter,on_410,on_613", [
    # read   read_iter   4.10   6.13
    (True,  False,       True,  False),   # every model in the tree today
    (False, True,        False, True),    # the "only read_iter" trap
    (True,  True,        True,  True),    # the answer
    (False, False,       False, False),
])
def test_the_host_readability_rule(read, read_iter, on_410, on_613):
    assert host_readable(read, read_iter, (4, 10))[0] is on_410
    assert host_readable(read, read_iter, (6, 13))[0] is on_613


def test_read_iter_alone_is_worse_than_it_looks(sample=None):
    """Not merely unreadable from the host on 4.10 -- broken for the GUEST too.

    This is the mistake worth a test rather than a comment: "implement read_iter
    instead of read" is the obvious reading of the 6.13 selection logic, and it
    silently breaks every 4.10 target, because 4.10's proc_reg_read never
    consults ->read_iter.
    """
    ok, why = host_readable(False, True, (4, 10))
    assert not ok
    assert "EIO" in why and "guest" in why


def test_defining_both_is_not_penalised_on_6_13():
    """The 5.6+ selection ignores proc_read, so keeping ->read costs nothing.

    Worth asserting because the natural assumption -- that __kernel_read's
    "refuses any file with .read set" applies to what the MODEL sets -- is
    wrong. It applies to the f_op procfs chose, and procfs chose it by looking
    only at proc_read_iter.
    """
    assert host_readable(True, True, (6, 13))[0]


# --------------------------------------------------------------------------- #
# The ISF facts the rule depends on. If either of these changes, the rule above
# is describing a driver that no longer exists.
# --------------------------------------------------------------------------- #

def test_igloo_proc_ops_carries_both_members(igloo_ko_isf):
    """The host can only supply what igloo_proc_ops has a member for.

    Both are present in the pinned driver, so the fix needs no driver change --
    which is the whole reason this is worth writing down.
    """
    kffi = RealKffi([igloo_ko_isf])
    members = set(kffi.get_type("igloo_proc_ops").members)
    assert "read" in members
    assert "read_iter" in members, (
        "igloo_proc_ops has no read_iter member, so a model cannot supply one "
        "and making modelled pseudofiles host-readable DOES need a driver "
        "change after all")


def test_igloo_proc_ops_has_no_write_iter(igloo_ko_isf):
    """Stated because its absence is the reason writes cannot be fixed the same way.

    There is no sequential write op and no write_iter member, so a modelled
    pseudofile cannot be made host-WRITABLE by this route. Left as a fact rather
    than discovered again later.
    """
    members = set(RealKffi([igloo_ko_isf]).get_type("igloo_proc_ops").members)
    assert "write_iter" not in members


# --------------------------------------------------------------------------- #
# The guardrail: which read mixins are host-readable today.
# --------------------------------------------------------------------------- #

# Every read mixin in the tree defines read and none defines read_iter, so none
# of penguin's modelled pseudofiles can be read from the host on a kernel from
# 5.6. This list is that state, written down: a NEW read mixin fails this test
# until it either defines read_iter or is added here deliberately.
KNOWN_READ_ONLY = {
    "ReadBufWrapper", "ReadConstBuf", "ReadEmpty", "ReadZero", "ReadOne",
    "ReadDefault", "ReadFromFile", "ReadConstMap", "ReadConstMapFile",
    "ReadCycle", "ReadZeroCycle", "ReadOneCycle", "ReadConstBufCycle",
    "ReadStateful", "ReadSequence", "ReadExternalVFS", "ReadExternalLegacy",
}


def _read_mixins():
    """Classes in hyperfile/models/read.py that implement a read path."""
    if PYPLUGINS not in sys.path:
        sys.path.insert(0, PYPLUGINS)
    mod = importlib.import_module("hyperfile.models.read")
    from hyperfile.models.base import ProcFile
    out = {}
    for name, cls in vars(mod).items():
        if not inspect.isclass(cls) or cls.__module__ != mod.__name__:
            continue
        has_read = any("read" in k.__dict__ for k in cls.__mro__)
        has_iter = any("read_iter" in k.__dict__ for k in cls.__mro__
                       if k is not ProcFile and k.__name__ != "VFSFile")
        if has_read:
            out[name] = has_iter
    return out


def test_every_read_mixin_is_accounted_for():
    """A new read mixin must decide whether the host can read it.

    Not a failing assertion about the current state -- that state is the
    KNOWN_READ_ONLY list -- but a tripwire, so the next mixin added does not
    silently inherit a host-unreadable read path.
    """
    mixins = _read_mixins()
    assert mixins, "found no read mixins; the sweep is not looking at anything"
    read_only = {n for n, has_iter in mixins.items() if not has_iter}
    new = read_only - KNOWN_READ_ONLY
    assert not new, (
        f"new read mixin(s) {sorted(new)} define read but not read_iter, so a "
        f"pseudofile using them cannot be read from the host on kernels from "
        f"5.6 (see this module's docstring). Add a read_iter, or add the name "
        f"to KNOWN_READ_ONLY to say that is intended.")
    fixed = KNOWN_READ_ONLY - read_only
    assert not fixed, (
        f"{sorted(fixed)} now define read_iter -- remove them from "
        f"KNOWN_READ_ONLY so the list keeps meaning something")


def test_no_modelled_pseudofile_is_host_readable_on_6_13_yet():
    """The systemic statement, asserted so that fixing it is visible.

    Every read mixin is read-only, so this is currently true of the whole tree.
    When the first mixin gains a read_iter this test fails, which is the point:
    the claim in KNOWN_GAPS and in fs.py's hint stops being true at that moment
    and both need updating.
    """
    mixins = _read_mixins()
    readable = [n for n, has_iter in mixins.items() if has_iter]
    assert not readable, (
        f"{readable} now define read_iter, so modelled pseudofiles are "
        f"host-readable on 5.6+. Update the /proc/large_file entry in "
        f"pyplugins/testing/vfs_read_verify.py KNOWN_GAPS and the hint in "
        f"pyplugins/apis/fs.py, which both still say they are not.")
