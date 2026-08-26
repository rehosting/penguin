#!/usr/bin/env python3
"""Rewrite every Nix store reference under a tree to an equal-length prefix.

Used by the `portable` image variant in mk-image.nix, which has to run where
something else owns /nix (see the comment there).

The whole technique rests on the replacement prefix being the *same byte
length* as the real store directory. Nix store paths are absolute and appear
not just in symlinks and shebangs but baked into binaries: ELF PT_INTERP and
DT_RUNPATH strings, compiled-in C string constants, .pyc co_filename entries,
pkg-config files, wrapper scripts. Replacing them in place, byte for byte,
keeps every one of those structurally valid without this script needing to
understand a single one of those formats -- no patchelf, no per-format
handling, no length bookkeeping. Any other length would corrupt the ELF
sections and offsets that reference them.

Only *this image's* store moved. penguin ships a second one -- the tool closure
baked into the guest at /igloo/nix/store -- and rewriting a literal that names
it yields a path that exists nowhere: it broke `mke2fs -d` on the base-image
tarball and pointed every /igloo/utils/<tool> wrapper at nothing. GUEST_SUBTREES
and GUEST_PREFIX below keep those out of the blast radius; both passes honour
them identically, or the leftover check fails the build on what the rewrite
deliberately kept.

Directories must be writable before this runs (symlink retargeting replaces
the link, which needs write permission on its parent). File modes are
preserved: each file is made writable only for its own rewrite and restored
immediately after.
"""

import os
import re
import stat
import sys
from typing import Iterator

# Guest filesystem payload; every store path in it is a guest path. Matched as
# a path fragment -- the walk starts above the igloo-static store path.
GUEST_SUBTREES = ("igloo_static/closures",)

# Glued straight on, this marks the guest's store: "igloo/nix/store" is the
# guest's copy, "/igloo:/nix/store" a host search path.
GUEST_PREFIX = "igloo"


def in_guest_subtree(path: str) -> bool:
    """True if `path` is, or lives under, a guest-payload subtree."""
    p = path.replace(os.sep, "/")
    return any(p.endswith("/" + frag) or "/" + frag + "/" in p for frag in GUEST_SUBTREES)


def walk(root: str, pruned: "list[str] | None" = None) -> Iterator[str]:
    """Yield every path under `root`, pruning guest-payload subtrees.

    Both passes walk through here so they cannot disagree about what is in
    scope. Pruned dirs are neither descended into nor yielded (their own names
    hold no store reference); each is appended to `pruned` if given.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in dirnames:
            path = os.path.join(dirpath, d)
            if in_guest_subtree(path):
                if pruned is not None:
                    pruned.append(path)
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in filenames + dirnames:
            yield os.path.join(dirpath, name)


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <root> <old-prefix> <new-prefix>", file=sys.stderr)
        return 2

    root, old_s, new_s = sys.argv[1], sys.argv[2], sys.argv[3]
    old, new = old_s.encode(), new_s.encode()

    if len(old) != len(new):
        print(
            f"prefix length mismatch: {old_s!r} is {len(old)} bytes, "
            f"{new_s!r} is {len(new)}. They must be equal -- see this script's "
            f"docstring for why.",
            file=sys.stderr,
        )
        return 1

    # Every occurrence EXCEPT one glued onto "igloo".
    guest_lit = GUEST_PREFIX.encode() + old
    ours = re.compile(b"(?<!" + re.escape(GUEST_PREFIX.encode()) + b")" + re.escape(old))
    ours_s = re.compile("(?<!" + re.escape(GUEST_PREFIX) + ")" + re.escape(old_s))

    def rewrite(data: bytes) -> "tuple[bytes, int, int]":
        """Return (rewritten data, references moved, guest references kept).

        Almost nothing in the tree mentions the guest, so one substring scan
        keeps the big binaries on the plain-replace path.
        """
        if guest_lit not in data:
            return data.replace(old, new), data.count(old), 0
        count = len(ours.findall(data))
        # A lambda, not `new`: re.sub reads backslashes in a replacement string.
        return ours.sub(lambda _m: new, data), count, data.count(old) - count

    def names_ours(data: bytes) -> bool:
        """True if `data` still holds a reference that should have moved."""
        if old not in data:
            return False
        return guest_lit not in data or ours.search(data) is not None

    # What a guest-side literal looks like once the rewrite has ruined it. Both
    # defects this script once shipped had exactly this shape, and the check
    # rides along on a pass that already reads every file.
    corrupt = GUEST_PREFIX.encode() + new

    files = links = refs = kept = 0
    pruned: "list[str]" = []

    for path in walk(root, pruned):
        if os.path.islink(path):
            target = os.readlink(path)
            n = len(ours_s.findall(target))
            kept += target.count(old_s) - n
            if n:
                os.unlink(path)
                os.symlink(ours_s.sub(lambda _m: new_s, target), path)
                links += 1
            continue

        # Regular files only: skip fifos, sockets, devices.
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue

        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
            continue

        if old not in data:
            continue

        rewritten, count, preserved = rewrite(data)
        kept += preserved
        if not count:
            continue

        mode = stat.S_IMODE(st.st_mode)
        os.chmod(path, mode | stat.S_IWUSR)
        try:
            with open(path, "r+b") as fh:
                fh.write(rewritten)
        finally:
            os.chmod(path, mode)

        files += 1
        refs += count

    print(
        f"relocate-store: {old_s} -> {new_s}: "
        f"rewrote {refs} references in {files} files, retargeted {links} symlinks, "
        f"preserved {kept} guest-side references and skipped "
        f"{len(pruned)} guest subtree(s)",
        file=sys.stderr,
    )

    # Verify: nothing may still name the old store, guest references excepted.
    # A leftover is a runtime failure in an environment where the old store does
    # not exist, and those are miserable to debug from a container that
    # half-works, so fail the build instead.
    stragglers = []
    corrupted = []
    for path in walk(root):
        if os.path.islink(path):
            target = os.readlink(path)
            if ours_s.search(target):
                stragglers.append(path)
            if GUEST_PREFIX + new_s in target:
                corrupted.append(path)
            continue
        try:
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            if names_ours(data):
                stragglers.append(path)
            if corrupt in data:
                corrupted.append(path)
        except OSError:
            continue

    if corrupted:
        print(
            f"relocate-store: {len(corrupted)} path(s) name "
            f"{GUEST_PREFIX}{new_s} -- a guest store reference was rewritten. "
            f"The guest did not move; see this script's docstring.",
            file=sys.stderr,
        )
        for path in corrupted[:20]:
            print(f"  {path}", file=sys.stderr)
        return 1

    # The pruned subtrees are skipped wholesale, so nothing above would notice
    # if one arrived already-relocated. Assert positively that the guest's exec
    # targets still name the guest's store -- the defect that made every
    # /igloo/utils/<tool> wrapper exec a path that exists nowhere.
    for subtree in pruned:
        for dirpath, _, filenames in os.walk(subtree):
            for name in filenames:
                if not name.endswith(".json"):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    with open(path, "rb") as fh:
                        data = fh.read()
                except OSError:
                    continue
                if new in data or old not in data:
                    print(
                        f"relocate-store: {path} does not name {old_s}; a guest "
                        f"manifest must keep the guest's own store paths.",
                        file=sys.stderr,
                    )
                    return 1

    if stragglers:
        print(
            f"relocate-store: {len(stragglers)} path(s) still reference {old_s}:",
            file=sys.stderr,
        )
        for path in stragglers[:20]:
            print(f"  {path}", file=sys.stderr)
        if len(stragglers) > 20:
            print(f"  ... and {len(stragglers) - 20} more", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
