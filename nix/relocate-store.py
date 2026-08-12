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

Directories must be writable before this runs (symlink retargeting replaces
the link, which needs write permission on its parent). File modes are
preserved: each file is made writable only for its own rewrite and restored
immediately after.
"""

import os
import stat
import sys


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

    files = links = refs = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames + dirnames:
            path = os.path.join(dirpath, name)

            if os.path.islink(path):
                target = os.readlink(path)
                if old_s in target:
                    os.unlink(path)
                    os.symlink(target.replace(old_s, new_s), path)
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

            count = data.count(old)
            if not count:
                continue

            mode = stat.S_IMODE(st.st_mode)
            os.chmod(path, mode | stat.S_IWUSR)
            try:
                with open(path, "r+b") as fh:
                    fh.write(data.replace(old, new))
            finally:
                os.chmod(path, mode)

            files += 1
            refs += count

    print(
        f"relocate-store: {old_s} -> {new_s}: "
        f"rewrote {refs} references in {files} files, retargeted {links} symlinks",
        file=sys.stderr,
    )

    # Verify: nothing may still name the old store. A leftover reference is a
    # runtime failure in an environment where the old store does not exist, and
    # those are miserable to debug from a container that half-works, so fail the
    # build instead.
    stragglers = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames + dirnames:
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                if old_s in os.readlink(path):
                    stragglers.append(path)
                continue
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    continue
                with open(path, "rb") as fh:
                    if old in fh.read():
                        stragglers.append(path)
            except OSError:
                continue

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
