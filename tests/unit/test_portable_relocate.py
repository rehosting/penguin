"""
Unit tests for the portable-image store relocation (``nix/relocate-store.py``).

The rewrite moves this image's closure out of ``/nix/store``, but penguin ships a
second store -- the tool closure baked into the guest at ``/igloo/nix/store`` --
that did not move. Every published ``-portable`` image rewrote two guest-side
literals anyway: the parent-directory entry in
``gen_image.tar_add_tool_closure`` (``mke2fs -d`` then refused the base tarball,
so no guest booted) and ``closures/<arch>/manifest.json`` (every
``/igloo/utils/<tool>`` wrapper exec'd a nonexistent path).

Below: the two rules that now exclude them, and the host-side rewrite they must
not weaken. The script runs as a subprocess, the way the build runs it.
"""

import json
import os
import subprocess
import sys

import pytest

RELOCATE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "nix", "relocate-store.py"))

# Absent, every test below would fail as python's "can't open file" exit 2
# rather than as a relocation result. The script has to be staged deliberately
# (flake.nix's testTree fileset), so say which one broke.
assert os.path.isfile(RELOCATE), (
    f"{RELOCATE} not found -- add nix/relocate-store.py to the testTree "
    f"fileset in flake.nix")

OLD = "/nix/store"
NEW = "/opt/store"


def relocate(root, old=OLD, new=NEW):
    """Run the relocation over ``root``; return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, RELOCATE, str(root), old, new],
        capture_output=True, text=True)


@pytest.fixture
def root(tmp_path):
    """An image root with both a host store reference and guest-side payload."""
    r = tmp_path / "root"

    # Host side: a source file naming the store, and the symlink farm that
    # points into it. Both must move.
    (r / "src").mkdir(parents=True)
    (r / "src" / "host.py").write_text(
        'GLOB = "/nix/store/*/igloo_static/kernels/*/igloo.ko"\n')
    (r / "bin").mkdir()
    (r / "bin" / "bash").symlink_to("/nix/store/aaaa-bash/bin/bash")

    # Guest side: the tool closure's manifest, under the relocated store the
    # way the build lays it out.
    closures = r / "opt" / "store" / "hhhh-igloo-static" / "igloo_static" / "closures" / "armel"
    closures.mkdir(parents=True)
    (closures / "manifest.json").write_text(json.dumps(
        {"gdb": "/nix/store/01crmi2lfm14bnl3rydihby3kbprnv2c-gdb-16.3/bin/gdb"}))

    # Guest side: a literal naming the guest's baked store.
    (r / "src" / "guest.py").write_text(
        'DIRS = ("igloo/nix/", "igloo/nix/store/", "nix/")\n')

    return r


def test_host_references_move(root):
    """The whole point: this image's own store references are rewritten."""
    assert relocate(root).returncode == 0

    assert "/opt/store/*/igloo_static" in (root / "src" / "host.py").read_text()
    assert os.readlink(root / "bin" / "bash") == "/opt/store/aaaa-bash/bin/bash"


def test_guest_closure_manifest_is_not_rewritten(root):
    """The wrapper exec targets name the guest's store, which did not move."""
    assert relocate(root).returncode == 0

    manifest = json.loads(
        (root / "opt" / "store" / "hhhh-igloo-static" / "igloo_static"
         / "closures" / "armel" / "manifest.json").read_text())
    assert manifest["gdb"].startswith("/nix/store/")


def test_igloo_prefixed_literals_are_not_rewritten(root):
    """``igloo/nix/store`` is the guest's copy; rewriting it broke mke2fs."""
    assert relocate(root).returncode == 0

    assert (root / "src" / "guest.py").read_text() == (
        'DIRS = ("igloo/nix/", "igloo/nix/store/", "nix/")\n')


def test_preserved_guest_references_do_not_fail_the_build(root):
    """The leftover check must agree with the rewrite about what is in scope --
    otherwise every reference deliberately kept is reported as a straggler."""
    proc = relocate(root)

    assert proc.returncode == 0, proc.stderr
    assert "still reference" not in proc.stderr
    assert "preserved 1 guest-side references and skipped 1 guest subtree(s)" in proc.stderr


def test_igloo_must_be_glued_on_to_count_as_guest_side(root):
    """``/igloo:/nix/store/...`` is a host search path listing ``/igloo`` first;
    only ``igloo/nix/store``, one path, names the guest's copy."""
    (root / "src" / "boundary.py").write_text(
        'PATH = "/igloo:/nix/store/aaaa-coreutils/bin"\n'
        'GUEST = "/igloo/nix/store/aaaa-gdb/bin/gdb"\n')

    assert relocate(root).returncode == 0

    assert (root / "src" / "boundary.py").read_text() == (
        'PATH = "/igloo:/opt/store/aaaa-coreutils/bin"\n'
        'GUEST = "/igloo/nix/store/aaaa-gdb/bin/gdb"\n')


def test_unequal_prefix_lengths_are_rejected(root):
    """In-place rewriting is only valid at equal byte length."""
    proc = relocate(root, new="/somewhere/else")

    assert proc.returncode == 1
    assert "prefix length mismatch" in proc.stderr


def test_a_corrupted_guest_literal_fails_the_build(root):
    """The signature both shipped defects had: a guest literal, relocated.

    The rules above stop this script from creating one, but a literal can also
    arrive pre-broken from an input; either way it must never reach an image.
    """
    (root / "src" / "already_broken.py").write_text(
        'DIRS = ("igloo/nix/", "igloo/opt/store/", "nix/")\n')

    proc = relocate(root)

    assert proc.returncode == 1
    assert "a guest store reference was rewritten" in proc.stderr
    assert "already_broken.py" in proc.stderr


def test_other_json_in_a_guest_subtree_is_not_a_manifest(root):
    """Only the tool manifest is asserted on, by name.

    Anything else that lands beside it -- an index, per-arch metadata -- carries
    no store path to check, so failing the build over it would be a false
    positive on a file the relocation never had an opinion about.
    """
    closures = (root / "opt" / "store" / "hhhh-igloo-static" / "igloo_static"
                / "closures" / "armel")
    (closures / "index.json").write_text(json.dumps({"arches": ["armel"]}))

    proc = relocate(root)

    assert proc.returncode == 0, proc.stderr


def test_a_store_pathless_guest_manifest_is_not_a_failure(root):
    """The manifest is checked for the host prefix, not for the guest one.

    An arch that ships no tools, or a future format that locates them some
    other way, names no store path at all. That is not a relocation defect,
    and a guard that exists to stop a bad release is the worst place to fail
    on a file it has no opinion about.
    """
    manifest = (root / "opt" / "store" / "hhhh-igloo-static" / "igloo_static"
                / "closures" / "armel" / "manifest.json")
    manifest.write_text(json.dumps({}))

    proc = relocate(root)

    assert proc.returncode == 0, proc.stderr


def test_a_relocated_guest_manifest_fails_the_build(root):
    """Guest subtrees are skipped wholesale, so assert on them positively.

    Nothing in the rewrite pass reads a pruned subtree, so a manifest that
    arrived already naming the host prefix would otherwise sail through.
    """
    manifest = (root / "opt" / "store" / "hhhh-igloo-static" / "igloo_static"
                / "closures" / "armel" / "manifest.json")
    manifest.write_text(json.dumps({"gdb": "/opt/store/01crmi2-gdb-16.3/bin/gdb"}))

    proc = relocate(root)

    assert proc.returncode == 1
    assert "must keep the guest's own store paths" in proc.stderr
