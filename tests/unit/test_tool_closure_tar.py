"""
Unit tests for ``gen_image.tar_add_tool_closure``.

The closure is appended re-rooted under ``igloo/``; the function pre-creates the
parent directory entries its members need and skips the closure's own bare
``nix/`` and ``nix/store/`` entries so they are not added twice. The two halves
have to agree, and in every published ``-portable`` image they did not: the
pre-created entry read ``igloo/opt/store/`` while members landed under
``igloo/nix/store/``, leaving thousands with no parent entry, which ``mke2fs -d``
refuses. (Cause: the portable store relocation -- see test_portable_relocate.py.)

The invariant below catches it cheaply: every member has a parent entry.
"""

import io
import tarfile

import pytest

from penguin import gen_image

ARCH = "armel"
STORE_PATH = "01crmi2lfm14bnl3rydihby3kbprnv2c-gdb-16.3"

CONFIG = {"core": {"arch": ARCH}}


def _closure_tar(path):
    """A miniature closure tarball, shaped like the real one: bare ``nix/`` and
    ``nix/store/`` dir entries, then one store path with a binary in it."""
    with tarfile.open(path, "w:gz") as tf:
        for name in ("nix/", "nix/store/", f"nix/store/{STORE_PATH}/",
                     f"nix/store/{STORE_PATH}/bin/"):
            di = tarfile.TarInfo(name=name)
            di.type = tarfile.DIRTYPE
            di.mode = 0o755
            tf.addfile(di)
        fi = tarfile.TarInfo(name=f"nix/store/{STORE_PATH}/bin/gdb")
        fi.mode = 0o755
        fi.size = 4
        tf.addfile(fi, io.BytesIO(b"ELF\n"))


@pytest.fixture
def base_tar(tmp_path, monkeypatch):
    """An (uncompressed) base tarball plus a staged closure to append into it."""
    closure_dir = tmp_path / "static" / "closures" / ARCH
    closure_dir.mkdir(parents=True)
    _closure_tar(closure_dir / "closure.tar.gz")
    monkeypatch.setattr(gen_image, "static_dir", str(tmp_path / "static"))
    monkeypatch.setattr(gen_image, "get_arch_subdir", lambda config: ARCH)

    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as tf:
        di = tarfile.TarInfo(name="igloo/")
        di.type = tarfile.DIRTYPE
        di.mode = 0o755
        tf.addfile(di)
    return path


def _members(path):
    """Member names, as tarfile reports them (trailing slashes normalised off)."""
    with tarfile.open(path) as tf:
        return tf.getnames()


def test_every_member_has_a_parent_directory_entry(base_tar):
    """The invariant ``mke2fs -d`` enforces, and defect-1 broke."""
    gen_image.tar_add_tool_closure(str(base_tar), CONFIG)

    names = _members(base_tar)
    dirs = {n.rstrip("/") for n in names}
    for name in names:
        parent = name.rstrip("/").rpartition("/")[0]
        while parent:
            assert parent in dirs, f"{name!r} has no directory entry for {parent!r}"
            parent = parent.rpartition("/")[0]


def test_closure_lands_under_the_guest_store(base_tar):
    """The wrappers bind ``/igloo/nix`` onto ``/nix``; the store has to be there."""
    gen_image.tar_add_tool_closure(str(base_tar), CONFIG)

    assert f"igloo/nix/store/{STORE_PATH}/bin/gdb" in _members(base_tar)


def test_parent_directory_entries_are_not_duplicated(base_tar):
    """The closure's own bare ``nix/``/``nix/store/`` entries give way to the
    pre-created ones -- exactly once each."""
    gen_image.tar_add_tool_closure(str(base_tar), CONFIG)

    names = _members(base_tar)
    assert len(names) == len(set(names))


def test_absent_closure_is_skipped(tmp_path, monkeypatch, base_tar):
    """Older images and arches without a closure must still build an image."""
    monkeypatch.setattr(gen_image, "static_dir", str(tmp_path / "nothing-here"))

    gen_image.tar_add_tool_closure(str(base_tar), CONFIG)

    assert _members(base_tar) == ["igloo"]
