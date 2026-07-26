"""
Unit tests for the built-image cache key (``penguin.utils.hash_image_inputs``).

The key names the qcow2 that a run boots, so it has to distinguish two different base
filesystems. It used to fold in only the filesystem's mtime, which meant two different
archives that happened to share a timestamp -- the normal outcome of one extraction,
copy or checkout pass -- hashed identically, and the image built from the first was
silently reused for the second.

The default path (``base/fs.tar.gz``) deliberately keeps its old key so existing
projects do not all rebuild; the tests below cover both that compatibility and the fact
that it cannot reintroduce the substitution.

Everything here runs without a rootfs, kernel, or container.
"""

import os

import pytest

from penguin import utils

#: Hard-coded rather than read from the module, so this suite still runs against a
#: build that predates the constant -- and so the compatibility path is pinned by the
#: test rather than by whatever the code happens to say.
DEFAULT_FS = "base/fs.tar.gz"


@pytest.fixture
def arch_dir(tmp_path, monkeypatch):
    """Stub out the arch assets so only the base filesystem varies."""
    arch = tmp_path / "arch"
    arch.mkdir()
    for name in ("busybox", "hyp_file_op", "send_portalcall", "igloo.ko"):
        (arch / name).write_bytes(name.encode())

    monkeypatch.setattr(utils, "get_arch_dir", lambda conf: str(arch))
    monkeypatch.setattr(utils, "get_driver_kmod_path", lambda conf: "igloo.ko")
    monkeypatch.setattr(utils, "get_arch_subdir", lambda conf: "testarch")
    return arch


def _archive(proj_dir, name, contents, mtime):
    path = proj_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    os.utime(path, (mtime, mtime))
    return {"core": {"fs": name, "arch": "armel", "kernel": "/kernels/zImage"}}


def test_the_compatibility_path_is_the_one_penguin_init_writes() -> None:
    """``penguin init`` writes base/fs.tar.gz and penguin_config points core.fs at it."""
    assert utils.LEGACY_KEY_FS_PATH == DEFAULT_FS


def test_two_archives_sharing_an_mtime_are_different_images(tmp_path, arch_dir):
    """The substitution this key must never allow.

    Two filesystems, one timestamp: before the path was part of the key these hashed
    the same, and the second run booted the first one's image.
    """
    one = _archive(tmp_path, "base/one.tar.gz", b"filesystem one", mtime=1_700_000_000)
    two = _archive(tmp_path, "base/two.tar.gz", b"filesystem two", mtime=1_700_000_000)

    assert utils.hash_image_inputs(str(tmp_path), one) != utils.hash_image_inputs(
        str(tmp_path), two
    )


def test_a_second_archive_never_collides_with_the_default_one(tmp_path, arch_dir):
    """The default path stays on the legacy key, so this pairing has to be checked.

    A project with the default filesystem plus one more -- both stamped by the same
    extraction pass -- is the realistic shape of the bug.
    """
    default = _archive(tmp_path, DEFAULT_FS, b"the default fs", mtime=1_700_000_000)
    other = _archive(tmp_path, "base/other.tar.gz", b"another fs", mtime=1_700_000_000)

    assert utils.hash_image_inputs(str(tmp_path), default) != utils.hash_image_inputs(
        str(tmp_path), other
    )


def test_the_default_path_keeps_its_legacy_key(tmp_path, arch_dir):
    """Existing projects must not be forced to rebuild.

    The observable signature of the unchanged key is that, for this one path, the digest
    still depends on nothing but the mtime -- so a same-mtime change of size does not
    move it. That is the pre-existing behaviour, kept deliberately: a project can hold
    only one archive here, so this path can never be the key shared by two filesystems.
    """
    conf = _archive(tmp_path, DEFAULT_FS, b"the default fs", mtime=1_700_000_000)
    before = utils.hash_image_inputs(str(tmp_path), conf)

    fs = tmp_path / DEFAULT_FS
    fs.write_bytes(b"the default fs, now a different length")
    os.utime(fs, (1_700_000_000, 1_700_000_000))

    assert utils.hash_image_inputs(str(tmp_path), conf) == before


def test_the_leading_dot_slash_form_is_the_same_path(tmp_path, arch_dir):
    """penguin_config writes ``./base/fs.tar.gz``; that must not read as non-default.

    Otherwise the compatibility above would apply to hand-written configs and not to
    generated ones, and the generated majority would rebuild.
    """
    plain = _archive(tmp_path, DEFAULT_FS, b"the default fs", mtime=1_700_000_000)
    dotted = dict(plain, core=dict(plain["core"], fs=f"./{DEFAULT_FS}"))

    assert utils.hash_image_inputs(str(tmp_path), plain) == utils.hash_image_inputs(
        str(tmp_path), dotted
    )


def test_a_non_default_archive_is_keyed_on_its_size(tmp_path, arch_dir):
    """Size is the cheap half: for a rekeyed path, a changed byte count cannot be missed
    even if the timestamp was restored."""
    conf = _archive(tmp_path, "base/fw.tar.gz", b"filesystem", mtime=1_700_000_000)
    before = utils.hash_image_inputs(str(tmp_path), conf)

    fs = tmp_path / "base/fw.tar.gz"
    fs.write_bytes(b"filesystem, now longer")
    os.utime(fs, (1_700_000_000, 1_700_000_000))  # timestamp deliberately restored

    assert utils.hash_image_inputs(str(tmp_path), conf) != before


def test_a_rewritten_archive_is_a_different_image(tmp_path, arch_dir):
    """The ordinary case, on either path: writing the file advances its mtime."""
    for name in (DEFAULT_FS, "base/fw.tar.gz"):
        conf = _archive(tmp_path, name, b"filesystem", mtime=1_700_000_000)
        before = utils.hash_image_inputs(str(tmp_path), conf)

        (tmp_path / name).write_bytes(b"filesystem, rebuilt")

        assert utils.hash_image_inputs(str(tmp_path), conf) != before, name


def test_the_same_archive_under_a_different_name_is_a_different_image(tmp_path, arch_dir):
    """The path is part of the key, so a built image stays traceable to its config."""
    one = _archive(tmp_path, "base/one.tar.gz", b"same bytes", mtime=1_700_000_000)
    two = _archive(tmp_path, "base/two.tar.gz", b"same bytes", mtime=1_700_000_000)

    assert utils.hash_image_inputs(str(tmp_path), one) != utils.hash_image_inputs(
        str(tmp_path), two
    )


def test_a_subdirectory_is_part_of_the_identity(tmp_path, arch_dir):
    """Same basename, different directory: still two filesystems."""
    one = _archive(tmp_path, "a/fs.tar.gz", b"same bytes", mtime=1_700_000_000)
    two = _archive(tmp_path, "b/fs.tar.gz", b"same bytes", mtime=1_700_000_000)

    assert utils.hash_image_inputs(str(tmp_path), one) != utils.hash_image_inputs(
        str(tmp_path), two
    )


def test_the_key_is_stable_across_calls(tmp_path, arch_dir):
    """An unchanged filesystem must keep its image: this is still a cache."""
    for name in (DEFAULT_FS, "base/fw.tar.gz"):
        conf = _archive(tmp_path, name, b"filesystem", mtime=1_700_000_000)

        assert utils.hash_image_inputs(str(tmp_path), conf) == utils.hash_image_inputs(
            str(tmp_path), conf
        ), name
