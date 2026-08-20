"""Host-side tests for `penguin init --output <path>` parent-directory handling.

`os.path.dirname("ap")` is `""` and `os.makedirs("")` raises FileNotFoundError
whatever `exist_ok` says, so a relative --output with no directory component --
`penguin init fw.rootfs.tar.gz --output ap`, a natural thing to type -- used to
crash before the project was created. Two authors hit it in one day.
"""
import os

import pytest

from penguin.__main__ import _ensure_parent_dir


def test_bare_name_has_no_parent_to_create(tmp_path, monkeypatch):
    """The regression: a bare relative name must not raise."""
    monkeypatch.chdir(tmp_path)
    _ensure_parent_dir("ap")
    # Nothing to create, and specifically not a directory named "".
    assert os.listdir(tmp_path) == []


def test_bare_name_is_what_os_makedirs_rejects():
    """Pin the underlying behaviour this helper exists to work around."""
    with pytest.raises(FileNotFoundError):
        os.makedirs(os.path.dirname("ap"), exist_ok=True)


def test_relative_path_parent_is_created(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _ensure_parent_dir("projects/ap")
    assert (tmp_path / "projects").is_dir()


def test_absolute_path_parent_is_created(tmp_path):
    _ensure_parent_dir(str(tmp_path / "nested" / "deeper" / "ap"))
    assert (tmp_path / "nested" / "deeper").is_dir()


def test_existing_parent_is_not_an_error(tmp_path):
    (tmp_path / "projects").mkdir()
    _ensure_parent_dir(str(tmp_path / "projects" / "ap"))
    assert (tmp_path / "projects").is_dir()


def test_trailing_slash_creates_the_named_directory(tmp_path):
    """`dirname("a/b/")` is "a/b", so a trailing slash creates the whole path."""
    _ensure_parent_dir(str(tmp_path / "a" / "b") + "/")
    assert (tmp_path / "a" / "b").is_dir()
