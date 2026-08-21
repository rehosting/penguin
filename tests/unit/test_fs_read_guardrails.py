"""A refused guest read must be distinguishable from an empty file.

Regression cover for the failure mode that made the /proc gap invisible: the
portal returns ``None`` for a HYPER_RESP_READ_FAIL, ``fs.read_file`` passed that
straight back, and every caller reasonably read it as "no data". A whole
procfs cross-check silently reported "no processes" instead of "could not read
/proc" -- and the only trace was a debug-level line in the portal.

These drive fs.read_file's generator directly, feeding the responses the portal
would produce, so no PANDA/guest is involved.
"""
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
FS = str(REPO_ROOT / "pyplugins" / "apis" / "fs.py")


def _load(tmp_path, isf, regions_size=4096):
    class _Portal:
        pass
    portal = _Portal()
    portal.regions_size = regions_size
    # fs.py imports the real HYPER_OP enum, so the genuine consts must be built
    # against the pinned driver ISF (same pattern as test_osi_bulk).
    return load_pyplugin(FS, outdir=tmp_path, real_isf=isf,
                         doubles={"portal": portal})


def _drive(gen, responses):
    """Run a portal generator, feeding `responses` to successive yields."""
    it = iter(responses)
    try:
        gen.send(None)
        while True:
            gen.send(next(it, None))
    except StopIteration as e:
        return e.value


def test_single_read_failure_raises_not_empty(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    fs = lp.plugin
    with pytest.raises(OSError) as ei:
        _drive(fs.read_file("/proc/net/tcp", size=64), [None])
    # The message has to name the path AND say why a synthetic fs can do this,
    # otherwise the next person reads the failure as an empty file again.
    msg = str(ei.value)
    assert "/proc/net/tcp" in msg
    assert "synthetic" in msg and "empty file" in msg


def test_non_synthetic_path_still_raises_without_the_hint(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    with pytest.raises(OSError) as ei:
        _drive(lp.plugin.read_file("/etc/passwd", size=64), [None])
    msg = str(ei.value)
    assert "/etc/passwd" in msg and "synthetic" not in msg


def test_empty_file_is_not_an_error(tmp_path, igloo_ko_isf):
    """A genuinely empty read (b"") is data, not a failure."""
    lp = _load(tmp_path, igloo_ko_isf)
    assert _drive(lp.plugin.read_file("/tmp/empty", size=64), [b""]) == b""


def test_successful_read_returns_data(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert _drive(lp.plugin.read_file("/etc/hostname", size=8), [b"guest\n"]) == b"guest\n"


def test_chunked_read_failure_on_first_chunk_raises(tmp_path, igloo_ko_isf):
    # size > regions_size takes the chunked path; nothing came back at all.
    lp = _load(tmp_path, igloo_ko_isf, regions_size=16)
    with pytest.raises(OSError) as ei:
        _drive(lp.plugin.read_file("/proc/net/unix", size=64), [None])
    assert "/proc/net/unix" in str(ei.value)


def test_chunked_read_stops_cleanly_after_partial_data(tmp_path, igloo_ko_isf):
    """A failure AFTER data arrived is EOF, not an error -- the read worked."""
    lp = _load(tmp_path, igloo_ko_isf, regions_size=8)
    got = _drive(lp.plugin.read_file("/var/log/messages", size=64),
                 [b"abcdefg", None])
    assert got == b"abcdefg"
