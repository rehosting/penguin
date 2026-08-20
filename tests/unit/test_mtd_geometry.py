"""Host-side tests for the MTD subsystem's device geometry
(pyplugins/hyperfile/mtd.py `_validate_and_build`).

`plugins.mtd.devices` is a free-form mapping in the schema -- `penguin schema
mtd` says only "devices: Dict" -- so nothing validates it before the plugin
does. These tests pin the geometry a config actually gets, and that a bad
`personality.type` is a config error rather than a KeyError later on.

Needs a real `igloo.ko` ISF because mtd.py imports `hyper.consts`; the fixture
skips when there is none cached and no network.
"""
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

MTD = Path(__file__).resolve().parents[2] / "pyplugins" / "hyperfile" / "mtd.py"

KIB = 1024
MIB = 1024 * 1024


def _devices(tmp_path, isf, devices):
    lp = load_pyplugin(str(MTD), outdir=tmp_path, real_isf=isf,
                       args={"devices": devices, "proj_dir": str(tmp_path)})
    return {d["name"]: d for d in lp.plugin.internal_devices}


def test_default_personality_is_nand(tmp_path, igloo_ko_isf):
    """Omitting `personality` gets NAND geometry: 128 KiB erase blocks."""
    dev = _devices(tmp_path, igloo_ko_isf, {"f": {"model": "zeros"}})["f"]
    assert dev["geometry"] == {
        "type": "nand", "erase_size": 128 * KIB, "write_size": 2048, "oob_size": 64,
    }
    assert dev["total_size"] == 256 * MIB


def test_nor_personality_geometry(tmp_path, igloo_ko_isf):
    dev = _devices(tmp_path, igloo_ko_isf, {
        "f": {"model": "zeros", "personality": {"type": "nor"}},
    })["f"]
    assert dev["geometry"] == {
        "type": "nor", "erase_size": 64 * KIB, "write_size": 1, "oob_size": 0,
    }
    assert dev["total_size"] == 16 * MIB


def test_explicit_fields_override_the_type_defaults(tmp_path, igloo_ko_isf):
    dev = _devices(tmp_path, igloo_ko_isf, {
        "f": {"model": "zeros",
              "personality": {"type": "nor", "erase_size": "128k", "oob_size": 8}},
    })["f"]
    assert dev["geometry"]["erase_size"] == 128 * KIB
    assert dev["geometry"]["oob_size"] == 8
    assert dev["geometry"]["write_size"] == 1        # still the nor default


def test_explicit_size_wins(tmp_path, igloo_ko_isf):
    dev = _devices(tmp_path, igloo_ko_isf, {
        "f": {"model": "zeros", "size": "4m"},
    })["f"]
    assert dev["total_size"] == 4 * MIB


def test_defaults_do_not_leak_between_devices(tmp_path, igloo_ko_isf):
    """Each device gets its own geometry dict, not a shared one."""
    devs = _devices(tmp_path, igloo_ko_isf, {
        "a": {"model": "zeros", "personality": {"type": "nor", "erase_size": "8k"}},
        "b": {"model": "zeros", "personality": {"type": "nor"}},
    })
    assert devs["a"]["geometry"]["erase_size"] == 8 * KIB
    assert devs["b"]["geometry"]["erase_size"] == 64 * KIB


@pytest.mark.parametrize("bad", ["spi-nor", "NOR", "Nand", "flash", ""])
def test_unknown_personality_type_is_a_config_error(tmp_path, igloo_ko_isf, bad):
    """Unknown types used to give an empty geometry dict, which became a
    KeyError at device registration instead of naming the bad value."""
    with pytest.raises(ValueError) as e:
        _devices(tmp_path, igloo_ko_isf, {
            "f": {"model": "zeros", "personality": {"type": bad}},
        })
    assert "personality type" in str(e.value)
    assert "'f'" in str(e.value)          # names the offending device
    assert "nand" in str(e.value)         # and the accepted values


def test_unknown_model_still_errors(tmp_path, igloo_ko_isf):
    with pytest.raises(ValueError, match="Unknown model type"):
        _devices(tmp_path, igloo_ko_isf, {"f": {"model": "magic"}})
