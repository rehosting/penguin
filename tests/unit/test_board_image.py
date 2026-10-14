"""Host-side tests for booting a board's own firmware (core.guest_image: none):
the schema and the run-path helpers in penguin_run. No QEMU, no guest."""
import json
import lzma

import pytest

from penguin.penguin_config.structure import Core
from penguin.penguin_run import (
    _board_flash_args,
    _check_board_image_config,
    _resolve_kernel_address,
)


def _conf(**core):
    base = {"machine": "bcm47094-router", "guest_image": "none",
            "flash": {"path": "flash/nand.img"}}
    base.update(core)
    return {"core": base, "plugins": {"vpn": {"enabled": False}}}


# ---- schema ----

def test_schema_accepts_board_image_fields():
    c = Core(version=2, arch="armel", kernel="kernels/2.6.36/Image", guest_image="none",
             machine="bcm47094-router",
             flash={"path": "flash/nand.img", "interface": "mtd"},
             kmod_inject={"hook": "vector_swi+0x20"})
    assert c.guest_image == "none"
    assert c.flash.format == "raw"
    assert c.kmod_inject.params == ""


def test_schema_default_is_penguin_image():
    assert Core(version=2, arch="armel").guest_image == "penguin"


# ---- config checks ----

def test_check_requires_machine_and_flash():
    with pytest.raises(ValueError, match="core.machine"):
        _check_board_image_config(_conf(machine=None))
    with pytest.raises(ValueError, match="core.flash"):
        _check_board_image_config(_conf(flash=None))


def test_check_rejects_vpn():
    conf = _conf()
    conf["plugins"] = {"vpn": {}}
    with pytest.raises(ValueError, match="vpn"):
        _check_board_image_config(conf)


def test_check_accepts_minimal():
    _check_board_image_config(_conf())


# ---- flash drive ----

def test_flash_args_relative_and_immutable(tmp_path):
    (tmp_path / "flash").mkdir()
    img = tmp_path / "flash" / "nand.img"
    img.write_bytes(b"\xff" * 16)
    args = _board_flash_args(_conf(), str(tmp_path))
    assert args == ["-drive", f"if=mtd,format=raw,file={img},snapshot=on"]


def test_flash_args_mutable(tmp_path):
    img = tmp_path / "nand.qcow2"
    img.write_bytes(b"")
    conf = _conf(flash={"path": str(img), "interface": "pflash",
                        "format": "qcow2"}, immutable=False)
    assert _board_flash_args(conf, "/nonexistent") == [
        "-drive", f"if=pflash,format=qcow2,file={img}"]


def test_flash_args_missing(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        _board_flash_args(_conf(), str(tmp_path))


# ---- hook address ----

def test_resolve_kernel_address(tmp_path):
    isf = tmp_path / "cosi.armel.json.xz"
    with lzma.open(isf, "wt") as f:
        json.dump({"symbols": {"vector_swi": {"address": 0x80050de0}}}, f)
    assert _resolve_kernel_address("0x80050e00", str(isf)) == 0x80050e00
    assert _resolve_kernel_address("vector_swi+0x20", str(isf)) == 0x80050e00
    assert _resolve_kernel_address("vector_swi", str(isf)) == 0x80050de0
    with pytest.raises(ValueError, match="not in"):
        _resolve_kernel_address("no_such_symbol+4", str(isf))
