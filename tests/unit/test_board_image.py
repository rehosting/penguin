"""Host-side tests for booting a board's own firmware (core.guest_image: none):
the schema and the run-path helpers in penguin_run. No QEMU, no guest."""
import json
import lzma

import pytest

from penguin.penguin_config.structure import Core
from penguin.penguin_run import (
    _board_flash_args,
    _check_board_image_config,
    _kmod_inject_args,
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


def _kmod_project(tmp_path, arch, cosi, ko, **spec):
    kdir = tmp_path / "kernels" / "6.13"
    kdir.mkdir(parents=True)
    with lzma.open(kdir / cosi, "wt") as f:
        json.dump({"symbols": {"do_el0_svc": {"address": 0xffff8000800254e8}}}, f)
    (kdir / ko).write_bytes(b"\x7fELF")
    plugin = tmp_path / "libkmodinject.so"
    plugin.write_bytes(b"")
    conf = _conf(arch=arch, kernel=str(kdir / "Image"),
                 kmod_inject={"hook": "do_el0_svc", "plugin": str(plugin), **spec})
    return conf, kdir, plugin


def test_kmod_inject_args_aarch64(tmp_path):
    # cosi and the module are named arm64, not by the config arch
    conf, kdir, plugin = _kmod_project(tmp_path, "aarch64", "cosi.arm64.json.xz",
                                       "igloo.ko.arm64")
    args = _kmod_inject_args(conf, tmp_path / "lib" / "libqemu.so", str(tmp_path))
    assert args == ["-plugin", f"{plugin},ko={kdir}/igloo.ko.arm64,hook=0xffff8000800254e8"]


def test_kmod_inject_args_frame(tmp_path):
    conf, _, _ = _kmod_project(tmp_path, "aarch64", "cosi.arm64.json.xz",
                               "igloo.ko.arm64", frame="sp")
    args = _kmod_inject_args(conf, tmp_path / "lib" / "libqemu.so", str(tmp_path))
    assert args[1].endswith(",hook=0xffff8000800254e8,frame=sp")


def test_schema_kmod_inject_frame():
    c = Core(version=2, arch="aarch64", kernel="kernels/4.10/zImage.arm64",
             guest_image="none", machine="virt",
             flash={"path": "flash/rootfs.ext4", "interface": "virtio"},
             kmod_inject={"hook": "el0_svc", "frame": "sp"})
    assert c.kmod_inject.frame == "sp"
    assert c.flash.interface == "virtio"


# ---- snapshots ----

def test_flash_args_snapshot_overlay():
    conf = _conf(flash={"path": "flash/nand.img", "interface": "mtd"})
    assert _board_flash_args(conf, "/nonexistent", overlay="/q/snapshot_warm.qcow2") == [
        "-drive", "if=mtd,format=qcow2,file=/q/snapshot_warm.qcow2"]


def test_check_rejects_readiness_snapshot():
    with pytest.raises(ValueError, match="manual"):
        _check_board_image_config(_conf(snapshot={"save_at": "readiness"}))
    _check_board_image_config(_conf(snapshot={"save_at": "manual"}))


def test_boot_fingerprint_covers_flash(tmp_path):
    from penguin.utils import boot_fingerprint
    (tmp_path / "flash").mkdir()
    img = tmp_path / "flash" / "nand.img"
    img.write_bytes(b"\xff" * 16)
    conf = _conf(kernel="kernels/2.6.36/Image", arch="armel",
                 kmod_inject={"hook": "vector_swi+0x20"})
    conf.update(env={}, nvram={}, netdevs=[], pseudofiles={})
    a = boot_fingerprint(str(tmp_path), conf)
    img.write_bytes(b"\x00" * 16)
    b = boot_fingerprint(str(tmp_path), conf)
    conf["core"]["kmod_inject"] = {"hook": "vector_swi+0x24"}
    c = boot_fingerprint(str(tmp_path), conf)
    assert len({a, b, c}) == 3
