"""
penguin.q_config
================

QEMU configuration utilities for the Penguin emulation environment.

This module provides architecture-specific QEMU configuration mappings and
a helper function to load the configuration for a given architecture.
"""

# Note armel is just panda-system-arm and mipseb is just panda-system-mips
ROOTFS: str = "/dev/vda"  # Common to all
qemu_configs: dict[str, dict[str, str]] = {
    "armel": {
        "qemu_machine": "virt",
        "arch": "arm",
        "kernel_whole": "zImage.armel",
    },
    "aarch64": {
        "qemu_machine": "virt",
        "kconf_group": "arm64",
        "cpu": "cortex-a57",
        "kernel_whole": "zImage.arm64",
    },
    "loongarch64": {
        "qemu_machine": "virt",
        "cpu": "la464",
        "kernel_fmt": "vmlinuz.efi"
    },
    "mipsel": {
        "qemu_machine": "malta",
    },
    "mipseb": {
        "qemu_machine": "malta",
        "arch": "mips",
        "kernel_whole": "vmlinux.mipseb"
    },
    "mips64el": {
        "qemu_machine": "malta",
        "cpu": "MIPS64R2-generic",
        "kernel_whole": "vmlinux.mips64el",
    },
    "mips64eb": {
        "qemu_machine": "malta",
        "arch": "mips64",
        "kernel_whole": "vmlinux.mips64eb",
        "cpu": "MIPS64R2-generic",
    },
    "powerpc64el": {
        "qemu_machine": "pseries",
        "arch": "ppc64",
        "cpu": "power9",
    },
    "powerpc64": {
        "qemu_machine": "pseries",
        "arch": "ppc64",
        "cpu": "power9",
        "kconf_group": "powerpc64",
        "kernel_whole": "vmlinux.powerpc64"
    },
    "riscv64": {
        "qemu_machine": "virt",
        "kernel_fmt": "Image",
    },
    "intel64": {
        "qemu_machine": "pc",
        "arch": "x86_64",
        "kconf_group": "x86_64",
        "kernel_fmt": "bzImage",
    },
}


def load_q_config(conf: dict) -> dict[str, str]:
    """
    Load the QEMU configuration for the given architecture.

    :param conf: Configuration dictionary containing 'core' and 'arch' keys.
    :type conf: dict

    :return: QEMU configuration dictionary for the specified architecture.
    :rtype: dict[str, str]

    :raises ValueError: If the architecture is unknown.
    """
    archend = conf["core"]["arch"]
    try:
        q_config = qemu_configs[archend]
        q_config["kconf_group"] = q_config.get("kconf_group", archend)
        q_config["arch"] = q_config.get("arch", archend)
    except KeyError:
        raise ValueError(f"Unknown architecture: {archend}")
    return q_config
