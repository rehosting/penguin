"""
penguin.q_config
================

QEMU configuration utilities for the Penguin emulation environment.

This module provides architecture-specific QEMU configuration mappings and
a helper function to load the configuration for a given architecture.
"""

# Note armel is just panda-system-arm and mipseb is just panda-system-mips.
# The per-arch QEMU facts now live in the single arch registry
# (penguin.arch_registry); this module just projects an ArchSpec into the
# legacy q_config dict shape that the rest of the runner expects.
ROOTFS: str = "/dev/vda"  # Common to all


def load_q_config(conf: dict) -> dict[str, str]:
    """
    Load the QEMU configuration for the given architecture.

    :param conf: Configuration dictionary containing 'core' and 'arch' keys.
    :type conf: dict

    :return: A fresh QEMU configuration dictionary for the specified architecture.
    :rtype: dict[str, str]

    :raises ValueError: If the architecture is unknown or has no QEMU machine.
    """
    from penguin import arch_registry

    archend = conf["core"]["arch"]
    try:
        s = arch_registry.spec(archend)
    except KeyError:
        raise ValueError(f"Unknown architecture: {archend}")
    if s.qemu_machine is None:
        raise ValueError(f"Unknown architecture: {archend}")

    # Return a fresh dict each call (the old code mutated a shared module dict).
    q_config = {
        "qemu_machine": s.qemu_machine,
        "arch": s.panda_arch,
        "kconf_group": s.kconf_group,
        "kernel_fmt": s.kernel_fmt,
        "kernel_whole": s.kernel_whole,
    }
    if s.cpu is not None:
        q_config["cpu"] = s.cpu
    return q_config
