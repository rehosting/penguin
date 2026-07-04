"""
Unit tests for the per-arch kernel cmdline length guard (env-off-cmdline slice 0).

The kernel silently truncates a ``-append`` longer than its compile-time
``COMMAND_LINE_SIZE`` (as low as 256B on the MIPS kernels we ship), quietly
dropping boot env. These tests assert that:

  * a representative penguin config's assembled cmdline fits under every arch's
    cap (so a new knob that blows the MIPS 256B budget is caught here, in CI,
    rather than in a mystifying rehost), and
  * the guard raises loudly (never silently truncates) once the cap is exceeded.

Everything here runs without a rootfs, kernel, or container.
"""

import logging

import pytest

from penguin import arch_registry
from penguin.penguin_run import render_kernel_append, check_cmdline_size


# A representative set of the igloo knobs that core.py and friends push into
# conf["env"] for a typical run. Kept deliberately realistic so the MIPS 256B
# assertion is meaningful — if this naturally grows past the budget, that is the
# signal slice 0 exists to surface.
# Penguin-internal knobs (moved off the cmdline to the boot env blob) plus a
# couple of user/firmware `env:` entries (which stay on the cmdline).
REPRESENTATIVE_ENV = {
    "igloo_init": "/igloo/init",
    "CID": "3",
    "PROJ_NAME": "test_target",
    "SHARED_DIR": "1",
    "ROOT_SHELL": "1",
    "WWW": "1",
    "STRACE": "1",
    "IGLOO_CGROUP_MODE": "v1",
    "IGLOO_IPTABLES_BACKEND": "legacy",
    "IGLOO_LTRACE": "1",
    # user/firmware-expected params (read by vendor init from /proc/cmdline)
    "somevar": "someval",
    "mtdparts": "phys:512k(boot),1m(kernel)",
}

# Internal knobs that must NOT appear on the cmdline anymore.
INTERNAL_KEYS = (
    "igloo_init", "CID", "PROJ_NAME", "SHARED_DIR", "ROOT_SHELL",
    "WWW", "STRACE", "IGLOO_CGROUP_MODE", "IGLOO_IPTABLES_BACKEND", "IGLOO_LTRACE",
)

# What QEMU/penguin already placed on the append before our env is merged in.
REPRESENTATIVE_APPEND_PARTS = ["console=ttyS0", "rw"]


class _CapturingLogger:
    """Minimal logger stand-in that records warning() calls."""

    def __init__(self):
        self.warnings = []

    def warning(self, msg, *args):
        self.warnings.append(msg % args if args else msg)


def test_representative_config_fits_every_arch():
    """The representative cmdline must stay under every shipped arch's cap."""
    logger = logging.getLogger("test")
    cmdline = render_kernel_append(REPRESENTATIVE_APPEND_PARTS, REPRESENTATIVE_ENV)
    for arch in arch_registry.canonical_names():
        cap = arch_registry.spec(arch).command_line_size
        assert len(cmdline) < cap, (
            f"representative cmdline is {len(cmdline)}B but {arch} caps at "
            f"COMMAND_LINE_SIZE={cap}: {cmdline!r}"
        )
        # And the guard itself must agree (not raise) for the representative env.
        check_cmdline_size(cmdline, arch, logger)


def test_internal_knobs_are_off_the_cmdline():
    """Penguin-internal knobs must not appear on -append; user env must."""
    cmdline = render_kernel_append(REPRESENTATIVE_APPEND_PARTS, REPRESENTATIVE_ENV)
    for key in INTERNAL_KEYS:
        assert key not in cmdline, f"internal knob {key} leaked onto the cmdline"
    # User/firmware-expected params still ride the cmdline.
    assert "somevar=someval" in cmdline
    assert "mtdparts=" in cmdline


def test_all_arches_share_the_4096_cap():
    """Every shipped arch now caps at 4096.

    MIPS used to be the tight one (256B) because QEMU's malta board passed the
    cmdline through a single 256B prom env slot (hw/mips/malta.c ENVP_ENTRY_SIZE),
    truncating it before the kernel saw it. That slot is now 0xfdc0, and the MIPS
    kernels themselves use COMMAND_LINE_SIZE=4096, so MIPS matches everyone else.
    This anti-drift check fails if a future edit re-tightens MIPS without also
    re-tightening the malta board (the two must move together).
    """
    for arch in ("mipsel", "mipseb", "mips64el", "mips64eb",
                 "armel", "aarch64", "riscv64", "loongarch64", "x86_64"):
        assert arch_registry.spec(arch).command_line_size == 4096


def test_critical_args_come_first():
    """root=/init=/panic= must lead and not be clobbered by config env."""
    cmdline = render_kernel_append(["console=ttyS0"], {"vendorvar": "x"})
    assert cmdline.startswith("root=/dev/vda init=/igloo/boot/preinit panic=1")


def test_kernel_cmdline_append_reaches_cmdline_verbatim():
    """core.kernel_cmdline_append tokens land on the cmdline and are never diverted."""
    # IGLOO_-prefixed and internal keys here would normally go to the blob, but
    # via the explicit raw channel they must reach the cmdline verbatim.
    cmdline = render_kernel_append(
        ["console=ttyS0"],
        {"ROOT_SHELL": "1"},                 # internal -> blob (absent from cmdline)
        extra_cmdline="nokaslr igloo_debug=1 mem=256M",
    )
    assert "ROOT_SHELL" not in cmdline       # still diverted
    assert "nokaslr" in cmdline
    assert "igloo_debug=1" in cmdline        # explicit, not diverted
    assert "mem=256M" in cmdline


def test_kernel_cmdline_append_counts_against_cap():
    """Explicit cmdline tokens are measured by the length guard like everything else."""
    logger = _CapturingLogger()
    big = " ".join(f"flag{i}=xxxxxxxx" for i in range(300))
    cmdline = render_kernel_append([], {}, extra_cmdline=big)
    assert len(cmdline) > 4096
    with pytest.raises(RuntimeError, match="COMMAND_LINE_SIZE"):
        check_cmdline_size(cmdline, "mipsel", logger)


def test_oversized_cmdline_raises_loudly():
    """Exceeding the cap must raise — never silently truncate."""
    logger = _CapturingLogger()
    # Build env that comfortably blows the 4096B budget. Use non-internal keys
    # so they actually land on the cmdline (internal knobs move to the blob).
    big_env = {f"vendorvar_{i:03d}": "x" * 20 for i in range(200)}
    cmdline = render_kernel_append([], big_env)
    assert len(cmdline) > 4096
    with pytest.raises(RuntimeError, match="COMMAND_LINE_SIZE"):
        check_cmdline_size(cmdline, "mipsel", logger)


def test_warns_when_approaching_cap():
    """A cmdline in the top 10% of the budget warns but does not raise."""
    logger = _CapturingLogger()
    cap = arch_registry.spec("mipsel").command_line_size  # 256
    # Land between 90% of usable and usable (one var, padded value).
    target = int((cap - 1) * 0.95)
    value = "x" * (target - len("PAD="))
    cmdline = f"PAD={value}"
    assert (cap - 1) * 9 // 10 < len(cmdline) <= cap - 1
    check_cmdline_size(cmdline, "mipsel", logger)
    assert logger.warnings, "expected an approaching-cap warning"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
