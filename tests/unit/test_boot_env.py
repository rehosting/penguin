"""
Unit tests for penguin.boot_env (env-off-cmdline slice 1).

Penguin's internal env knobs are partitioned off the kernel cmdline and
delivered as an early-boot `export K=V` blob that preinit.sh sources. These
tests pin the partition rule and the blob rendering.

Everything here runs without a rootfs, kernel, or container.
"""

import pytest

from penguin.boot_env import (
    KERNEL_CMDLINE_KNOBS,
    PENGUIN_INTERNAL_ENV,
    is_penguin_internal_env,
    partition_boot_env,
    render_env_blob,
)


@pytest.mark.parametrize("key", [
    "igloo_init",                              # lowercase igloo_ prefix
    "IGLOO_LTRACE", "IGLOO_CGROUP_MODE",       # uppercase IGLOO_ prefix
    "IGLOO_OWN_IFACES", "IGLOO_EXT_MAC",       # newer prefixed knobs (no edit needed)
    "ROOT_SHELL", "SHARED_DIR", "WWW", "CID",  # un-prefixed knobs
    "STRACE", "PROJ_NAME", "LD_LIBRARY_PATH", "TERM",
])
def test_internal_keys_recognized(key):
    assert is_penguin_internal_env(key)


@pytest.mark.parametrize("key", [
    "somevar", "mtdparts", "console", "root", "vendor_flag", "DEBUG",
])
def test_external_keys_not_internal(key):
    assert not is_penguin_internal_env(key)


@pytest.mark.parametrize("key", sorted(KERNEL_CMDLINE_KNOBS))
def test_kernel_cmdline_knobs_stay_on_cmdline(key):
    # Kernel-parsed knobs carry the igloo_ prefix but must NOT be diverted to the
    # blob -- the kernel reads them from /proc/cmdline at boot, before the blob is
    # sourced in preinit.sh. Regression guard for the ros6 VM-split break
    # (igloo_task_size diverted off the cmdline -> wrong guest address-space split).
    assert not is_penguin_internal_env(key)
    cmdline_env, blob_env = partition_boot_env({key: "0x7f000000"})
    assert key not in blob_env
    assert cmdline_env == {key: "0x7f000000"}


def test_explicit_set_is_a_subset_of_recognized():
    # Every explicitly-listed knob must be recognized as internal.
    for key in PENGUIN_INTERNAL_ENV:
        assert is_penguin_internal_env(key)


def test_partition_splits_internal_from_firmware():
    env = {
        "igloo_init": "/igloo/init",
        "ROOT_SHELL": "1",
        "IGLOO_LTRACE": "1",
        "somevar": "someval",         # user/firmware -> cmdline
        "mtdparts": "phys:1m(boot)",  # firmware -> cmdline
    }
    cmdline_env, blob_env = partition_boot_env(env)
    assert set(blob_env) == {"igloo_init", "ROOT_SHELL", "IGLOO_LTRACE"}
    assert set(cmdline_env) == {"somevar", "mtdparts"}
    # The two buckets are a clean disjoint partition of the input.
    assert set(cmdline_env) | set(blob_env) == set(env)
    assert not (set(cmdline_env) & set(blob_env))


def test_partition_preserves_insertion_order():
    env = {"ZZZ": "1", "igloo_a": "1", "aaa": "2", "IGLOO_B": "3"}
    cmdline_env, blob_env = partition_boot_env(env)
    assert list(cmdline_env) == ["ZZZ", "aaa"]
    assert list(blob_env) == ["igloo_a", "IGLOO_B"]


def test_render_env_blob_emits_export_lines():
    blob = render_env_blob({"ROOT_SHELL": "1", "igloo_init": "/igloo/init"})
    assert "export ROOT_SHELL=1" in blob
    assert "export igloo_init=/igloo/init" in blob
    assert blob.endswith("\n")


def test_render_env_blob_shell_quotes_values():
    blob = render_env_blob({"IGLOO_X": "a b; rm -rf /"})
    # The dangerous value must be quoted so sourcing it can't run anything.
    assert "export IGLOO_X='a b; rm -rf /'" in blob


def test_render_env_blob_skips_none_values():
    # A None value (a valueless cmdline flag) never became an env var on the
    # old cmdline path, so it must not be exported in the blob either.
    blob = render_env_blob({"ROOT_SHELL": "1", "IGLOO_FLAG": None})
    assert "ROOT_SHELL" in blob
    assert "IGLOO_FLAG" not in blob


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
