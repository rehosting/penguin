import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import yaml
from pathlib import Path
from collections import Counter
from os.path import dirname, join
import click
from elftools.elf.elffile import ELFFile

from penguin import getColoredLogger

from .arch import arch_end, arch_filter
from .defaults import (
    DEFAULT_KERNEL,
    default_init_script,
    default_lib_aliases,
    default_netdevs,
    default_plugins,
    default_pseudofiles,
    default_version,
    static_dir,
)
from .penguin_config import dump_config
from .penguin_static import create_patches, find_env_options_and_init, log_potential_pseudofiles

logger = getColoredLogger("penguin.gen_config")


def binary_filter(fsbase, name):
    base_directories = ["sbin", "bin", "usr/sbin", "usr/bin"]
    for base in base_directories:
        if name.startswith(join(fsbase, base)):
            return True
    # Shared libraries, kernel modules, or busybox
    return name.endswith((".so", ".ko")) or \
        ".so." in name or \
        name.endswith("busybox")

def find_architecture(infile):
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(infile) as tf:
            # Extracting to a temporary directory is much faster than processing
            # directly with tarfile
            tf.extractall(tmp)
        arch_counts = {32: Counter(), 64: Counter()}
        for root, _, files in os.walk(tmp):
            for file_name in files:
                path = join(root, file_name)

                if (
                    os.path.isfile(path)
                    and not os.path.islink(path)
                    and binary_filter(tmp, path)
                ):
                    logger.debug(f"Checking architecture in {path}")
                    with open(path, "rb") as f:
                        if f.read(4) != b"\x7fELF":
                            continue
                        f.seek(0)
                        ef = ELFFile(f)
                        info = arch_filter(ef)
                    assert info.bits is not None
                    arch_counts[info.bits][info.arch] += 1

    # If there is at least one intel and non-intel arch,
    # filter out all the intel ones.
    # Some firmwares include x86_64 binaries left-over from the build process that aren't run in the guest.
    intel_archs = ("intel", "intel64")
    archs_list = list(arch_counts[32].keys()) + list(arch_counts[64].keys())
    if any(arch in intel_archs for arch in archs_list) and any(
        arch not in intel_archs for arch in archs_list
    ):
        del arch_counts[32]["intel"]
        del arch_counts[64]["intel64"]

    # Now select the most common architecture.
    # First try the most common 64-bit architecture.
    # Then try the most common 32-bit one.
    best_64 = arch_counts[64].most_common(1)
    best_32 = arch_counts[32].most_common(1)
    if len(best_64) != 0:
        best = best_64[0][0]
    elif len(best_32) != 0:
        best = best_32[0][0]
    else:
        return None

    logger.debug(f"Identified architecture: {best}")
    return best


def get_kernel_path(arch, end, static_dir):
    if arch == "arm":
        return static_dir + f"kernels/{DEFAULT_KERNEL}/zImage.arm{end}"
    elif arch == "aarch64":
        return static_dir + f"kernels/{DEFAULT_KERNEL}/zImage.arm64"
    elif arch == "intel64":
        return static_dir + f"kernels/{DEFAULT_KERNEL}/bzImage.x86_64"
    else:
        return static_dir + f"kernels/{DEFAULT_KERNEL}/" + "vmlinux" + f".{arch}{end}"

def get_arch_info(arch, end):
    '''
    Our naming convention for architectures is a bit inconsistent. This function
    returns the arch name, kernel suffix, and dylib directory for a given architecture.
    '''
    if arch == "aarch64":
        # TODO: We should use a consistent name here. Perhaps aarch64eb?
        arch_name = "aarch64"
        arch_suffix = ".aarch64"
        dylib_dir = join(static_dir, "dylibs", "arm64")
    elif arch == "intel64":
        arch_name = "intel64"
        arch_suffix = ".x86_64"
        dylib_dir = join(static_dir, "dylibs", "x86_64")
    else:
        arch_name = arch + end
        arch_suffix = f".{arch}{end}"
        dylib_dir = join(static_dir, "dylibs", arch + end)
    return arch_name, arch_suffix, dylib_dir


def make_config(fs, out, artifacts_dir, timeout=None, auto_explore=False):
    logger.info(f"Generating new configuration for {fs}...")
    """
    Given a filesystem as a .tar.gz make a configuration

    When called as a function return the path to the configuration.

    Timeout enforced if it's provided.
    If it's None and auto_explore is true, we'll use 300s

    Auto controls if we turn on nmap scanning (auto = yes)
    If niters is 1 we'll select a default init and set the /dev/gpio ioctl model to return 0
    (Otherwise we'll learn both of these dynamically)

    Returns the path to the config file. Raises an exception with a user-friendly message if it fails.
    """

    # If auto_explore we'll turn on zap and nmap to automatically generate coverage
    # Note that there's no way for a user to control that flag yet.

    if not os.path.isfile(fs):
        raise RuntimeError(f"FATAL: Firmware file not found: {fs}")

    if not fs.endswith(".tar.gz"):
        raise ValueError(
            f"Penguin should begin post extraction and be given a .tar.gz archive of a root fs, not {fs}"
        )

    if artifacts_dir is None:
        tmpdir = tempfile.TemporaryDirectory()
        output_dir = tmpdir.name
    else:
        tmpdir = None
        output_dir = Path(artifacts_dir)
        output_dir.mkdir(exist_ok=True)

    # Ensure created files (e.g., base/*.yaml, output/*.yaml), are
    # readable/writable by everyone since non-container users will want to access them
    os.umask(0o000)

    # Create a base directory for filesystem archive and static analysis results
    base_dir = Path(output_dir, "base")
    base_dir.mkdir(exist_ok=True, parents=True)
    base_fs = Path(base_dir, "fs.tar.gz")
    shutil.copy(fs, base_fs)

    # TODO: refactor to have a single extract with patches into output_dir
    arch_identified = find_architecture(fs)
    if arch_identified is None:
        raise ValueError(f"Failed to determine architecture for {fs}")

    arch, end = arch_end(arch_identified)
    if arch is None:
        raise ValueError(f"Architecture {arch_identified} not supported ({arch}, {end})")
    arch_name, arch_suffix, dylib_dir = get_arch_info(arch, end)

    # Find init and create env.yaml in base directory
    # TODO: refactor to have single extract with patches
    best_init = find_env_options_and_init(output_dir, base_fs, f"{output_dir}/base/")
    if best_init is None:
        raise ValueError("Failed to find an init script")

    config = {
        "core": {
            "arch": arch_name,
            "kernel": get_kernel_path(arch, end, static_dir),
            "fs": "./base/fs.tar.gz",
            "root_shell": True,
            "show_output": False,
            "strace": False,
            "ltrace": False,
            "version": default_version,
        },
        "env": {
            "igloo_init": best_init,
        },
        "patches": [],
        "blocked_signals": [],
        "netdevs": [],
        "lib_inject": {},
        "pseudofiles": {},
        "static_files": {
            "/igloo": {
                    "type": "dir",
                    "mode": 0o755,
                },
                "/igloo/init": {
                    "type": "inline_file",
                    "contents": default_init_script,
                    "mode": 0o111,
                },
                "/igloo/utils/sh": {
                    "type": "symlink",
                    "target": "/igloo/utils/busybox",
                },
                "/igloo/utils/sleep": {
                    "type": "symlink",
                    "target": "/igloo/utils/busybox",
                },
                # Pre-computed crypto keys
                "/igloo/keys/*": {
                    "type": "host_file",
                    "mode": 0o444,
                    "host_path": join(*[dirname(dirname(__file__)), "resources", "static_keys", "*"])
                },
                # Add ltrace prototype files. They go in /igloo/ltrace because /igloo is treated as ltrace's /usr/share, and the files are normally in /usr/share/ltrace.
                "/igloo/ltrace/*": {
                    "type": "host_file",
                    "mode": 0o444,
                    "host_path": join(*[static_dir, "ltrace", "*"]),
                },

                # Dynamic libraries
                "/igloo/dylibs/*": {
                    "type": "host_file",
                    "mode": 0o755,
                    "host_path": join(dylib_dir, "*"),
                },

                "/igloo/utils": {
                    "type": "dir",
                    "mode": 0o755,
                },

                # Add serial device in pseudofiles
                # XXX: For mips we use major 4, minor 65. For arm we use major 204, minor 65.
                # This is because arm uses ttyAMA (major 204) and mips uses ttyS (major 4).
                "/igloo/serial": {
                    "type": "dev",
                    "devtype": "char",
                    "major": 4 if "mips" in arch else 204,
                    "minor": 65,
                    "mode": 0o666,
                }
        },
        "plugins": default_plugins,
        "nvram": {},
    }

    # Always add our utilities into static files. Note that we can't currently use
    #a full directory copy since we're doing some renaming.
    # TODO: Refactor utility paths in container so we can just copy the whole directory
    # for a given architecture.
    for util_dir in ["console", "libnvram", "utils.bin", "utils.source", "vpn"]:
        for f in os.listdir(join(static_dir, util_dir)):
            if f.endswith(arch_suffix) or f.endswith(".all"):
                out_name = f.replace(arch_suffix, "").replace(".all", "")
                config["static_files"][f"/igloo/utils/{out_name}"] = {
                    "type": "host_file",
                    "host_path": f"/igloo_static/{util_dir}/{f}",
                    "mode": 0o755,
                }
    patch_names = create_patches(
        output_dir,
        config,
        f"{output_dir}/base/",
        f"{output_dir}/patches/")

    if len(patch_names):
        # TODO: should this be ordered?
        config["patches"] = list(patch_names)

    # TODO: in create_patches we do env.yaml, but here we do pseudofiles.yaml independently
    log_potential_pseudofiles(
        output_dir,
        config,
        f"{output_dir}/base/")

    # For all identified pseudofiles, try adding them. This reliably causes kernel panics - are we running
    # out of kernel memory or are we clobbering important things?
    """
    with open(f"{output_dir}/base/pseudofiles.yaml", 'r') as f:
        static_pseudofiles = yaml.safe_load(f)
        print(f"Static analysis identified {len(static_pseudofiles)} potential pseudofiles")
        cnt = 0
        for f in static_pseudofiles:
            if f in data['pseudofiles']:
                continue

            if len(f.split("/")) == 3: # /proc/foo good, /proc/asdf/zoo less good
                continue
            cnt += 1

            data['pseudofiles'][f] = {
                'read': {
                    "model": "zero",
                },
                'write': {
                    "model": "discard",
                }
            }

            if f.startswith("/proc/mtd"):
                data['pseudo_files'][f]['name'] = "uboot." + f.split("/")[-1]
        print(f"\tAdded {cnt} of them")
    """

    # Write config to both output and base directories. Disable flow style and width
    # so that our multi-line init script renders the way we want
    for idx, outfile in enumerate(
        [f"{output_dir}/base/initial_config.yaml", f"{output_dir}/config.yaml"]
    ):
        if idx == 1 and os.path.isfile(outfile):
            # Don't clobber existing config.yaml in main output dir
            # (but do clobber the initial_config.yaml in base if it exists)
            logger.debug(f"Not overwriting existing config file: {outfile}")
            continue
        dump_config(config, outfile)

    # Config is a path to output_dir/base/config.yaml
    if out:
        if not shutil._samefile(outfile, out):
            shutil.copyfile(outfile, out)
        final_out = out
    else:
        default_out = f"{output_dir}/base/config.yaml"
        if not shutil._samefile(outfile, default_out):
            shutil.copy(outfile, default_out)
        final_out = default_out

    if tmpdir:
        tmpdir.cleanup()

    return final_out


def fakeroot_gen_config(fs, out, artifacts_dir, verbose):
    o = Path(out)
    cmd = [
        "fakeroot",
        "gen_config",
        "--fs",
        str(fs),
        "--out",
        str(o),
        "--artifacts",
        artifacts_dir,
    ]
    if verbose:
        cmd.extend(["--verbose"])
    p = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()
    if o.exists():
        return str(o)


@click.command()
@click.option("--fs", required=True, help="Path to a filesystem as a tar gz")
@click.option("--out", required=True, help="Path to a config to be created")
@click.option("--artifacts", default=None, help="Path to a directory for artifacts")
@click.option("-v", "--verbose", count=True)
def makeConfig(fs, out, artifacts, verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # Return a path to a config if we generate one
        return make_config(fs, out, artifacts)
    except Exception as e:
        # Otherwise log error to results directory and with logger
        # Then return None
        # Ensure we have a directory to write result into
        result_dir = os.path.dirname(out)
        if not os.path.isdir(result_dir):
            os.makedirs(result_dir)
        with open(os.path.join(result_dir, "result"), "w") as f:
            f.write(str(e)+"\n")
        logger.error(f"Error! Could not generate config for {fs}")
        logger.exception(e)
        return None


if __name__ == "__main__":
    makeConfig()
