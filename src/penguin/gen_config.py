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
from .penguin_static import generate_static_patches, find_env_options_and_init

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


def make_config(fs, out, artifacts, timeout=None, auto_explore=False):
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

    tmpdir = None
    if artifacts is None:
        tmpdir = tempfile.TemporaryDirectory()
        output_dir = tmpdir.name
    else:
        output_dir = Path(artifacts)
        output_dir.mkdir(exist_ok=True)

    # extract into output_dir/base/{image.qcow,fs.tar}
    arch_identified = find_architecture(fs)
    if arch_identified is None:
        raise ValueError(f"Failed to determine architecture for {fs}")
    arch, end = arch_end(arch_identified)

    if arch is None:
        raise ValueError(f"Architecture {arch_identified} not supported ({arch}, {end})")

    kernel = get_kernel_path(arch, end, static_dir)

    base_dir = Path(output_dir, "base")
    base_dir.mkdir(exist_ok=True, parents=True)
    base_fs = Path(base_dir, "fs.tar.gz")
    shutil.copy(fs, base_fs)

    data = {}
    data["core"] = {
        "arch": arch if arch in ["aarch64", "intel64"] else arch + end,
        "kernel": kernel,
        "fs": "./base/fs.tar.gz",
        "root_shell": True,
        "show_output": False,
        "strace": False,
        "ltrace": False,
        "version": default_version,
        "auto_patching": True,
    }

    data["blocked_signals"] = []
    data["netdevs"] = default_netdevs

    data["env"] = {}
    data["pseudofiles"] = default_pseudofiles
    data["lib_inject"] = {"aliases": default_lib_aliases}

    data["static_files"] = {
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
    }

    data["static_files"]["/igloo/keys/*"] = {
        "type": "host_file",
        "mode": 0o444,
        "host_path": join(*[dirname(dirname(__file__)), "resources", "static_keys", "*"])
    }

    # Add ltrace prototype files.
    #
    # They to go in `/igloo/ltrace`, because `/igloo` is treated as ltrace's
    # `/usr/share`, and the files are normally in `/usr/share/ltrace`.
    data["static_files"][f"/igloo/ltrace/*"] = {
        "type": "host_file",
        "mode": 0o444,
        "host_path": join(*[static_dir, "ltrace", "*"]),
    }

    arch_suffix = f".{arch}{end}"
    dylib_dir = join(static_dir, "dylibs", arch + end)
    if arch == "aarch64":
        # TODO: We should use a consistent name here. Perhaps aarch64eb?
        arch_suffix = ".aarch64"
        dylib_dir = join(static_dir, "dylibs", "arm64")
    elif arch == "intel64":
        arch_suffix = ".x86_64"
        dylib_dir = join(static_dir, "dylibs", "x86_64")

	# Add dynamic libraries
    data["static_files"][f"/igloo/dylibs/*"] = {
        "type": "host_file",
        "mode": 0o755,
        "host_path": join(dylib_dir, "*"),
    }

    data["static_files"]["/igloo/utils"] = {
        "type": "dir",
        "mode": 0o755,
    }

    # Add executable binaries, can't use a full directory copy here because we rename things
    for util_dir in ["console", "libnvram", "utils.bin", "utils.source", "vpn"]:
        for f in os.listdir(join(static_dir, util_dir)):
            if f.endswith(arch_suffix) or f.endswith(".all"):
                out_name = f.replace(arch_suffix, "").replace(".all", "")
                data["static_files"][f"/igloo/utils/{out_name}"] = {
                    "type": "host_file",
                    "host_path": f"/igloo_static/{util_dir}/{f}",
                    "mode": 0o755,
                }

	# Add serial device in pseudofiles
    # XXX: For mips we use major 4, minor 65. For arm we use major 204, minor 65.
    # This is because arm uses ttyAMA (major 204) and mips uses ttyS (major 4).
    # so calling it ttyS1 is a bit of a misnomer, but we don't want to go patch the console
    # binary to use a different path.
    data["static_files"]["/igloo/serial"] = {
        "type": "dev",
        "devtype": "char",
        "major": 4 if "mips" in data["core"]["arch"] else 204,
        "minor": 65,
        "mode": 0o666,
    }

    data["plugins"] = default_plugins

    # Explicitly placing this at the end
    data["nvram"] = {}

    if auto_explore:
        # If auto_explore, we'll enable extra plugins to generate coverage - unless we're told the VPN is disabled.
        if "vpn" in data["plugins"] and data["plugins"]["vpn"].get("enabled", True):
            # If we have VPN (which we will if we have vsock), turn on zap and nmap
            for p in ["nmap"]:
                if p in data["plugins"]:
                    data["plugins"][p]["enabled"] = True

        # Also disable root shell and set timeout to 5 minutes (unless told otherwise)
        data["core"]["root_shell"] = False
        data["plugins"]["core"]["timeout"] = timeout if timeout else 300
    else:
        # Interactive, let's enable root shell and fully delete some plugins
        data["core"]["root_shell"] = True
        for p in ["zap", "nmap" "coverage"]:
            if p in data["plugins"]:
                del data["plugins"][p]

    # Make sure we have a base directory to store config
    # and static results in.
    if not os.path.isdir(os.path.join(output_dir, "base")):
        os.makedirs(os.path.join(output_dir, "base"))

    # If we create files (e.g., base/*.yaml, output/*.yaml), we want them to be
    # readable/writable by everyone since non-container users will want to access them
    os.umask(0o000)

    init = find_env_options_and_init(output_dir, data, f"{output_dir}/base/")
    if init is None:
        raise ValueError("Failed to find an init script")
    data["env"]["igloo_init"] = init

    patch_names = generate_static_patches(
        output_dir,
        data,
        f"{output_dir}/base/",
        f"{output_dir}/patches/")
    

    # TODO: Add patches by name into config['patches']

    if not auto_explore:
        # We want to build this configuration for a single-shot rehost.
        # We'll ensure it has an igloo_init set and we'll specify an ioctl model for all our pseudofiles in /dev
        logger.info(
            "Tailoring configuration for single-iteration: selecting init and configuring default catch-all ioctl models"
        )

        with open(f"{output_dir}/base/env.yaml", "r") as f:
            static_env = yaml.safe_load(f)
            if "igloo_init" in static_env and len(static_env["igloo_init"]) > 0:
                data["env"]["igloo_init"] = static_env["igloo_init"][0]
                logger.info(f"\tinit set to: {data['env']['igloo_init']}")
                if len(static_env["igloo_init"]) > 1:
                    logger.debug(
                        f"\tOther options are: {', '.join(static_env['igloo_init'][1:])}"
                    )

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

        # Now we'll set a default ioctl model for all our pseudofiles in /dev
        for dev in data["pseudofiles"]:
            if dev.startswith("/dev/"):
                data["pseudofiles"][dev]["ioctl"] = {
                    "*": {
                        "model": "return_const",
                        "val": 0,
                    }
                }

    else:
        # Automated mode

        # Turn on force_www -> it will probably help?
        data["core"]["force_www"] = True

        # Make sure we dont' have an igloo_init set
        if "igloo_init" in data["env"]:
            # Make sure we didn't set an igloo_init in our env if there are multiple potential values
            with open(f"{output_dir}/base/env.yaml", "r") as f:
                static_env = yaml.safe_load(f)
                if "igloo_init" in static_env:
                    if len(static_env["igloo_init"]) > 1:
                        del data["env"]["igloo_init"]

    # Data includes 'meta' field with hypotheses about files/devices
    # Let's drop that. It's stored in base/{env,files}.yaml
    if "meta" in data:
        del data["meta"]

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
        dump_config(data, outfile)

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


def fakeroot_gen_config(fs, out, artifacts, verbose):
    o = Path(out)
    cmd = [
        "fakeroot",
        "gen_config",
        "--fs",
        str(fs),
        "--out",
        str(o),
        "--artifacts",
        artifacts,
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
