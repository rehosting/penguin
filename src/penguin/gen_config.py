import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import yaml
import copy
from pathlib import Path
from collections import Counter
from os.path import dirname, join
from pathlib import Path

import click
import yaml
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
from .penguin_static import extend_config_with_static

logger = getColoredLogger("penguin.gen_confg")


def binary_filter(fsbase, name):
    base_directories = ["sbin", "bin", "usr/sbin", "usr/bin"]
    for base in base_directories:
        if name.startswith(join(fsbase, base)):
            return True
    # might be good to add "*.so" to this list
    return name.endswith("busybox")


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
    archs_list = list(arch_counts[32].values()) + list(arch_counts[64].values())
    if (
        any(arch in intel_archs for arch in archs_list)
        and any(arch not in intel_archs for arch in archs_list)
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
    else:
        return static_dir + f"kernels/{DEFAULT_KERNEL}/" + "vmlinux" + f".{arch}{end}"


def make_config(fs, out, artifacts, settings_path, timeout=None, auto_explore=False):
    logger.info(f"Generating new configuration for {fs}...")
    """
    Given a filesystem as a .tar.gz make a configuration

    When called as a function return the path to the configuration.

    Timeout enforced if it's provided.
    If it's None and auto_explore is true, we'll use 300s

    Auto controls if we turn on nmap scanning (auto = yes)
    If niters is 1 we'll select a default init and set the /dev/gpio ioctl model to return 0
    (Otherwise we'll learn both of these dynamically)

    Returns the path to the config file.
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
        logger.error(f"Failed to determine architecture for {fs}")
        return
    arch, end = arch_end(arch_identified)

    kernel = get_kernel_path(arch, end, static_dir)

    base_dir = Path(output_dir, "base")
    base_dir.mkdir(exist_ok=True, parents=True)
    base_fs = Path(base_dir, "fs.tar.gz")
    shutil.copy(fs, base_fs)

    data = {}
    data["core"] = {
        "arch": arch if arch == "aarch64" else arch + end,
        "kernel": kernel,
        "fs": "./base/fs.tar.gz",
        "root_shell": True,
        "show_output": False,
        "strace": False,
        "ltrace": False,
        "version": default_version,
    }

    data["blocked_signals"] = []
    data["netdevs"] = default_netdevs

    data["env"] = {}
    data["pseudofiles"] = default_pseudofiles
    data["lib_inject"] = {"aliases": default_lib_aliases}

    data["static_files"] = {
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

    data["static_files"]["/igloo/keys/"] = {
        "type": "dir",
        "mode": 0o755,
    }
    for f in os.listdir(
        os.path.join(*[dirname(dirname(__file__)), "resources", "static_keys"])
    ):
        data["static_files"][f"/igloo/keys/{f}"] = {
            "type": "host_file",
            # 'contents': open(static_dir + f"static_keys/{f}", 'rb').read(),
            "host_path": os.path.join(
                *[dirname(dirname(__file__)), "resources", "static_keys", f]
            ),
            "mode": 0o444,
        }

    for dir in ("/igloo", "/igloo/utils", "/igloo/dylibs", "/igloo/ltrace"):
        data["static_files"][dir] = dict(type="dir", mode=0o755)

    # Add ltrace prototype files.
    #
    # They to go in `/igloo/ltrace`, because `/igloo` is treated as ltrace's
    # `/usr/share`, and the files are normally in `/usr/share/ltrace`.
    ltrace_prots_dir = join(static_dir, "ltrace")
    for f in os.listdir(ltrace_prots_dir):
        data["static_files"][f"/igloo/ltrace/{f}"] = dict(
            type="host_file",
            host_path=join(ltrace_prots_dir, f),
            mode=0o444,
        )

    arch_suffix = f".{arch}{end}"
    dylib_dir = join(static_dir, "dylibs", arch + end)
    if arch == "aarch64":
        # TODO: We should use a consistent name here. Perhaps aarch64eb?
        arch_suffix = ".aarch64"
        dylib_dir = join(static_dir, "dylibs", "arm64")

    # Add executable binaries
    for util_dir in ["console", "libnvram", "utils.bin", "utils.source", "vpn"]:
        for f in os.listdir(join(static_dir, util_dir)):
            if f.endswith(arch_suffix) or f.endswith(".all"):
                out_name = f.replace(arch_suffix, "").replace(".all", "")
                data["static_files"][f"/igloo/utils/{out_name}"] = {
                    "type": "host_file",
                    "host_path": f"/igloo_static/{util_dir}/{f}",
                    "mode": 0o755,
                }

    # Add dynamically-linked libraries
    for f in os.listdir(dylib_dir):
        data["static_files"][f"/igloo/dylibs/{f}"] = dict(
            type="host_file",
            host_path=join(dylib_dir, f),
            mode=0o755,
        )

    data["plugins"] = default_plugins

    # Function to update the global settings variable
    def _recursive_update(base, new):
        for k, v in new.items():
            if isinstance(v, dict):
                base[k] = _recursive_update(base.get(k, {}), v)
            else:
                base[k] = v
        return base

    # Replace all values in default_settings.yaml with user_settings.yaml (user_settings is the one that was passed in)
    settings = {}
    user_settings = {}
    if settings_path:
        # TODO: apply all use cases
        relative_path = "src/penguin/resources/default_settings.yaml"
        absolute_path = os.path.join(os.getcwd(), relative_path)
        try:
            with open(settings_path, "r") as user_f:
                user_settings = yaml.safe_load(user_f)
            with open(absolute_path, "r") as default_f:
                settings = yaml.safe_load(default_f)
        except Exception as e:
            logger.error(f"An unexpected error has occurred: {e}")

        if user_settings:
            for key, value in user_settings.items():
                if key in settings:
                    # If the value is a dictionary, update subfields recursively
                    if isinstance(value, dict):
                        settings[key] = _recursive_update(settings.get(key, {}), value)
                    else:
                        settings[key] = value
                else:
                    logger.error(
                        f"Invalid key in YAML file: '{key}' not found in default settings."
                    )

    if settings and settings["coverage"]:
        data["plugins"]["coverage"]["enabled"] = True

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

    data = extend_config_with_static(
        output_dir, data, f"{output_dir}/base/", settings, auto_explore
    )

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


def fakeroot_gen_config(fs, out, artifacts, verbose, settings_path):
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
    if settings_path:
        cmd.extend(["--settings", str(settings_path)])
    p = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()
    if o.exists():
        return str(o)


@click.command()
@click.option("--fs", required=True, help="Path to a filesystem as a tar gz")
@click.option("--out", required=True, help="Path to a config to be created")
@click.option("--artifacts", default=None, help="Path to a directory for artifacts")
@click.option("-v", "--verbose", count=True)
@click.option("-s", "--settings", type=str, help="Path to the YAML configuration file")
def makeConfig(fs, out, artifacts, verbose, settings_path):
    if verbose:
        logger.setLevel(logging.DEBUG)

    config = make_config(fs, out, artifacts, settings_path)
    if not config:
        logger.error(f"Error! Could not generate config for {fs}")
    else:
        logger.info(f"Generated config at {config}")


if __name__ == "__main__":
    makeConfig()
