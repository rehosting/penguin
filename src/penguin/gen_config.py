"""
penguin.gen_config
==================

Configuration generation utilities for the Penguin emulation environment.

This module provides functions and classes for analyzing extracted filesystems,
running static analyses, generating configuration files and patches, and handling
config creation via CLI or programmatically.
"""

import click
import logging
import os
import shutil
import subprocess
import sys
import tempfile

from pathlib import Path
from penguin import getColoredLogger

from . import config_patchers as CP
from . import static_analyses as STATIC

from .defaults import (
    default_version as DEFAULT_VERSION,
)
from .init_plugin import InitContext
from .init_runner import InitPluginRunner
from penguin.penguin_config import dump_config

logger = getColoredLogger("penguin.gen_config")

# Built-in init plugins, loaded explicitly (discovery via plugin_path comes
# with the pyplugins/init migration). Execution is concurrent; the position of
# each plugin's patch in the generated config's `patches:` list (and therefore
# its override precedence) comes from its `order` attribute, not this list.
BUILTIN_INIT_PLUGINS = [
    # Analyses
    STATIC.ArchId,
    STATIC.InitFinder,
    STATIC.EnvFinder,
    STATIC.PseudofileFinder,
    STATIC.InterfaceFinder,
    STATIC.ClusterCollector,
    STATIC.LibrarySymbols,
    STATIC.KernelVersionFinder,
    # Patchers
    CP.BasePatch,
    CP.RootShell,
    CP.DynamicExploration,
    CP.SingleShotFICD,
    CP.ManualInteract,
    CP.NetdevsDefault,
    CP.NetdevsTailored,
    CP.PseudofilesExpert,
    CP.PseudofilesTailored,
    CP.LibInjectSymlinks,
    CP.LibInjectStringIntrospection,
    CP.LibInjectTailoredAliases,
    CP.LibInjectFixedAliases,
    CP.ForceWWW,
    CP.GenerateMissingDirs,
    CP.GenerateReferencedDirs,
    CP.GenerateShellMounts,
    CP.GenerateMissingFiles,
    CP.DeleteFiles,
    CP.LinksysHack,
    CP.KernelModules,
    CP.ShimStopBins,
    CP.ShimNoModules,
    CP.ShimBusybox,
    CP.ShimCrypto,
    # CP.ShimFwEnv,  # untested, never registered
    CP.NvramFirmAEFileSpecific,
    CP.NvramDefaults,
    CP.NvramConfigRecoveryWild,
    CP.NvramConfigRecovery,
    CP.NvramLibraryRecovery,
]


class ConfigBuilder:
    '''
    Given a filesystem and an output directory, create a configuration
    and initialize the output directory as necessary.
    '''
    PATCH_DIR: str = "static_patches"

    def __init__(self, fs_archive: str, output_dir: str | Path, jobs: int | None = None) -> None:
        # Create a 'base' directory for analysis results, copy fs into it
        base_dir = Path(output_dir, "base")
        base_dir.mkdir(exist_ok=True, parents=True)
        archive_fs = Path(base_dir, "fs.tar.gz")
        shutil.copy(fs_archive, archive_fs)

        # Extract the filesystem into base_dir/fs
        extracted_fs = base_dir / "extracted"
        extracted_fs.mkdir()
        subprocess.check_output(["tar", "-xf", archive_fs, "-C", str(extracted_fs)])

        # ensure every file is readable by the current user
        subprocess.check_output(
            ["find", str(extracted_fs), "-type", "f", "-exec", "chmod", "u+r", "{}", "+"])

        # ensure every directory is readable by the current user (requires exec)
        subprocess.check_output(
            ["find", str(extracted_fs), "-type", "d", "-exec", "chmod", "u+rx", "{}", "+"])

        try:
            # Run the init plugins: static analyses inform config generation
            # (e.g., what's the arch, what's the init prog) and subsequent
            # analyses after a run (i.e., guiding refinement); patch plugins
            # produce the config patches.
            ctx = InitContext(
                fs_archive=archive_fs,
                extracted_fs=extracted_fs,
                proj_dir=output_dir,
                static_dir=Path(output_dir, "static"),
                patch_dir=Path(output_dir, self.PATCH_DIR),
            )
            runner = InitPluginRunner(BUILTIN_INIT_PLUGINS, ctx, jobs=jobs)
            patches = runner.run()
            runner.render_patches(patches)

            # Generate our base config including our list of patches
            config = self.generate_initial_config(patches)

            # Dump it to disk
            dump_config(config, os.path.join(output_dir, "config.yaml"))

        finally:
            # Always clean up extracted filesystem
            shutil.rmtree(extracted_fs)

    def generate_initial_config(self, patches: dict) -> dict:
        '''
        Generate the initial configuration dictionary.

        :param patches: Dictionary of patches.
        :type patches: dict
        :return: Initial configuration dictionary.
        :rtype: dict
        '''

        patch_filenames = []

        for patch_name, (_, enabled) in patches.items():
            if enabled:
                patch_filenames.append(f"{self.PATCH_DIR}/{patch_name}.yaml")

        return {
            "core": {
                "root_shell": False,
                "show_output": False,
                "strace": False,
                "ltrace": False,
                "version": DEFAULT_VERSION,
                "auto_patching": True,
            },
            "patches": patch_filenames,
            "env": {},
            "blocked_signals": [],
            "netdevs": [],
            "lib_inject": {},
            "pseudofiles": {},
            "static_files": {},
            "plugins": {},
            "nvram": {},
        }


def initialize_and_build_config(
    fs: str,
    out: str | None = None,
    artifacts_dir: str | None = None
) -> str:
    """
    Given a filesystem as a .tar.gz analyze it to create a configuration file.
    Out is the path to the config to produce.
    Use artifacts_dir as scratch space while analyzing.

    :param fs: Path to filesystem archive (.tar.gz).
    :type fs: str
    :param out: Path to output config file.
    :type out: str or None
    :param artifacts_dir: Path to artifacts directory.
    :type artifacts_dir: str or None

    :return: Path to generated config file.
    :rtype: str

    :raises RuntimeError: If firmware file is not found.
    :raises ValueError: If input file is not a .tar.gz archive.
    """
    logger.info(f"Generating new configuration for {fs}...")

    if not os.path.isfile(fs):
        raise RuntimeError(f"Fatal: firmware file not found: {fs}")

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

    if out is None:
        out = os.path.join(*[output_dir, "base", "config.yaml"])

    # If we create files (e.g., base/*.yaml, output/*.yaml), we want them to be
    # readable/writable by everyone since non-container users will want to access them
    os.umask(0o000)

    # Generate our config and patches
    ConfigBuilder(fs, output_dir)

    outfile = os.path.join(output_dir, "config.yaml")

    # config is a path to output_dir/base/config.yaml
    if not shutil._samefile(outfile, out):
        shutil.copyfile(outfile, out)

    if tmpdir:
        tmpdir.cleanup()

    return out


def fakeroot_gen_config(
    fs: str,
    out: str,
    artifacts_dir: str,
    verbose: int
) -> str | None:
    """
    Run config generation under fakeroot.

    :param fs: Path to filesystem archive.
    :type fs: str
    :param out: Path to output config file.
    :type out: str
    :param artifacts_dir: Path to artifacts directory.
    :type artifacts_dir: str
    :param verbose: Verbosity level.
    :type verbose: int
    :return: Path to generated config file or None.
    :rtype: str or None
    """
    o = Path(out)
    cmd = [
        "fakeroot",
        "gen_config",
        "--fs", str(fs),
        "--out", str(o),
        "--artifacts", artifacts_dir,
    ]
    if verbose:
        cmd.extend(["--verbose"])
    p = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()
    if o.exists():
        return str(o)


@click.command()
@click.option("--fs", required=True, help="Path to a filesystem archive")
@click.option("--out", required=True, help="Path to a config to be created")
@click.option("--artifacts", default=None, help="Path to a directory for artifacts")
@click.option("-v", "--verbose", count=True)
def main(fs: str, out: str, artifacts: str | None, verbose: int) -> str | None:
    """
    CLI entrypoint for configuration generation.

    :param fs: Path to filesystem archive.
    :type fs: str
    :param out: Path to output config file.
    :type out: str
    :param artifacts: Path to artifacts directory.
    :type artifacts: str or None
    :param verbose: Verbosity level.
    :type verbose: int
    :return: Path to generated config file or None.
    :rtype: str or None
    """
    if verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # Return a path to a config if we generate one
        return initialize_and_build_config(fs, out, artifacts)
    except NotImplementedError as e:
        # Raised for unsupported architecture - don't need a full traceback, place in result file
        result_dir = os.path.dirname(out)
        if not os.path.isdir(result_dir):
            os.makedirs(result_dir)
        with open(os.path.join(result_dir, "result"), "w") as f:
            f.write(str(e)+"\n")
        logger.error(e)  # Here we use .error to print the message without the traceback
        return None
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
        logger.exception(e)  # Full traceback
        return None


if __name__ == "__main__":
    main()
