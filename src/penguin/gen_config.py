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
import yaml
import json
import lzma

from collections import defaultdict
from pathlib import Path
from penguin import getColoredLogger

from .static_plugin import StaticAnalysisPlugin, ConfigPatcherPlugin
from .static_plugin_manager import StaticPluginManager

from .defaults import (
    default_version as DEFAULT_VERSION,
)
from penguin.penguin_config import dump_config

logger = getColoredLogger("penguin.gen_config")


class ConfigBuilder:
    '''
    Given a filesystem and an output directory, create a configuration
    and initialize the output directory as necessary.
    '''
    PATCH_DIR: str = "static_patches"

    def __init__(self, fs_archive: str, output_dir: str | Path) -> None:
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
            # Initialize StaticPluginManager
            # We look for plugins in pyplugins/static_analysis and pyplugins/config_patchers
            plugin_dirs = [
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "pyplugins", "static_analysis"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "pyplugins", "config_patchers"),
            ]
            self.plugin_manager = StaticPluginManager(plugin_dirs)

            # First run static analyses and produce info about the filesystem
            # This informs how we generate configs (e.g., what's the arch, what's the init prog)
            # and also subsequent analyses after a run (i.e., guiding refinement)
            static_results = self.run_static_analyses(output_dir, archive_fs, extracted_fs)

            # TODO: Is there a better way to manage order of patches?
            patches = self.create_patches(archive_fs, static_results, extracted_fs)
            self.render_patches(output_dir, patches)

            # Generate our base config including our list of patches
            config = self.generate_initial_config(patches)

            # Dump it to disk
            dump_config(config, os.path.join(output_dir, "config.yaml"))

        finally:
            # Always clean up extracted filesystem
            shutil.rmtree(extracted_fs)

    def run_static_analyses(
        self,
        output_dir: str | Path,
        fs_archive: str | Path,
        extracted_dir: str | Path,
        static_dir_name: str = "static"
    ) -> dict:
        '''
        Run static analysis on the extracted filesystem and write results to output_dir/static.

        :param output_dir: Output directory for results.
        :type output_dir: str or Path
        :param fs_archive: Path to filesystem archive.
        :type fs_archive: str or Path
        :param extracted_dir: Directory containing extracted filesystem.
        :type extracted_dir: str or Path
        :param static_dir_name: Name of static results subdirectory.
        :type static_dir_name: str
        :return: Dictionary of static analysis results.
        :rtype: dict
        '''
        results_dir = Path(output_dir, static_dir_name)
        results_dir.mkdir(exist_ok=True, parents=True)

        USE_JSON_XZ = [
            "LibrarySymbols"
        ]

        results = {}
        ordered_plugins = self.plugin_manager.get_ordered_plugins()

        for plugin_cls in ordered_plugins:
            if not issubclass(plugin_cls, StaticAnalysisPlugin):
                continue

            logger.info(f"Running static analysis: {plugin_cls.__name__}")
            try:
                plugin_instance = plugin_cls(str(fs_archive), str(extracted_dir), results)
                this_result = plugin_instance.run()
                results[plugin_cls.__name__] = this_result

                # If we have results, store on disk. Always store in results dict, even if empty
                if this_result:
                    if plugin_cls.__name__ in USE_JSON_XZ:
                        with lzma.open(results_dir / f"{plugin_cls.__name__}.json.xz", "wt", encoding="utf-8") as f:
                            json.dump(this_result, f)
                    else:
                        with open(results_dir / f"{plugin_cls.__name__}.yaml", "w") as f:
                            yaml.dump(this_result, f)
            except Exception as e:
                logger.error(f"Error running static analysis {plugin_cls.__name__}: {e}")
                raise e

        return results

    def render_patches(self, output_dir: str | Path, patches: dict) -> None:
        '''
        Given a dictionary of patches, render them into output_dir / patches.

        :param output_dir: Output directory.
        :type output_dir: str or Path
        :param patches: Dictionary of patches.
        :type patches: dict
        '''
        patch_dir = Path(output_dir, self.PATCH_DIR)

        # Now render patches
        # Ensure patch_dir exists
        patch_dir.mkdir(exist_ok=True, parents=True)

        def _convert_to_dict(data):
            # Recursively convert defaultdict to dict so we can yaml-ize it
            if isinstance(data, defaultdict):
                return {k: _convert_to_dict(v) for k, v in data.items()}
            elif isinstance(data, dict):
                return {k: _convert_to_dict(v) for k, v in data.items()}
            return data

        for name, (default_dict_data, _) in patches.items():
            data = _convert_to_dict(default_dict_data)

            # If there's no data, skip the patch entirely
            if isinstance(data, dict):
                if not data or all(not v for v in data.values()):
                    continue
            elif isinstance(data, list):
                if not len(data):
                    continue

            with open(patch_dir / f"{name}.yaml", "w") as f:
                yaml.dump(data, f, default_flow_style=False)

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

    def create_patches(
        self,
        fs_archive: str | Path,
        static_results: dict,
        extract_dir: str | Path
    ) -> dict:
        """
        Generate a patch that ensures we have all directories in a fixed list.

        :param fs_archive: Path to filesystem archive.
        :type fs_archive: str or Path
        :param static_results: Static analysis results.
        :type static_results: dict
        :param extract_dir: Directory containing extracted filesystem.
        :type extract_dir: str or Path
        :return: Dictionary of generated patches.
        :rtype: dict
        """

        # collect patches in patches[patchfile_name] -> {section -> {key -> value}}
        patches = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))

        ordered_plugins = self.plugin_manager.get_ordered_plugins()

        for plugin_cls in ordered_plugins:
            if not issubclass(plugin_cls, ConfigPatcherPlugin):
                continue

            logger.info(f"Running config patcher: {plugin_cls.__name__}")
            try:
                generator = plugin_cls(str(fs_archive), str(extract_dir), static_results)
                if result := generator.generate(patches):
                    if len(result):
                        patches[generator.patch_name] = (result, generator.enabled)
                        if not generator.enabled:
                            logger.info(f"{generator.patch_name} patch generated but disabled")
            except Exception as e:
                logger.error(f"Error running config patcher {plugin_cls.__name__}: {e}")
                raise e

        return patches


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
    builder = ConfigBuilder(fs, output_dir)

    # Save the hash of the static plugins to detect changes later
    state_hash = builder.plugin_manager.get_state_hash()
    # Save .plugin_cache in the same directory as the output config
    cache_dir = os.path.dirname(out) if out else str(output_dir)
    with open(os.path.join(cache_dir, ".plugin_cache"), "w") as f:
        f.write(state_hash)

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
