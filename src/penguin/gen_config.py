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

from . import config_patchers as CP
from . import static_analyses as STATIC

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
    PATCH_DIR = "static_patches"

    def __init__(self, fs_archive, output_dir):
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
            # First run static analyses and produce info about the filesystem
            # This informs how we generate configs (e.g., what's the arch, what's the init prog)
            # and also subsequent analyses after a run (i.e., guiding refinement)
            static_results = self.run_static_analyses(output_dir, extracted_fs)

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

    def run_static_analyses(self, output_dir, extracted_dir, static_dir_name="static"):
        '''
        Run static analysis on the extracted filesystem and write results to output_dir/static
        '''
        results_dir = Path(output_dir, static_dir_name)
        results_dir.mkdir(exist_ok=True, parents=True)

        # Collect a list of all files in advance so we don't regenerate
        # archive_files = TarHelper.get_all_members(fs_archive)

        # Ordered list of static analyses to run (from static_analyses.py)
        # Each has an init method that can return results
        # If any raises an exception, it will be fatal to config generation and shown
        # to a user
        static_analyses = [
            STATIC.ArchId,
            STATIC.InitFinder,
            STATIC.EnvFinder,
            STATIC.PseudofileFinder,
            STATIC.InterfaceFinder,
            STATIC.ClusterCollector,
            STATIC.LibrarySymbols,
            STATIC.KernelVersionFinder,
        ]

        USE_JSON_XZ = [
            STATIC.LibrarySymbols
        ]

        results = {}
        for analysis in static_analyses:
            # Call each analysis and store results
            this_result = analysis().run(extracted_dir, results)
            results[analysis.__name__] = this_result

            # If we have results, store on disk. Always store in results dict, even if empty
            if this_result:
                if analysis in USE_JSON_XZ:
                    with lzma.open(results_dir / f"{analysis.__name__}.json.xz", "wt", encoding="utf-8") as f:
                        json.dump(this_result, f)
                else:
                    with open(results_dir / f"{analysis.__name__}.yaml", "w") as f:
                        yaml.dump(this_result, f)

        return results

    def render_patches(self, output_dir, patches):
        '''
        Given a dictionary of patches, render them into output_dir / patches
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

    def generate_initial_config(self, patches):

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

    def create_patches(self, fs_archive, static_results, extract_dir):
        """
        Generate a patch that ensures we have all directories in a fixed list.
        """

        # Collect a list of all files in advance so we don't regenerate
        archive_files = CP.TarHelper.get_all_members(fs_archive)

        # Instantiate and apply patch generators
        # Later patches will override earlier ones
        patch_generators = [
            CP.BasePatch(static_results['ArchId'], static_results['InitFinder'], static_results['KernelVersionFinder']),
            CP.RootShell(),
            CP.DynamicExploration(),
            CP.SingleShotFICD(),
            CP.ManualInteract(),
            CP.NetdevsDefault(),
            CP.NetdevsTailored(static_results['InterfaceFinder']),
            CP.PseudofilesExpert(),
            CP.PseudofilesTailored(static_results['PseudofileFinder']),
            CP.LibInjectSymlinks(extract_dir),
            CP.LibInjectStringIntrospection(static_results['LibrarySymbols']),
            CP.LibInjectTailoredAliases(static_results['LibrarySymbols']),
            CP.LibInjectFixedAliases(),
            CP.ForceWWW(extract_dir),
            CP.GenerateMissingDirs(fs_archive, archive_files),
            CP.GenerateReferencedDirs(extract_dir),
            CP.GenerateShellMounts(extract_dir, archive_files),
            CP.GenerateMissingFiles(extract_dir),
            CP.DeleteFiles(extract_dir),
            CP.LinksysHack(extract_dir),
            CP.KernelModules(extract_dir, static_results['KernelVersionFinder']),
            CP.ShimStopBins(archive_files),
            CP.ShimNoModules(archive_files),
            CP.ShimBusybox(archive_files),
            CP.ShimCrypto(archive_files),
            # ShimFwEnv(archive_files),
            CP.NvramFirmAEFileSpecific(extract_dir),
            CP.NvramDefaults(),
            CP.NvramConfigRecoveryWild(extract_dir),
            CP.NvramConfigRecovery(extract_dir),
            CP.NvramLibraryRecovery(static_results['LibrarySymbols']),
        ]

        # collect patches in patches[patchfile_name] -> {section -> {key -> value}}
        patches = defaultdict(lambda: defaultdict(lambda: defaultdict(dict)))

        for generator in patch_generators:
            if result := generator.generate(patches):
                if len(result):
                    patches[generator.patch_name] = (result, generator.enabled)
                    if not generator.enabled:
                        logger.info(f"{generator.patch_name} patch generated but disabled")

        return patches


###################################

def initialize_and_build_config(fs, out=None, artifacts_dir=None):
    """
    Given a filesystem as a .tar.gz analyze it to create a configuration file.
    Out is the path to the config to produce.
    Use artifacts_dir as scratch space while analyzing.

    Returns the path to the config file.
    Raises an exception with a user-friendly message if it fails.
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


def fakeroot_gen_config(fs, out, artifacts_dir, verbose):
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
def main(fs, out, artifacts, verbose):
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
