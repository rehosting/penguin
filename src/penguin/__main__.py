#!/usr/bin/env python3

import click
import logging
import os
import shutil
import subprocess
import glob
from os.path import dirname, join
from pathlib import Path
import sys
import hashlib
import tempfile
import art

from penguin import VERSION, getColoredLogger, yaml

from .common import get_inits_from_proj
from .gen_config import fakeroot_gen_config
from .manager import PandaRunner, calculate_score
from penguin.penguin_config import load_config

from .genetic import ga_search
from .graph_search import graph_search
from .patch_search import patch_search
from .patch_minimizer import minimize as patch_minimize
from .plugin_manager import find_local_plugins

logger = getColoredLogger("penguin")


def _validate_project(proj_dir, config_path):
    if not os.path.isdir(proj_dir):
        raise RuntimeError(f"Project directory not found: {proj_dir}")

    if not os.path.isfile(config_path):
        raise RuntimeError(f"Config file not found: {config_path}")

    try:
        config = load_config(proj_dir, config_path)
    except UnicodeDecodeError:
        raise RuntimeError(
            f"Config file {config_path} is not a valid unicode YAML file. Is it a firmware file instead of a configuration?"
        )

    # XXX: Should we put this in results somewhere?
    # from .penguin_config import load_config
    # dump_config(config, config_path+".realized")
    return config


def run_from_config(proj_dir, config_path, output_dir, timeout=None, verbose=False):
    config = _validate_project(proj_dir, config_path)

    # You already have a config, let's just run it. This is what happens
    # in each iterative run normally. Here we just do it directly.
    # Only needs a single thread, regardless of nthreads.

    # PandaRunner allows us to override the init from what's specified in the
    # config if necessary. If we don't have an init, go find a default, otherwise
    # use the one specified in the config.
    specified_init = None
    if config.get("env", {}).get("igloo_init", None) is None:
        options = get_inits_from_proj(proj_dir)
        if len(options):
            logger.info(
                f"Config does not specify init. Selecting first option: {options[0]}."
                + (
                    (" Other options are: " + ", ".join(options[1:]))
                    if len(options) > 1
                    else ""
                )
            )
            specified_init = options[0]
        else:
            raise RuntimeError(
                "Static analysis failed to identify an init script. Please specify one in your config under env.igloo_init"
            )

    try:
        PandaRunner().run(
            config_path,
            proj_dir,
            output_dir,
            init=specified_init,
            timeout=timeout,
            show_output=True,
            verbose=verbose,
            resolved_kernel=config["core"]["kernel"],
        )
    except RuntimeError:
        logger.error("No post-run analysis since there was no .run file")
        return

    # Single iteration: there is no best - don't report that
    # from manager import report_best_results
    # report_best_results(run_base, output_dir, os.path.dirname(output_dir))

    # But do calculate and report scores. Unlike multi-run mode, we'll write scores right into output dir instead of in parent
    try:
        best_scores = calculate_score(
            output_dir, have_console=not config["core"].get("show_output", False)
        )
    except RuntimeError as e:
        logger.error(f"Failed to calculate scores: {e}")
        return
    with open(os.path.join(output_dir, "scores.txt"), "w") as f:
        f.write("score_type,score\n")
        for k, v in best_scores.items():
            f.write(f"{k},{v:.02f}\n")
    with open(os.path.join(output_dir, "score.txt"), "w") as f:
        total_score = sum(best_scores.values())
        f.write(f"{total_score:.02f}\n")


def explore_from_config(
    explore_type, proj_dir, config_path, output_dir, niters, timeout,
    nworkers=1, verbose=False,
):
    config = _validate_project(proj_dir, config_path)

    if not explore_type:
        raise ValueError("Must specify explore_type when running multiple iterations")

    if explore_type == "explore":
        return graph_search(
            proj_dir, config, output_dir, timeout, max_iters=niters,
            nthreads=nworkers, verbose=verbose
        )

    if explore_type == "ga_explore":
        return ga_search(
            proj_dir, config_path, output_dir, timeout, max_iters=niters,
            nthreads=nworkers, verbose=verbose, nmuts=1
        )

    if explore_type == "patch_explore":
        return patch_search(
            proj_dir, config_path, output_dir, timeout, max_iters=niters,
            nworkers=nworkers, verbose=verbose
        )

    if explore_type == "minimize":
        return patch_minimize(
            proj_dir, config_path, output_dir, timeout, max_iters=niters,
            nworkers=nworkers, verbose=verbose
        )

    raise ValueError(f"Invalid explore_type: {explore_type}")


def get_file_hash(filename):
    sha256 = hashlib.sha256()
    try:
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        exit(1)
    return sha256.hexdigest()


def _setup_explore_dirs(config_path, output, force, cmd_name):
    """Shared logic for setting up explore/minimize output directories."""
    config_path = Path(config_path)
    if not config_path.exists():
        raise ValueError(f"Config file does not exist: {config_path}")

    # Allow config to be the project dir (which contains config.yaml)
    if os.path.isdir(config_path) and os.path.exists(
        os.path.join(config_path, "config.yaml")
    ):
        config_path = Path(config_path, "config.yaml")

    # Sanity check, should have a 'base' directory next to the config
    if not os.path.isdir(os.path.join(os.path.dirname(config_path), "base")):
        raise ValueError(
            f"Config directory does not contain a 'base' directory: {os.path.dirname(config_path)}."
        )

    if output is None:
        output = os.path.join(os.path.dirname(config_path), cmd_name)

    if force and os.path.isdir(output):
        shutil.rmtree(output, ignore_errors=True)

    if os.path.exists(output):
        raise ValueError(
            f"Output directory exists: {output}. Run with --force to delete."
        )

    os.makedirs(output)
    return config_path, output


def _startup_checks(verbose):
    """Performs hash checks and logging that should only run during execution, not help."""
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    logger.info("penguin %s", VERSION)

    penguin_hash_env = os.getenv("PENGUIN_HASH")
    if penguin_hash_env is None:
        logger.error("PENGUIN_HASH environment variable is not set.")

    penguin_file = "/usr/local/src/penguin_wrapper"
    if os.path.exists(penguin_file):
        penguin_hash = get_file_hash(penguin_file)

        if penguin_hash != penguin_hash_env:
            logger.warning(
                "Current penguin file does not match /usr/local/src/penguin_wrapper."
            )
            logger.warning(
                'Reinstall global penguin from container with "docker run rehosting/penguin penguin_install | sudo sh"'
            )
            logger.warning(
                'Reinstall local penguin from container with "docker run rehosting/penguin penguin_install.local | sh"'
            )


def _do_package(project_dir, output_path):
    project_dir_abs = os.path.abspath(project_dir)
    config_path = os.path.join(project_dir_abs, "config.yaml")

    # This fully validates and resolves auto-patching files into final config state
    config = _validate_project(project_dir_abs, config_path)

    if output_path is None:
        base_name = os.path.basename(project_dir_abs)
        output_path = f"{base_name}.tar.gz"

    # Route relative output paths into the mapped workspace
    if not os.path.isabs(output_path):
        if os.path.exists("/workspace"):
            output_path = os.path.join("/workspace", output_path)
        else:
            output_path = os.path.join(os.path.dirname(project_dir_abs), output_path)

    logger.info(f"Packaging project {project_dir_abs} into {output_path}...")

    # Discover local plugins using the shared logic
    plugins_dict = config.get("plugins", {})
    local_plugins = find_local_plugins(list(plugins_dict.keys()), project_dir_abs)

    for lp in local_plugins:
        logger.info(f"Ensuring local plugin is included: {os.path.relpath(lp, project_dir_abs)}")

    added_project_files = set()
    external_files_to_copy = set()
    project_files_list = []

    def _add_file(file_path):
        if not file_path:
            return

        file_path_str = str(file_path)

        # Treat absolute paths not starting with project_dir as container paths and skip
        if os.path.isabs(file_path_str):
            if file_path_str.startswith(project_dir_abs):
                abs_path = file_path_str
            else:
                logger.debug(f"Skipping absolute (container) path: {file_path_str}")
                return
        else:
            abs_path = os.path.abspath(os.path.join(project_dir_abs, file_path_str))

        if not os.path.exists(abs_path):
            logger.warning(f"File referenced in config not found: {abs_path}")
            return

        # If it's outside the project dir, scoop it into external_files staging
        if not abs_path.startswith(project_dir_abs):
            logger.info(f"Pulling in external local file into archive: {file_path_str}")
            external_files_to_copy.add(abs_path)
        else:
            rel_path = os.path.relpath(abs_path, project_dir_abs)
            if rel_path not in added_project_files:
                project_files_list.append(rel_path)
                added_project_files.add(rel_path)

    # Always include config.yaml
    _add_file("config.yaml")

    # Always include the static directory wholesale
    static_dir = os.path.join(project_dir_abs, "static")
    if os.path.exists(static_dir):
        _add_file("static")

    # Add explicit file references from the VALIDATED config
    core = config.get("core", {})
    _add_file(core.get("fs"))
    _add_file(core.get("kernel"))

    static_files = config.get("static_files", {})
    if isinstance(static_files, dict):
        for guest_path, file_info in static_files.items():
            if isinstance(file_info, dict) and file_info.get("type") == "host_file":
                _add_file(file_info.get("host_path"))

    # Include explicit patches from the UNPATCHED (raw) config
    with open(config_path, "r") as f:
        raw_config = yaml.safe_load(f) or {}

    patches_block = raw_config.get("patches")
    raw_patches = []

    # Gracefully handle both list and dict patch formats
    if isinstance(patches_block, dict):
        raw_patches = patches_block.get("root", [])
    elif isinstance(patches_block, list):
        raw_patches = patches_block

    if isinstance(raw_patches, list):
        for patch in raw_patches:
            _add_file(patch)

    # Include auto-patching files exactly as PENGUIN computes them
    raw_core = raw_config.get("core", {})
    if raw_core.get("auto_patching", True):
        patch_files = list(Path(project_dir_abs).glob("patch_*.yaml"))
        patches_dir = Path(project_dir_abs, "patches")

        if patches_dir.exists():
            patch_files += list(patches_dir.glob("*.yaml"))

        for pf in patch_files:
            _add_file(pf)

        # Catch loose .patch or .diff files too just in case
        for root_file in os.listdir(project_dir_abs):
            if root_file.endswith(".patch") or root_file.endswith(".diff"):
                _add_file(root_file)

    # Include discovered local plugins
    for lp in local_plugins:
        _add_file(lp)

    # Build the package using tar and pigz
    with tempfile.TemporaryDirectory() as temp_dir:
        # Write the project files list
        files_list_path = os.path.join(temp_dir, "files.txt")
        with open(files_list_path, "w") as f:
            for pf in project_files_list:
                f.write(f"{pf}\n")

        # Write the version file as structured YAML
        version_file_path = os.path.join(temp_dir, ".penguin_packaged_version")
        package_metadata = {
            "format_version": 1,
            "penguin_version": VERSION
        }
        with open(version_file_path, "w") as f:
            yaml.dump(package_metadata, f, default_flow_style=False, sort_keys=False)

        # Handle external files by copying them into the temp directory
        has_external = False
        if external_files_to_copy:
            has_external = True
            ext_dir = os.path.join(temp_dir, "external_files")
            os.makedirs(ext_dir)
            for ext_f in external_files_to_copy:
                # copy2 preserves file metadata
                shutil.copy2(ext_f, os.path.join(ext_dir, os.path.basename(ext_f)))

        # Construct the tar command using -I pigz
        tar_cmd = [
            "tar",
            "-I", "pigz",
            "-cf", output_path,
            "-C", project_dir_abs,
            "-T", files_list_path,
            "-C", temp_dir,
            ".penguin_packaged_version"
        ]

        # Append external_files directory if we copied anything into it
        if has_external:
            tar_cmd.append("external_files")

        logger.debug(f"Running packaging command: {' '.join(tar_cmd)}")
        try:
            subprocess.run(tar_cmd, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to package project using tar/pigz: {e}")
            exit(1)

    logger.info(f"Successfully packaged to {output_path}")

# --- Click Utilities ---


class RawHelpGroup(click.Group):
    """
    Overwrites the help formatting to preserve whitespace (for ASCII art).
    """

    def format_help_text(self, ctx, formatter):
        if self.help:
            formatter.write(self.help)
            formatter.write('\n')


def verbose_option(f):
    """
    Common option for commands that support verbose logging.
    Updates the context VERBOSE object so it can be merged with group-level verbose flag.
    """
    def callback(ctx, param, value):
        if value:
            # Update the context object
            ctx.ensure_object(dict)
            ctx.obj['VERBOSE'] = True
        return value
    return click.option("-v", "--verbose", is_flag=True, help="Set log level to debug", expose_value=False, callback=callback)(f)

# --- Click Commands ---


LOGO = f"""
    {art.text2art("PENGUIN", font='tarty1-large')}
\t\t\t\tversion {VERSION}

Configuration based firmware rehosting. Penguin can generate a project with a configuration for a firmware and
run a rehosting as specified in a config.

Before you start with PENGUIN, you'll need an archive of a firmware root filesystem. This is a tarball of the root
filesystem with permissions and ownership preserved. You can generate this with the 'fw2tar' utility or by hand.

    fw2tar your_fw.bin

Once you have a root filesystem, you can generate an initial rehosting configuration based on a static analysis
of the filesystem. This initial configuration is stored within a "project directory" which will hold the config,
static analysis results, and the output from every dynamic analysis you run.

To generate your initial configuration you'll use the "init" subcommand to penguin. This will generate a configuration
for the provided firmware root filesystem. By default the configuration will be stored in
./projects/<firmware_name>/config.yaml. You can specify a different output directory with the --output flag.

    penguin init your_fw.rootfs.tar.gz --output projects/your_fw

Once you have created an initial configuration you can view and edit it if necessary.

To run a configuration, use the "run" subcommand. This will run the rehosting as specified in the configuration file and
report dynamic analysis results in a "results directory." By default this directory will be within the project directory
at <project directory>/results/<auto-incrementing number>.  You can also specify an output directory with the --output
flag and replace an existing directory with --force.

    penguin run projects/your_fw/config.yaml --output projects/your_fw/results/0

Some dynamic analysis output will be logged into the results directory *during* the emulation, for example the file `console.log`
within the directory will be updated as console output is produced from the guest. Other output will be generated after the emulation
completes such as information on pseudofiles accessed, network binds, and environment variables accessed.


To learn more about PENGUIN view documentation by running the "docs" subcommand. This will list available documentation files which
you can then select to view with the --filename flag. The `README.md` file contains an overview of the project while `schema_doc.md`
contains details on the configuration file format and options.

    penguin docs --filename schema_doc.md
"""


@click.group(cls=RawHelpGroup, help=LOGO)
@click.option("-v", "--verbose", is_flag=True, help="Set log level to debug")
@click.option("--wrapper-help", is_flag=True, help="Show help for host penguin wrapper")
@click.version_option(version=VERSION)
@click.pass_context
def cli(ctx, verbose, wrapper_help):
    # Store verbose in context object for subcommands
    ctx.ensure_object(dict)
    # If already set by callback (rare, usually callbacks run after), or defaults
    if verbose:
        ctx.obj['VERBOSE'] = True
    elif 'VERBOSE' not in ctx.obj:
        ctx.obj['VERBOSE'] = False

    if wrapper_help:
        click.echo(ctx.get_help())
        ctx.exit()


@cli.command()
@click.argument("rootfs", type=str)
@click.option("--output", type=str, default=None, help="Optional argument specifying the path where the project will be created. Default is projects/<basename of firmware file>.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete project directory if it exists")
@click.option("--output_base", type=str, default="projects", help="Default project directory base. Default is 'projects'")
@verbose_option
@click.pass_context
def init(ctx, rootfs, output, force, output_base):
    """
    Create project from firmware root filesystem archive.

    ROOTFS is the rootfs path. (e.g. path/to/fw_rootfs.tar.gz)
    """
    _startup_checks(ctx.obj['VERBOSE'])

    firmware = Path(rootfs)

    if not firmware.exists():
        raise ValueError(f"Firmware file not found: {firmware}")

    if rootfs.endswith(".yaml"):
        raise ValueError(
            "FATAL: It looks like you provided a config file (it ends with .yaml)."
            "Please provide a firmware file"
        )

    if "/host_" in rootfs or (output and output.startswith("/host_")):
        logger.info(
            "Note messages referencing /host paths reflect automatically-mapped shared directories based on your command line arguments"
        )

    if output is None:
        if rootfs.endswith(".rootfs.tar.gz"):
            basename_stem = os.path.basename(rootfs)[0:-14]
        elif rootfs.endswith(".tar.gz"):
            basename_stem = os.path.basename(rootfs)[0:-7]
        else:
            basename_stem = os.path.splitext(os.path.basename(rootfs))[0]

        if not os.path.exists(output_base):
            print("Creating output_base:", output_base)
            os.makedirs(output_base, exist_ok=True)

        output = output_base + "/" + basename_stem
        output_type = "generated"
    else:
        output_type = "specified"
    logger.info(f"Creating project at {output_type} path: {output}")

    if os.path.isdir(output) and (
        os.path.exists(os.path.join(output, "config.yaml"))
        or os.path.exists(os.path.join(output, "base"))
    ):
        if force:
            logger.info(f"Deleting existing project directory: {output}")
            shutil.rmtree(output, ignore_errors=True)
        else:
            raise ValueError(
                f"Project directory already exists: {output}. Use --force to delete."
            )

    os.makedirs(os.path.dirname(output), exist_ok=True)

    out_config_path = Path(output, "config.yaml")
    config = fakeroot_gen_config(
        rootfs, out_config_path, output, ctx.obj['VERBOSE']
    )
    if config:
        logger.info(f"Generated config at {config}")
    else:
        logger.error(
            f"Failed to generate config for {rootfs}. See {output}/result for details."
        )
        exit(1)


@cli.command()
@click.argument("project_dir", type=str)
@click.option("--config", type=str, help="Path to a config file. Defaults to <project_dir>/config.yaml.")
@click.option("--output", type=str, default=None, help="The output directory path. Defaults to results/X in project directory where X auto-increments.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete output directory if it exists.")
@click.option("--timeout", type=int, default=None, help="Number of seconds that run/iteration should last. Default is None (must manually kill)")
@click.option("-a", "--auto", is_flag=True, help="Run in auto mode (don't start telnet shell).")
@verbose_option
@click.pass_context
def run(ctx, project_dir, config, output, force, timeout, auto):
    """
    Run from a config.

    PROJECT_DIR is the path to project directory. For backwards compatability, a path to a config file within a project directory is also accepted.
    """
    _startup_checks(ctx.obj['VERBOSE'])

    if not os.path.isabs(project_dir):
        current_dir = os.getcwd()
        project_dir = os.path.join(current_dir, project_dir)

    if os.path.isfile(project_dir) or project_dir.endswith("/config.yaml"):
        config = project_dir
        project_dir = os.path.dirname(config)

    if force and output and os.path.isdir(output):
        shutil.rmtree(output, ignore_errors=True)

    if not config and os.path.isdir(project_dir) and os.path.exists(
        os.path.join(project_dir, "config.yaml")
    ):
        config = os.path.join(project_dir, "config.yaml")

    if config is None:
        raise ValueError(f"Could not find config and none was provided. Auto-checked {project_dir} for config.yaml")

    config_path = Path(config)
    if not config_path.exists():
        raise ValueError(f"Config file does not exist: {config}")

    if not os.path.isdir(os.path.join(project_dir, "base")):
        raise ValueError(
            f"Project directory does not contain a 'base' directory: {project_dir}."
        )

    if output is None:
        results_base = os.path.join(project_dir, "results")

        if not os.path.exists(results_base):
            os.makedirs(results_base)
            idx = 0
        else:
            def getint(d):
                try:
                    return int(d)
                except ValueError:
                    return -1

            results = [
                getint(d)
                for d in os.listdir(results_base)
                if os.path.isdir(os.path.join(results_base, d))
            ]
            if len(results) == 0:
                idx = 0
            else:
                idx = max(results) + 1

        latest_dir = os.path.join(results_base, "latest")
        if os.path.islink(latest_dir):
            os.unlink(latest_dir)
        os.symlink(f"./{idx}", latest_dir)

        output = os.path.join(results_base, str(idx))

    friendly_config = config
    if friendly_config.startswith(project_dir):
        friendly_config = friendly_config[len(project_dir):]

    logger.info(f"Running project {project_dir} with config {friendly_config}")
    logger.info(f"Saving results to {output}")

    if "/host_" in config or "/host_" in output:
        logger.info(
            "Note messages referencing /host paths reflect automatically-mapped shared directories based on your command line arguments"
        )

    run_from_config(project_dir, config, output, timeout=timeout, verbose=ctx.obj['VERBOSE'])


@cli.command()
@verbose_option
@click.pass_context
def shell(ctx):
    """Get a shell inside the penguin container"""
    _startup_checks(ctx.obj['VERBOSE'])
    logger.error("The 'shell' command is not available in this context. Please use the 'penguin' wrapper script to start a container shell.")
    sys.exit(1)


@cli.command()
@click.option("--filename", type=str, default=None, help="Documentation file to render. If unset, filenames are printed.")
@verbose_option
@click.pass_context
def docs(ctx, filename):
    """Show documentation"""
    _startup_checks(ctx.obj['VERBOSE'])
    docs_path = "/docs"

    if filename:
        fn = filename
    else:
        doc_files = glob.glob("**/*.md", root_dir=docs_path, recursive=True)
        gum_args = ["gum", "choose"] + doc_files
        try:
            fn = subprocess.check_output(gum_args, text=True).strip()
        except subprocess.CalledProcessError:
            return

    if not fn.endswith(".md"):
        fn += ".md"

    full_path = join(docs_path, fn)
    if ".." in fn:
        raise ValueError("Invalid filename")

    if not os.path.isfile(full_path):
        logger.info(f"Documentation file not found: {fn}")
    else:
        with open(full_path, "r") as f:
            lines = len(f.readlines())

        try:
            rows, _ = os.get_terminal_size()
        except OSError:
            rows = None

        glow_args = ["glow", full_path]
        if rows and lines > rows:
            subprocess.run(glow_args + ["--pager"])
        else:
            subprocess.run(glow_args)


@cli.command()
@click.argument("config", type=str)
@click.option("--niters", type=int, default=100, help="Number of iterations to run. Default is 100.")
@click.option("--nworkers", type=int, default=4, help="Number of workers to run in parallel. Default is 4")
@click.option("--timeout", type=int, default=300, help="Number of seconds that automated runs will execute for. Default is 300.")
@click.option("--output", type=str, default=None, help="The output directory path. Defaults to results/explore.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete output directory if it exists.")
@verbose_option
@click.pass_context
def explore(ctx, config, niters, nworkers, timeout, output, force):
    """
    Search for alternative configurations to improve system health by walking a configuration graph.

    CONFIG is the path to a config file within a project directory or a project directory that contains a config.yaml.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    config_path, output_dir = _setup_explore_dirs(config, output, force, "explore")
    logger.info(f"Exploring from {config_path} and saving results to {output_dir}")

    if "/host_" in str(config_path) or "/host_" in output_dir:
        logger.info("Note messages referencing /host paths reflect automatically-mapped shared directories")

    explore_from_config(
        "explore",
        dirname(config_path),
        str(config_path),
        output_dir,
        niters,
        timeout,
        nworkers=nworkers,
        verbose=ctx.obj['VERBOSE']
    )


@cli.command()
@click.argument("config", type=str)
@click.option("--niters", type=int, default=100, help="Number of iterations to run. Default is 100.")
@click.option("--nworkers", type=int, default=4, help="Number of workers to run in parallel. Default is 4")
@click.option("--timeout", type=int, default=300, help="Number of seconds that automated runs will execute for. Default is 300.")
@click.option("--output", type=str, default=None, help="The output directory path.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete output directory if it exists.")
@click.option("--nmuts", type=int, default=1, help="Number of mutations to try per chromosome per generation. Default is 1.")
@verbose_option
@click.pass_context
def ga_explore(ctx, config, niters, nworkers, timeout, output, force, nmuts):
    """
    Search for alternative configurations to improve system health by using a genetic algorithm.

    CONFIG is the path to a config file within a project directory or a project directory that contains a config.yaml.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    config_path, output_dir = _setup_explore_dirs(config, output, force, "ga_explore")
    logger.info(f"Exploring from {config_path} and saving results to {output_dir}")

    if "/host_" in str(config_path) or "/host_" in output_dir:
        logger.info("Note messages referencing /host paths reflect automatically-mapped shared directories")

    explore_from_config(
        "ga_explore",
        dirname(config_path),
        str(config_path),
        output_dir,
        niters,
        timeout,
        nworkers=nworkers,
        verbose=ctx.obj['VERBOSE']
    )


@cli.command()
@click.argument("config", type=str)
@click.option("--niters", type=int, default=100, help="Number of iterations to run. Default is 100.")
@click.option("--nworkers", type=int, default=4, help="Number of workers to run in parallel. Default is 4")
@click.option("--timeout", type=int, default=300, help="Number of seconds that automated runs will execute for. Default is 300.")
@click.option("--output", type=str, default=None, help="The output directory path.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete output directory if it exists.")
@verbose_option
@click.pass_context
def patch_explore(ctx, config, niters, nworkers, timeout, output, force):
    """
    Search for alternative configurations to improve system health by using a patch-based search.

    CONFIG is the path to a config file within a project directory or a project directory that contains a config.yaml.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    config_path, output_dir = _setup_explore_dirs(config, output, force, "patch_explore")
    logger.info(f"Exploring from {config_path} and saving results to {output_dir}")

    if "/host_" in str(config_path) or "/host_" in output_dir:
        logger.info("Note messages referencing /host paths reflect automatically-mapped shared directories")

    explore_from_config(
        "patch_explore",
        dirname(config_path),
        str(config_path),
        output_dir,
        niters,
        timeout,
        nworkers=nworkers,
        verbose=ctx.obj['VERBOSE']
    )


@cli.command()
@click.argument("config", type=str)
@click.option("--niters", type=int, default=100, help="Number of iterations to run. Default is 100.")
@click.option("--nworkers", type=int, default=4, help="Number of workers to run in parallel. Default is 4")
@click.option("--timeout", type=int, default=300, help="Number of seconds that automated runs will execute for. Default is 300.")
@click.option("--output", type=str, default=None, help="The output directory path.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete output directory if it exists.")
@verbose_option
@click.pass_context
def minimize(ctx, config, niters, nworkers, timeout, output, force):
    """
    Search for a minimal set of patches to rehost a system.

    CONFIG is the path to a config file within a project directory or a project directory that contains a config.yaml.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    config_path, output_dir = _setup_explore_dirs(config, output, force, "minimize")
    logger.info(f"Exploring from {config_path} and saving results to {output_dir}")

    if "/host_" in str(config_path) or "/host_" in output_dir:
        logger.info("Note messages referencing /host paths reflect automatically-mapped shared directories")

    explore_from_config(
        "minimize",
        dirname(config_path),
        str(config_path),
        output_dir,
        niters,
        timeout,
        nworkers=nworkers,
        verbose=ctx.obj['VERBOSE']
    )


@cli.command(context_settings=dict(
    ignore_unknown_options=True,
    allow_extra_args=True,
))
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def guest_cmd(ctx, args):
    """
    Execute a command inside a guest and capture stdout/stderr.

    ARGS are passed as the command to the guest.
    """
    # NOTE: guest_cmd does NOT accept -v for the host script.
    # We pass ctx.obj['VERBOSE'] (set by global flag) to startup checks.
    _startup_checks(ctx.obj['VERBOSE'])

    guest_cmd_args = ["python3", "/igloo_static/guesthopper/guest_cmd.py"] + list(args)
    result = subprocess.run(guest_cmd_args, capture_output=True, text=True, check=False)
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    sys.exit(result.returncode)


@cli.command()
@click.argument("project_dir", type=click.Path(exists=True))
@click.option("-o", "--out", type=str, default=None, help="Output tar.gz file path. Defaults to <project_dir_name>.tar.gz")
@verbose_option
@click.pass_context
def package(ctx, project_dir, out):
    """
    Package a penguin project into a distributable archive.

    Creates a tar.gz pulling in configs, base, and static patches while omitting results and qcows.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    _do_package(project_dir, out)


@cli.command(hidden=True)
@click.argument("project_dir", type=click.Path(exists=True))
@click.option("-o", "--out", type=str, default=None)
@verbose_option
@click.pass_context
def export(ctx, project_dir, out):
    """Alias for package"""
    ctx.invoke(package, project_dir=project_dir, out=out)


if __name__ == "__main__":
    cli()
