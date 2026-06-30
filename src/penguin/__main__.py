#!/usr/bin/env python3

import click
import logging
import os
import shutil
import subprocess
import glob
from os.path import join
from pathlib import Path
import sys
import hashlib
import tempfile
import art

from penguin import VERSION, getColoredLogger, yaml

from .common import get_inits_from_proj
from .gen_config import fakeroot_gen_config, fakeroot_refresh
from .manager import PandaRunner, calculate_score
from penguin.penguin_config import load_config

from .plugin_manager import find_local_plugins
from .utils import hash_image_inputs
from .compose import run_compose, scaffold_compose
from .utils_cli import utils as _utils_group

logger = getColoredLogger("penguin")


def _resolve_project_and_config(project_dir, config):
    """
    Normalize a (project_dir, config) pair the way `run` and `validate` expect.

    Accepts a project directory or, for backwards compatibility, a path to a
    config file inside one. Returns (project_dir, config) with both resolved to
    existing absolute paths, raising ValueError if no config can be found.
    """
    if not os.path.isabs(project_dir):
        project_dir = os.path.join(os.getcwd(), project_dir)

    if os.path.isfile(project_dir) or project_dir.endswith("/config.yaml"):
        config = project_dir
        project_dir = os.path.dirname(config)

    if not config and os.path.isdir(project_dir) and os.path.exists(
        os.path.join(project_dir, "config.yaml")
    ):
        config = os.path.join(project_dir, "config.yaml")

    if config is None:
        raise ValueError(
            f"Could not find config and none was provided. Auto-checked {project_dir} for config.yaml"
        )

    if not Path(config).exists():
        raise ValueError(f"Config file does not exist: {config}")

    return project_dir, config


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


def run_from_config(proj_dir, config_path, output_dir, timeout=None, verbose=False,
                    from_snapshot=None, ignore_saved_config=False):
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

    extra_env = {}
    if from_snapshot:
        extra_env["PENGUIN_SNAPSHOT_BOOT_FROM"] = from_snapshot
    if ignore_saved_config:
        # Opt out of defaulting to the snapshot's own saved config; drive the
        # restored guest with the provided config instead (fingerprint-gated).
        extra_env["PENGUIN_SNAPSHOT_IGNORE_SAVED_CONFIG"] = "1"
    extra_env = extra_env or None

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
            extra_env=extra_env,
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


def _stage_snapshots(project_dir_abs, config, tags, temp_dir):
    """Stage portable copies of snapshot bundles for packaging.

    Snapshots live in qcows/ (omitted from a normal pack). For each tag we copy
    the overlay + base image + sidecars into temp_dir/qcows and rebase the
    overlay COPY to a *relative* backing file (qemu-img rebase -u), so the
    bundle is self-contained and portable — the live project is never touched.
    Returns True if anything was staged.
    """
    qcow_dir = os.path.join(project_dir_abs, "qcows")
    base_name = f"image_{hash_image_inputs(project_dir_abs, config)}.qcow2"
    base_path = os.path.join(qcow_dir, base_name)
    staged = False
    stage_dir = os.path.join(temp_dir, "qcows")

    for tag in tags:
        overlay = os.path.join(qcow_dir, f"snapshot_{tag}.qcow2")
        if not os.path.isfile(overlay):
            logger.warning(f"No snapshot overlay for tag '{tag}' ({overlay}); skipping")
            continue
        os.makedirs(stage_dir, exist_ok=True)
        # Base image must travel so the overlay's disk resolves.
        if os.path.isfile(base_path) and not os.path.isfile(os.path.join(stage_dir, base_name)):
            shutil.copy2(base_path, os.path.join(stage_dir, base_name))
        staged_overlay = os.path.join(stage_dir, f"snapshot_{tag}.qcow2")
        shutil.copy2(overlay, staged_overlay)
        # Point the COPY at a relative backing so it resolves wherever qcows/
        # lands on unpack. -u is unsafe (metadata-only); no data is rewritten.
        try:
            subprocess.run(
                ["qemu-img", "rebase", "-u", "-b", base_name, "-F", "qcow2", staged_overlay],
                check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to rebase staged snapshot '{tag}': {e}")
            exit(1)
        for side in (f"snapshot_{tag}.meta.json", f"snapshot_{tag}.host.json",
                     f"snapshot_{tag}.config.yaml"):
            src = os.path.join(qcow_dir, side)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(stage_dir, side))
        logger.info(f"Staged snapshot '{tag}' (overlay + base + sidecars) for packaging")
        staged = True

    return staged


def _do_package(project_dir, output_path, with_snapshots=()):
    project_dir_abs = os.path.abspath(project_dir)
    config_path = os.path.join(project_dir_abs, "config.yaml")

    # This fully validates and resolves auto-patching files into final config state
    config = _validate_project(project_dir_abs, config_path)

    # Always compute base_name from the project directory
    base_name = os.path.basename(project_dir_abs)

    if output_path is None:
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

    # Bundle drop-in directories wholesale so .c/.h sources and disabled
    # plugins travel with the project even when nothing references them
    # directly via static_files.
    for dropin in ("init.d", "source.d", "plugins.d"):
        if os.path.exists(os.path.join(project_dir_abs, dropin)):
            _add_file(dropin)

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
            "penguin_version": VERSION,
            "base_name": base_name
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

        # Optionally stage portable snapshot bundles (overlay + base + sidecars)
        # into temp_dir/qcows so they travel with the project for 'capture & share'.
        has_snapshots = False
        if with_snapshots:
            has_snapshots = _stage_snapshots(project_dir_abs, config,
                                             with_snapshots, temp_dir)

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

        # Append staged snapshot bundle (qcows/) if present
        if has_snapshots:
            tar_cmd.append("qcows")

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


class ComposeGroup(click.Group):
    """Click group that preserves `penguin compose <target...>` shortcuts."""

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            if args:
                cmd = self.get_command(ctx, "_shortcut")
                return "_shortcut", cmd, args
            raise

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
@click.option("--jobs", type=int, default=None, help="Init plugin thread pool size (default: cpu count)")
@click.option("--init-plugin-path", multiple=True, help="Extra directory to search for init plugins (repeatable)")
@click.option("--enable", multiple=True, help="Init plugin name to force-enable (repeatable)")
@click.option("--disable", multiple=True, help="Init plugin name to skip (repeatable)")
@verbose_option
@click.pass_context
def init(ctx, rootfs, output, force, output_base, jobs, init_plugin_path, enable, disable):
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
        rootfs, out_config_path, output, ctx.obj['VERBOSE'],
        jobs=jobs,
        init_plugin_dirs=init_plugin_path,
        enable=enable,
        disable=disable,
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
@click.option("--only", multiple=True, help="Only re-run these init plugins (repeatable)")
@click.option("--jobs", type=int, default=None, help="Init plugin thread pool size (default: cpu count)")
@click.option("--init-plugin-path", multiple=True, help="Extra directory to search for init plugins (repeatable)")
@click.option("--enable", multiple=True, help="Init plugin name to force-enable (repeatable)")
@click.option("--disable", multiple=True, help="Init plugin name to skip (repeatable)")
@click.option("--update-config/--no-update-config", default=True,
              help="Reconcile the config's patches/init_plugins sections (default: on)")
@verbose_option
@click.pass_context
def refresh(ctx, project_dir, only, jobs, init_plugin_path, enable, disable, update_config):
    """
    Re-run init plugins inside an existing project.

    Regenerates static/ analysis results and static_patches/ from the
    project's base/fs.tar.gz. Project-local plugins in plugins.d/ are
    included. The config's init_plugins: section selects what runs; the
    patches: list is updated in place (backup in config.yaml.bak) and
    user-edited patch files are preserved (new content goes to *.yaml.new).
    """
    _startup_checks(ctx.obj['VERBOSE'])

    proj = Path(project_dir)
    if not (proj / "config.yaml").is_file():
        raise ValueError(f"No config.yaml in {project_dir} - not a penguin project?")
    if not (proj / "base" / "fs.tar.gz").is_file():
        raise ValueError(f"No base/fs.tar.gz in {project_dir} - cannot re-analyze")

    ok = fakeroot_refresh(
        project_dir,
        verbose=ctx.obj['VERBOSE'],
        jobs=jobs,
        init_plugin_dirs=init_plugin_path,
        enable=enable,
        disable=disable,
        only=only,
        update_config=update_config,
    )
    if not ok:
        logger.error(f"Refresh failed for {project_dir}")
        exit(1)
    logger.info(f"Refreshed init analyses in {project_dir}")


@cli.command()
@click.argument("project_dir", type=str)
@click.option("--config", type=str, help="Path to a config file. Defaults to <project_dir>/config.yaml.")
@click.option("--output", type=str, default=None, help="The output directory path. Defaults to results/X in project directory where X auto-increments.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete output directory if it exists.")
@click.option("--timeout", type=int, default=None, help="Number of seconds that run/iteration should last. Default is None (must manually kill)")
@click.option("-a", "--auto", is_flag=True, help="Run in auto mode (don't start telnet shell).")
@click.option("--from-snapshot", "from_snapshot", type=str, default=None,
              help="Restore from a saved VM snapshot tag at startup (sugar for core.snapshot.boot_from).")
@click.option("--ignore-saved-config", "ignore_saved_config", is_flag=True, default=False,
              help="When restoring, do NOT default to the config the snapshot was saved with; "
                   "use the provided config instead (still gated by the snapshot fingerprint).")
@verbose_option
@click.pass_context
def run(ctx, project_dir, config, output, force, timeout, auto, from_snapshot,
        ignore_saved_config):
    """
    Run from a config.

    PROJECT_DIR is the path to project directory. For backwards compatability, a path to a config file within a project directory is also accepted.
    """
    _startup_checks(ctx.obj['VERBOSE'])

    project_dir, config = _resolve_project_and_config(project_dir, config)

    if force and output and os.path.isdir(output):
        shutil.rmtree(output, ignore_errors=True)

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

    run_from_config(project_dir, config, output, timeout=timeout, verbose=ctx.obj['VERBOSE'],
                    from_snapshot=from_snapshot, ignore_saved_config=ignore_saved_config)


@cli.command()
@click.option("--transport", type=str, default="stdio", help="MCP transport (default: stdio).")
@click.pass_context
def mcp(ctx, transport):
    """
    Start the MCP server for AI-led rehosting (runs in-container, speaks MCP over stdio).

    Exposes Penguin's loop to an LLM agent as tools: run, config mutations (accumulated in
    patch_90_mcp.yaml), and structured diagnostics over results/N/. See penguin.mcp.
    """
    from .mcp.server import serve
    serve(transport=transport)


@cli.command()
@click.argument("project_dir", type=str)
@click.option("--config", type=str, default=None, help="Path to a config file. Defaults to <project_dir>/config.yaml.")
@verbose_option
@click.pass_context
def validate(ctx, project_dir, config):
    """
    Validate a config without running it.

    Loads the config, applies patches and drop-ins, and runs full schema
    validation. On failure, prints a located, actionable report (which file,
    which option, what was wrong, allowed values) and exits non-zero.
    """
    _startup_checks(ctx.obj['VERBOSE'])

    project_dir, config = _resolve_project_and_config(project_dir, config)

    # load_config routes schema errors through the friendly formatter and
    # exits non-zero itself; a clean return means the config validated.
    cfg = load_config(project_dir, config, validate=True, verbose=ctx.obj['VERBOSE'])

    click.secho("Config OK", fg="green", bold=True)
    click.echo(f"  arch:   {cfg['core'].get('arch')}")
    click.echo(f"  kernel: {cfg['core'].get('kernel')}")
    plugin_names = sorted((cfg.get("plugins") or {}).keys())
    click.echo(f"  plugins: {', '.join(plugin_names) if plugin_names else '(none)'}")


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
        _render_markdown_file(full_path, num_lines=lines)


def _render_markdown_file(path, num_lines=None):
    """Render a markdown file to the terminal via glow, with a pager for long files."""
    if not shutil.which("glow"):
        with open(path, "r") as f:
            click.echo(f.read())
        return
    if num_lines is None:
        with open(path, "r") as f:
            num_lines = len(f.readlines())
    try:
        rows, _ = os.get_terminal_size()
    except OSError:
        rows = None
    glow_args = ["glow", path]
    if rows and num_lines > rows:
        subprocess.run(glow_args + ["--pager"])
    else:
        subprocess.run(glow_args)


def _render_markdown(text):
    """Render a markdown string to the terminal (reuses the glow file renderer)."""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(text)
        tmp = f.name
    try:
        _render_markdown_file(tmp, num_lines=text.count("\n") + 1)
    finally:
        os.unlink(tmp)


@cli.command()
@click.argument("section", type=str, required=False)
@click.option("--project_dir", type=str, default=None, help="Project dir used to discover local plugins for `schema <plugin>`.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit the raw JSON schema instead of rendered docs.")
@verbose_option
@click.pass_context
def schema(ctx, section, project_dir, as_json):
    """
    Show the config schema.

    With no SECTION, lists the top-level config sections. With a dotted SECTION
    (e.g. `core`, `pseudofiles.read`, `pseudofiles.read.const_buf`), renders that
    part of the schema. `schema plugins` additionally lists the declared
    arguments of every discovered plugin; `schema <plugin>` (or the dotted
    `schema plugins.<plugin>`) renders one plugin's arguments.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    from penguin.penguin_config import gen_docs

    if not section:
        if as_json:
            click.echo(yaml.dump(structure_json_schema(), indent=2))
            return
        lines = ["# Config sections", ""]
        for name, title in gen_docs.list_sections():
            lines.append(f"- `{name}` — {title}")
        lines.append("")
        lines.append("Run `penguin schema <section>` to see details, e.g. `penguin schema core`.")
        lines.append("Run `penguin schema plugins` to see every plugin's arguments, "
                     "or `penguin schema <plugin>` for a single plugin.")
        _render_markdown("\n".join(lines))
        return

    from penguin.penguin_config import structure as _structure
    plugin_path = _structure.Core.model_fields["plugin_path"].default

    # The `plugins` section is special: its type is just `dict[str, Plugin]`
    # (the generic per-plugin keys), which says nothing about what arguments any
    # given plugin actually accepts. Augment it with every discovered plugin's
    # declared `Args` so `penguin schema plugins` surfaces real plugin arguments.
    if section == "plugins":
        # Read declared Args via AST (no import) so every plugin is covered, not
        # just those importable outside a live emulator — the same static
        # approach config-load validation uses.
        if as_json:
            from penguin.plugin_manager import discover_declaring_plugins_static
            found, _skipped = discover_declaring_plugins_static(plugin_path)
            click.echo(yaml.dump(
                {name: _arg_specs_to_schema(specs) for name, specs in found},
                indent=2, sort_keys=False,
            ))
            return
        section_md = gen_docs.gen_docs(
            path=["plugins"],
            docs_field=gen_docs.resolve_section_docs_field("plugins"),
        )
        args_md = gen_docs.gen_all_plugin_args_docs(
            plugin_path, level=2, show_skipped=True, static=True)
        _render_markdown(section_md + "\n" + args_md)
        return

    resolved = gen_docs.resolve_section(section)
    if resolved is not None:
        if as_json:
            try:
                click.echo(yaml.dump(resolved.model_json_schema(), indent=2))
            except AttributeError:
                click.echo(f"(section '{section}' is a primitive type with no sub-schema)")
            return
        # Resolve through the owning field so field-level metadata (e.g. the
        # `plugins` section's title, which lives on its Field rather than its
        # type) is preserved; DocsField.from_type alone would drop it.
        md = gen_docs.gen_docs(
            path=section.split("."),
            docs_field=gen_docs.resolve_section_docs_field(section),
        )
        _render_markdown(md)
        return

    # Not a config section: maybe it's a plugin name. Accept both the bare name
    # (`schema vpn`) and the dotted form under the section (`schema plugins.vpn`).
    from penguin.plugin_manager import (
        get_plugin_args_model, get_plugin_class, plugin_declared_arg_specs)

    plugin = section[len("plugins."):] if section.startswith("plugins.") else section
    proj = project_dir or os.getcwd()

    # Prefer the imported model (richer types); fall back to AST-extracted specs
    # so plugins that can't be imported outside a live emulator still render —
    # matching `schema plugins`.
    args_model = get_plugin_args_model(plugin, proj, plugin_path)
    if args_model is not None:
        if as_json:
            click.echo(yaml.dump(args_model.model_json_schema(), indent=2))
            return
        _render_markdown(gen_docs.gen_plugin_args_docs(plugin, args_model))
        return

    specs = plugin_declared_arg_specs(plugin, proj, plugin_path)
    if specs is not None:
        if as_json:
            click.echo(yaml.dump(_arg_specs_to_schema(specs), indent=2, sort_keys=False))
            return
        _render_markdown(gen_docs.gen_plugin_args_docs_from_specs(plugin, specs))
        return

    cls = get_plugin_class(plugin, proj, plugin_path)
    if cls is not None:
        doc = cls.__doc__ or "(no docstring)"
        _render_markdown(f"# Plugin `{plugin}`\n\nThis plugin does not declare an `Args` schema.\n\n{doc}")
        return

    logger.error(
        f"Unknown schema section or plugin '{section}'. "
        f"Run `penguin schema` to list available sections."
    )
    sys.exit(1)


def structure_json_schema():
    from penguin.penguin_config import structure
    return structure.Main.model_json_schema()


def _arg_specs_to_schema(arg_specs):
    """
    Turn a list of statically-extracted ``ArgSpec`` into a JSON-serializable dict
    keyed by argument name (type/default rendered from source — see
    ``plugin_manager.discover_declaring_plugins_static``).
    """
    out = {}
    for spec in arg_specs:
        entry = {"type": spec.type, "required": spec.required}
        if not spec.required and spec.default is not None:
            kind, val = spec.default
            entry["default"] = val if kind == "literal" else f"{val}  # (non-literal)"
        if spec.description:
            entry["description"] = spec.description
        out[spec.name] = entry
    return out


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
@click.option("--with-snapshot", "with_snapshot", multiple=True, metavar="TAG",
              help="Also include the named VM snapshot bundle (overlay + base + sidecars) so the project can boot_from it elsewhere. Repeatable.")
@verbose_option
@click.pass_context
def pack(ctx, project_dir, out, with_snapshot):
    """
    Package a penguin project into a distributable archive.

    Creates a tar.gz pulling in configs, base, and static patches while omitting
    results and qcows. Pass --with-snapshot TAG to additionally bundle a saved
    VM snapshot (made portable via a relative backing rebase) for capture & share.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    _do_package(project_dir, out, with_snapshots=with_snapshot)


@cli.command()
@click.argument("archive", type=click.Path(exists=True))
@click.option("-o", "--output", type=str, default="./projects", help="Output directory path. Defaults to ./projects in current directory.")
@click.option("--force", is_flag=True, default=False, help="Forcefully delete output directory if it exists")
@verbose_option
@click.pass_context
def unpack(ctx, archive, output, force):
    """
    Extract a packaged penguin project.

    ARCHIVE is the path to a .tar.gz file created by 'penguin pack'.
    """
    _startup_checks(ctx.obj['VERBOSE'])

    archive_path = os.path.abspath(archive)
    if not archive_path.endswith('.tar.gz'):
        raise ValueError(f"Archive must be a .tar.gz file: {archive}")

    if not os.path.exists(archive_path):
        raise ValueError(f"Archive file not found: {archive}")

    # Route relative output paths into the mapped workspace, similar to package command
    if output is None:
        output = "./projects"

    if not os.path.isabs(output):
        if os.path.exists("/workspace"):
            output = os.path.join("/workspace", output)
        else:
            output = os.path.abspath(output)
    else:
        output = os.path.abspath(output)

    # Ensure output directory exists
    os.makedirs(output, exist_ok=True)

    # Verify the archive contains the version file and extract metadata
    try:
        subprocess.run(
            ["tar", "-tzf", archive_path, ".penguin_packaged_version"],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError:
        raise ValueError(
            "Archive is not a valid penguin package: missing .penguin_packaged_version file. "
            "This archive was not created with 'penguin pack'."
        )
    except FileNotFoundError:
        logger.error("tar command not found. Please ensure tar is installed.")
        exit(1)

    # Extract metadata to determine the base_name
    with tempfile.TemporaryDirectory() as temp_extract_dir:
        try:
            subprocess.run(
                ["tar", "-I", "pigz", "-xf", archive_path, "-C", temp_extract_dir, ".penguin_packaged_version"],
                check=True
            )
            metadata_path = os.path.join(temp_extract_dir, ".penguin_packaged_version")
            with open(metadata_path, "r") as f:
                metadata = yaml.safe_load(f) or {}

            base_name = metadata.get("base_name")
            if not base_name:
                # Fall back to archive filename without .tar.gz
                base_name = os.path.basename(archive_path)
                if base_name.endswith(".tar.gz"):
                    base_name = base_name[:-7]
                logger.warning(f"No base_name in metadata, using archive filename: {base_name}")
        except (subprocess.CalledProcessError, yaml.YAMLError) as e:
            logger.error(f"Failed to extract metadata: {e}")
            exit(1)

    # Set target directory based on metadata
    target_dir = os.path.join(output, base_name)

    # Check if target directory exists
    if os.path.exists(target_dir):
        if force:
            logger.info(f"Deleting existing directory: {target_dir}")
            shutil.rmtree(target_dir, ignore_errors=True)
        else:
            raise ValueError(
                f"Output directory already exists: {target_dir}. Use --force to delete."
            )

    logger.info(f"Extracting {archive} to {target_dir}...")

    # Create the target directory
    os.makedirs(target_dir, exist_ok=True)

    try:
        subprocess.run(
            ["tar", "-I", "pigz", "-xf", archive_path, "-C", target_dir],
            check=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to extract archive: {e}")
        exit(1)

    logger.info(f"Successfully extracted to {target_dir}")

    # Verify it's a valid penguin project
    config_path = os.path.join(target_dir, "config.yaml")
    if not os.path.exists(config_path):
        logger.warning("Extracted directory does not contain config.yaml")
    else:
        logger.info(f"Project ready at {target_dir}")


@cli.command(hidden=True)
@click.argument("project_dir", type=click.Path(exists=True))
@click.option("-o", "--out", type=str, default=None)
@verbose_option
@click.pass_context
def export(ctx, project_dir, out):
    """Alias for pack"""
    ctx.invoke(pack, project_dir=project_dir, out=out)


@cli.command(name="import", hidden=True)
@click.argument("archive", type=click.Path(exists=True))
@click.option("-o", "--output", type=str, default="./projects")
@click.option("--force", is_flag=True, default=False)
@verbose_option
@click.pass_context
def import_cmd(ctx, archive, output, force):
    """Alias for unpack"""
    ctx.invoke(unpack, archive=archive, output=output, force=force)


def _looks_like_compose_project_dir(path: str) -> bool:
    return os.path.isdir(path) and os.path.isfile(os.path.join(path, "compose.yaml"))


def _looks_like_compose_device_project_dir(path: str) -> bool:
    return (
        os.path.isdir(path)
        and os.path.isfile(os.path.join(path, "config.yaml"))
        and not os.path.isfile(os.path.join(path, "compose.yaml"))
    )


def _compose_file_from_target(target: str) -> str:
    if os.path.isfile(target):
        return target
    if _looks_like_compose_project_dir(target):
        return os.path.join(target, "compose.yaml")
    if _looks_like_compose_device_project_dir(target):
        raise click.ClickException(
            f"'{target}' is a single-device project, not a compose project. "
            "Use `penguin run` for one project, or `penguin compose init` "
            "with two-or-more project directories."
        )
    raise click.ClickException(
        f"Cannot interpret '{target}' as a compose target. Expected a "
        "compose.yaml file or a directory containing compose.yaml."
    )


def _scaffold_compose_from_project_dirs(
    project_dirs: tuple[str, ...] | list[str],
    name: str | None = None,
) -> str:
    if len(project_dirs) < 2:
        raise click.ClickException(
            "Compose init requires two-or-more project directories, each "
            "containing config.yaml and no compose.yaml."
        )
    bad = [p for p in project_dirs if not _looks_like_compose_device_project_dir(p)]
    if bad:
        joined = ", ".join(repr(p) for p in bad)
        raise click.ClickException(
            "Compose init expects only project directories containing config.yaml "
            f"and no compose.yaml. Cannot use: {joined}"
        )
    try:
        return scaffold_compose(list(project_dirs), name=name)
    except (ValueError, RuntimeError) as e:
        raise click.ClickException(str(e))


def _run_compose_target(ctx, target: str, output: str | None, force: bool, timeout: int | None) -> None:
    compose_file = _compose_file_from_target(target)
    run_compose(
        compose_file,
        output,
        timeout=timeout,
        force=force,
        verbose=ctx.obj['VERBOSE'],
    )


def _run_compose_shortcut(ctx, targets, output, force, timeout) -> None:
    project_dirs = [t for t in targets if _looks_like_compose_device_project_dir(t)]

    if len(project_dirs) == len(targets) and len(targets) >= 2:
        try:
            compose_file = scaffold_compose(list(targets))
        except (ValueError, RuntimeError) as e:
            raise click.ClickException(str(e))
        run_compose(
            compose_file,
            output,
            timeout=timeout,
            force=force,
            verbose=ctx.obj['VERBOSE'],
        )
    elif len(targets) == 1:
        _run_compose_target(ctx, targets[0], output, force, timeout)
    else:
        raise click.ClickException(
            "Cannot interpret compose arguments. Expected one of: "
            "(a) `penguin compose run <compose.yaml-or-dir>`, "
            "(b) `penguin compose init <project-dir> <project-dir> [...]`, "
            "or (c) the shortcut `penguin compose <project-dir> <project-dir> [...]`."
        )


@cli.group(
    cls=ComposeGroup,
    invoke_without_command=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@verbose_option
@click.pass_context
def compose(ctx):
    """
    Manage multi-device firmware rehosting.

    Common workflow:

    \b
    * `penguin compose init ./projects/a ./projects/b`
    * inspect or edit the generated compose.yaml
    * `penguin compose run ./compose_projects/<timestamp>`

    For quick experiments, `penguin compose ./projects/a ./projects/b`
    remains a scaffold-and-run shortcut.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        ctx.exit()


@compose.command("init")
@click.argument("project_dirs", nargs=-1, required=True, type=click.Path(exists=True, file_okay=False))
@click.option("--name", "name", type=str, default=None,
              help="Name of the scaffolded compose project directory. "
                   "Defaults to the device basenames joined with '_' "
                   "(e.g. projects 'foo' + 'bar' → 'foo_bar').")
@verbose_option
@click.pass_context
def compose_init(ctx, project_dirs, name):
    """
    Create a compose project from two or more device projects.

    PROJECT_DIRS must each contain a config.yaml. The generated compose
    project is written under compose_projects/<name>/ alongside the
    projects' parent directory.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    compose_file = _scaffold_compose_from_project_dirs(project_dirs, name=name)
    click.echo(compose_file)


@compose.command("run")
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", type=str, default=None, help="Exact output directory. Defaults to results/<N> next to compose.yaml with latest symlink.")
@click.option("--force", is_flag=True, default=False, help="Delete existing explicit output directory before running.")
@click.option("--timeout", type=int, default=None, help="Per-device timeout in seconds.")
@verbose_option
@click.pass_context
def compose_run(ctx, target, output, force, timeout):
    """
    Run an existing compose project.

    TARGET is a compose.yaml file or a directory containing compose.yaml.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    _run_compose_target(ctx, target, output, force, timeout)


@compose.command("_shortcut", hidden=True, context_settings={"ignore_unknown_options": True})
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--output", type=str, default=None, help="Exact output directory. Defaults to results/<N> next to compose.yaml with latest symlink.")
@click.option("--force", is_flag=True, default=False, help="Delete existing explicit output directory before running.")
@click.option("--timeout", type=int, default=None, help="Per-device timeout in seconds.")
@verbose_option
@click.pass_context
def compose_shortcut(ctx, targets, output, force, timeout):
    """
    Compatibility path for `penguin compose <target...>`.
    """
    _startup_checks(ctx.obj['VERBOSE'])
    _run_compose_shortcut(ctx, targets, output, force, timeout)


cli.add_command(_utils_group)


if __name__ == "__main__":
    cli()
