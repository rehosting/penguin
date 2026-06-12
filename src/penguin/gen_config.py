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

from pathlib import Path
from penguin import getColoredLogger

from .defaults import (
    default_plugin_path,
    default_version as DEFAULT_VERSION,
)
from .init_plugin import InitContext
from .init_runner import (
    InitPluginRunner,
    _norm_name,
    discover_init_plugins,
    load_manifest,
)
from penguin.penguin_config import dump_config, load_unpatched_config

logger = getColoredLogger("penguin.gen_config")


def init_plugin_search_dirs(proj_dir: str | Path, extra_dirs=()) -> list:
    """
    Directories scanned for init plugins, lowest to highest precedence:
    built-ins under <plugin_path>/init, then the project's plugins.d/, then
    any explicitly passed directories.
    """
    return [
        Path(default_plugin_path, "init"),
        Path(proj_dir, "plugins.d"),
        *[Path(d) for d in extra_dirs],
    ]


class ConfigBuilder:
    '''
    Given a filesystem and an output directory, create a configuration
    and initialize the output directory as necessary.
    '''
    PATCH_DIR: str = "static_patches"

    def __init__(
        self,
        fs_archive: str,
        output_dir: str | Path,
        jobs: int | None = None,
        init_plugin_dirs=(),
        enable=(),
        disable=(),
    ) -> None:
        # Create a 'base' directory for analysis results, copy fs into it
        base_dir = Path(output_dir, "base")
        base_dir.mkdir(exist_ok=True, parents=True)
        archive_fs = Path(base_dir, "fs.tar.gz")
        shutil.copy(fs_archive, archive_fs)

        # Extract the filesystem into base_dir/fs
        extracted_fs = base_dir / "extracted"
        extract_fs_archive(archive_fs, extracted_fs)

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
                options={"enable": tuple(enable)},
            )
            all_classes = discover_init_plugins(
                init_plugin_search_dirs(output_dir, init_plugin_dirs)
            )
            if not all_classes:
                raise RuntimeError(
                    "No init plugins discovered - is the plugin path "
                    f"({default_plugin_path}/init) available?"
                )
            disabled = {_norm_name(d) for d in disable}
            plugin_classes = [
                c for c in all_classes if _norm_name(c.__name__) not in disabled
            ]
            # Recorded in the generated config; drives `penguin refresh`
            init_plugin_record = {
                c.__name__: {"enabled": _norm_name(c.__name__) not in disabled}
                for c in all_classes
            }
            logger.debug(f"Running {len(plugin_classes)} init plugins")
            runner = InitPluginRunner(plugin_classes, ctx, jobs=jobs)
            patches = runner.run()
            runner.render_patches(patches)

            # Generate our base config including our list of patches
            config = self.generate_initial_config(patches, init_plugin_record)

            # Dump it to disk
            dump_config(config, os.path.join(output_dir, "config.yaml"))

        finally:
            # Always clean up extracted filesystem
            shutil.rmtree(extracted_fs)

    def generate_initial_config(self, patches: dict, init_plugins: dict | None = None) -> dict:
        '''
        Generate the initial configuration dictionary.

        :param patches: Dictionary of patches.
        :type patches: dict
        :param init_plugins: Init plugin record for the init_plugins section.
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
            "init_plugins": init_plugins or {},
            "nvram": {},
        }


def extract_fs_archive(archive: str | Path, dest: str | Path) -> None:
    """Extract a root filesystem archive and normalize permissions so the
    current (fakeroot) user can read everything."""
    dest = Path(dest)
    dest.mkdir()
    subprocess.check_output(["tar", "-xf", str(archive), "-C", str(dest)])

    # ensure every file is readable by the current user
    subprocess.check_output(
        ["find", str(dest), "-type", "f", "-exec", "chmod", "u+r", "{}", "+"])

    # ensure every directory is readable by the current user (requires exec)
    subprocess.check_output(
        ["find", str(dest), "-type", "d", "-exec", "chmod", "u+rx", "{}", "+"])


def initialize_and_build_config(
    fs: str,
    out: str | None = None,
    artifacts_dir: str | None = None,
    jobs: int | None = None,
    init_plugin_dirs=(),
    enable=(),
    disable=(),
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
    :param jobs: Init plugin thread pool size (default: cpu count).
    :param init_plugin_dirs: Extra directories to search for init plugins.
    :param enable: Init plugin names to force-enable (their patches join the
        config's patches list even if disabled by default).
    :param disable: Init plugin names to skip entirely.

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
    ConfigBuilder(
        fs, output_dir,
        jobs=jobs,
        init_plugin_dirs=init_plugin_dirs,
        enable=enable,
        disable=disable,
    )

    outfile = os.path.join(output_dir, "config.yaml")

    # config is a path to output_dir/base/config.yaml
    if not shutil._samefile(outfile, out):
        shutil.copyfile(outfile, out)

    if tmpdir:
        tmpdir.cleanup()

    return out


def refresh_project(
    proj_dir: str,
    jobs: int | None = None,
    init_plugin_dirs=(),
    enable=(),
    disable=(),
    only=(),
    update_config: bool = True,
) -> bool:
    """
    Re-run init plugins inside an existing project, refreshing static/ and
    static_patches/ and (optionally) reconciling the config's patches list.

    The user's config.yaml is never rewritten wholesale: only the `patches:`
    and `init_plugins:` sections are updated, after backing the file up to
    config.yaml.bak. Patch files the user edited since generation are
    preserved (new content lands in <name>.yaml.new).

    The config's init_plugins: section is the source of truth for which
    plugins run; entries with enabled=false are skipped. CLI --enable/--disable
    override per-invocation, and --only restricts execution to the named
    plugins (everything else keeps its current outputs; shared analyses are
    still computed on demand).

    :return: True on success.
    """
    proj = Path(proj_dir)
    config_path = proj / "config.yaml"
    fs_archive = proj / "base" / "fs.tar.gz"
    if not config_path.is_file():
        raise RuntimeError(f"No config.yaml in {proj} - not a penguin project?")
    if not fs_archive.is_file():
        raise RuntimeError(f"No base/fs.tar.gz in {proj} - cannot re-analyze")

    config = load_unpatched_config(config_path)
    recorded = config.get("init_plugins") or {}

    all_classes = discover_init_plugins(
        init_plugin_search_dirs(proj, init_plugin_dirs)
    )
    if not all_classes:
        raise RuntimeError(
            "No init plugins discovered - is the plugin path "
            f"({default_plugin_path}/init) available?"
        )

    # Which plugins should run: recorded enabled=false and CLI --disable skip;
    # CLI --enable overrides a recorded disable; --only restricts further.
    cli_enable = {_norm_name(x) for x in enable}
    cli_disable = {_norm_name(x) for x in disable}
    recorded_disabled = {
        _norm_name(name)
        for name, entry in recorded.items()
        if isinstance(entry, dict) and entry.get("enabled") is False
    }
    skip = (recorded_disabled - cli_enable) | cli_disable
    if only:
        only_norm = {_norm_name(x) for x in only}
        unknown = only_norm - {_norm_name(c.__name__) for c in all_classes}
        if unknown:
            raise RuntimeError(f"--only names not found: {sorted(unknown)}")
        skip |= {
            _norm_name(c.__name__)
            for c in all_classes
            if _norm_name(c.__name__) not in only_norm
        }

    previous_manifest = load_manifest(proj / "static")

    extracted_fs = proj / "base" / "extracted.refresh"
    if extracted_fs.exists():
        shutil.rmtree(extracted_fs)
    extract_fs_archive(fs_archive, extracted_fs)
    try:
        ctx = InitContext(
            fs_archive=fs_archive,
            extracted_fs=extracted_fs,
            proj_dir=proj,
            static_dir=proj / "static",
            patch_dir=proj / ConfigBuilder.PATCH_DIR,
            options={"enable": tuple(enable)},
        )
        runner = InitPluginRunner(all_classes, ctx, jobs=jobs, skip=skip)
        patches = runner.run()
        runner.merge_previous_manifest(previous_manifest)
        rendered = runner.render_patches(patches, previous_manifest=previous_manifest)
    finally:
        shutil.rmtree(extracted_fs)

    ran = [c.__name__ for c in all_classes if _norm_name(c.__name__) not in skip]
    logger.info(
        f"Refreshed {len(ran)} init plugins"
        + (f" ({len(rendered['preserved'])} user-edited patch files preserved)"
           if rendered["preserved"] else "")
    )

    if update_config:
        _reconcile_config(
            config_path, config, patches, rendered, runner.manifest,
            all_classes, skip, recorded,
        )
    return True


def _reconcile_config(
    config_path: Path,
    config: dict,
    patches: dict,
    rendered: dict,
    manifest: dict,
    all_classes,
    skip: set,
    recorded: dict,
) -> None:
    """
    Update the patches: and init_plugins: sections of an existing config.
    Everything else in the file is left untouched (but yaml comments and
    formatting are not preserved; a backup is written to config.yaml.bak).
    """
    patch_dir = ConfigBuilder.PATCH_DIR
    existing = list(config.get("patches") or [])

    # Order lookup for insertion position, from the (merged) manifest
    order_of = {}
    for entry in manifest.values():
        if entry.get("patch_file"):
            order_of[f"{patch_dir}/{entry['patch_file']}"] = entry.get("order", 1000)

    added, removed = [], []

    # Add newly generated+enabled patches missing from the list, at the
    # position their order implies (entries with unknown order are skipped
    # when comparing - user patches keep their place).
    for name, (_data, enabled) in patches.items():
        fname = f"{patch_dir}/{name}.yaml"
        if not enabled or name not in rendered["written"] or fname in existing:
            continue
        idx = 0
        for i, entry in enumerate(existing):
            entry_order = order_of.get(entry)
            if entry_order is not None and entry_order <= order_of.get(fname, 1000):
                idx = i + 1
        existing.insert(idx, fname)
        added.append(fname)

    # Drop entries whose patch files no longer exist
    for entry in list(existing):
        if entry.startswith(f"{patch_dir}/") and not Path(config_path.parent, entry).is_file():
            existing.remove(entry)
            removed.append(entry)

    # Refresh the init_plugins record: keep user's enabled=false entries,
    # append newly discovered plugins.
    new_record = dict(recorded)
    for c in all_classes:
        if c.__name__ not in new_record:
            new_record[c.__name__] = {"enabled": _norm_name(c.__name__) not in skip}
            logger.info(f"Recording newly discovered init plugin {c.__name__}")

    if not added and not removed and new_record == recorded:
        logger.info("Config already up to date")
        return

    backup = config_path.with_suffix(".yaml.bak")
    shutil.copy2(config_path, backup)
    config["patches"] = existing
    config["init_plugins"] = new_record
    with open(config_path, "w") as f:
        yaml.dump(config, f, sort_keys=False)

    for fname in added:
        logger.info(f"config patches: added {fname}")
    for fname in removed:
        logger.info(f"config patches: removed {fname} (file no longer exists)")
    logger.info(f"Updated {config_path} (backup at {backup})")


def fakeroot_gen_config(
    fs: str,
    out: str,
    artifacts_dir: str,
    verbose: int,
    jobs: int | None = None,
    init_plugin_dirs=(),
    enable=(),
    disable=(),
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
    :param jobs: Init plugin thread pool size.
    :param init_plugin_dirs: Extra directories to search for init plugins.
    :param enable: Init plugin names to force-enable.
    :param disable: Init plugin names to skip entirely.
    :return: Path to generated config file or None.
    :rtype: str or None
    """
    o = Path(out)
    cmd = [
        "fakeroot",
        "gen_config",
        "generate",
        "--fs", str(fs),
        "--out", str(o),
        "--artifacts", artifacts_dir,
    ]
    if jobs:
        cmd.extend(["--jobs", str(jobs)])
    for d in init_plugin_dirs:
        cmd.extend(["--init-plugin-path", str(d)])
    for name in enable:
        cmd.extend(["--enable", name])
    for name in disable:
        cmd.extend(["--disable", name])
    if verbose:
        cmd.extend(["--verbose"])
    p = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()
    if o.exists():
        return str(o)


def fakeroot_refresh(
    proj_dir: str,
    verbose: int = 0,
    jobs: int | None = None,
    init_plugin_dirs=(),
    enable=(),
    disable=(),
    only=(),
    update_config: bool = True,
) -> bool:
    """
    Run `gen_config refresh` under fakeroot (always in a fresh subprocess so
    the plugin-manager singleton never collides with a running emulation).

    :return: True if the refresh subprocess succeeded.
    """
    cmd = [
        "fakeroot",
        "gen_config",
        "refresh",
        "--project", str(proj_dir),
    ]
    if jobs:
        cmd.extend(["--jobs", str(jobs)])
    for d in init_plugin_dirs:
        cmd.extend(["--init-plugin-path", str(d)])
    for name in enable:
        cmd.extend(["--enable", name])
    for name in disable:
        cmd.extend(["--disable", name])
    for name in only:
        cmd.extend(["--only", name])
    if not update_config:
        cmd.append("--no-update-config")
    if verbose:
        cmd.append("--verbose")
    p = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()
    return p.returncode == 0


@click.group()
def main() -> None:
    """Penguin config generation (runs under fakeroot)."""


@main.command()
@click.option("--fs", required=True, help="Path to a filesystem archive")
@click.option("--out", required=True, help="Path to a config to be created")
@click.option("--artifacts", default=None, help="Path to a directory for artifacts")
@click.option("--jobs", default=None, type=int, help="Init plugin thread pool size (default: cpu count)")
@click.option("--init-plugin-path", multiple=True, help="Extra directory to search for init plugins (repeatable)")
@click.option("--enable", multiple=True, help="Init plugin name to force-enable (repeatable)")
@click.option("--disable", multiple=True, help="Init plugin name to skip (repeatable)")
@click.option("-v", "--verbose", count=True)
def generate(
    fs: str,
    out: str,
    artifacts: str | None,
    jobs: int | None,
    init_plugin_path: tuple,
    enable: tuple,
    disable: tuple,
    verbose: int,
) -> str | None:
    """Generate a new config from a filesystem archive."""
    if verbose:
        logger.setLevel(logging.DEBUG)

    try:
        # Return a path to a config if we generate one
        return initialize_and_build_config(
            fs, out, artifacts,
            jobs=jobs,
            init_plugin_dirs=init_plugin_path,
            enable=enable,
            disable=disable,
        )
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


@main.command()
@click.option("--project", required=True, help="Path to an existing penguin project")
@click.option("--jobs", default=None, type=int, help="Init plugin thread pool size (default: cpu count)")
@click.option("--init-plugin-path", multiple=True, help="Extra directory to search for init plugins (repeatable)")
@click.option("--enable", multiple=True, help="Init plugin name to force-enable (repeatable)")
@click.option("--disable", multiple=True, help="Init plugin name to skip (repeatable)")
@click.option("--only", multiple=True, help="Only re-run these init plugins (repeatable)")
@click.option("--update-config/--no-update-config", default=True,
              help="Reconcile the config's patches/init_plugins sections (default: on)")
@click.option("-v", "--verbose", count=True)
def refresh(
    project: str,
    jobs: int | None,
    init_plugin_path: tuple,
    enable: tuple,
    disable: tuple,
    only: tuple,
    update_config: bool,
    verbose: int,
) -> None:
    """Re-run init plugins inside an existing project."""
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Match init's umask: generated files must be usable by non-container users
    os.umask(0o000)
    try:
        refresh_project(
            project,
            jobs=jobs,
            init_plugin_dirs=init_plugin_path,
            enable=enable,
            disable=disable,
            only=only,
            update_config=update_config,
        )
    except Exception as e:
        logger.error(f"Refresh failed: {e}")
        if verbose:
            logger.exception(e)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
