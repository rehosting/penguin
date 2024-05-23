#!/usr/bin/env python3

import os
import shutil
import subprocess
import logging
import art
import argparse
from pathlib import Path
from os.path import join, dirname
from .common import yaml
from .manager import graph_search, PandaRunner, calculate_score
from .gen_config import fakeroot_gen_config
from .penguin_config import load_config
from penguin import VERSION, getColoredLogger

logger = getColoredLogger("penguin")

def run_from_config(config_path, output_dir, niters=1, nthreads=1, timeout=None, verbose=False):

    if not os.path.isfile(config_path):
        raise RuntimeError(f"Config file not found: {config_path}")

    proj_dir = os.path.dirname(config_path)

    try:
        config = load_config(config_path)
    except UnicodeDecodeError:
        raise RuntimeError(f"Config file {config_path} is not a valid unicode YAML file. Is it a firmware file instead of a configuration?")

    if not os.path.isfile(config['core']['kernel']):
        # The config specifies where the kernel shoudl be. Generally this is in
        # /igloo_static/kernels, but it could be elsewhere.
        raise RuntimeError(f"Base kernel not found: {config['core']['kernel']}")

    if niters > 1:
        return graph_search(config, output_dir, max_iters=niters, nthreads=nthreads)

    # You already have a config, let's just run it. This is what happens
    # in each iterative run normally. Here we just do it directly.
    # Only needs a single thread, regardless of nthreads.
    # We need to select an init - grab the first one from our base/env.yaml file

    init = None
    if config.get('env', {}).get('igloo_init', None) is None:
        with open(join(dirname(output_dir), "base", "env.yaml"), 'r') as f:
            env = yaml.safe_load(f)
            if env.get('igloo_init', None) and len(env['igloo_init']) > 0:
                init = env['igloo_init'][0]
                logger.info(f"Config does not specify init. Selecting first option: {init}." + ((" Other options are: " + ", ".join(env['igloo_init'][1:])) if len(env['igloo_init']) > 1 else ""))
            else:
                raise RuntimeError(f"Static analysis failed to identify an init script. Please specify one in {output_dir}/config.yaml and run again with --config.")

    # XXX is this the right run_base? It's now our project dir
    proj_dir = os.path.dirname(config_path)
    PandaRunner().run(config_path, proj_dir, output_dir, init=init, timeout=timeout, show_output=True, verbose=verbose) # niters is 1

    # Single iteration: there is not best - don't report that
    #report_best_results(run_base, output_dir, os.path.dirname(output_dir))

    # But do calculate and report scores. Unlike multi-run mode, we'll write scores right into output dir instead of in parent
    best_scores = calculate_score(output_dir, have_console=not config['core'].get('show_output', False))
    with open(os.path.join(output_dir, "scores.txt"), "w") as f:
        f.write("score_type,score\n")
        for k, v in best_scores.items():
            f.write(f"{k},{v:.02f}\n")
    with open(os.path.join(output_dir, "score.txt"), "w") as f:
        total_score = sum(best_scores.values())
        f.write(f"{total_score:.02f}\n")

def add_init_arguments(parser):
    parser.add_argument('rootfs', type=str, help='The rootfs path. (e.g. path/to/fw_rootfs.tar.gz)')
    parser.add_argument('--output', type=str, help="Optional argument specifying the path where the project will be created. Default is projects/<basename of firmware file>.", default=None)
    parser.add_argument('--force', action='store_true', default=False, help="Forcefully delete project directory if it exists")
    parser.add_argument('--output_base', type=str, help="Default project directory base. Default is 'projects'", default="projects")
    parser.add_argument('-v','--verbose', action='store_true', help='Set log level to debug')

def penguin_init(args):
    '''
    Initialize a project from a firmware rootfs
    '''
    firmware = Path(args.rootfs)

    if not firmware.exists():
        raise ValueError(f"Firmware file not found: {firmware}")

    if args.rootfs.endswith(".yaml"):
        raise ValueError("FATAL: It looks like you provided a config file (it ends with .yaml)." \
                         "Please provide a firmware file")

    if args.output is None:
        # Expect filename to end with .tar.gz - drop that extension
        if args.rootfs.endswith(".rootfs.tar.gz"):
            basename_stem = os.path.basename(args.rootfs)[0:-14] # Drop the .rootfs.tar.gz
        elif args.rootfs.endswith(".tar.gz"):
            basename_stem = os.path.basename(args.rootfs)[0:-7] # Drop the .tar.gz
        else:
            # Drop the extension
            basename_stem = os.path.splitext(os.path.basename(args.rootfs))[0]

        if not os.path.exists(args.output_base):
            os.makedirs(args.output_base)
        args.output = args.output_base  + "/" + basename_stem
        logger.info(f"Creating project at generated path: {args.output}")
    else:
        logger.info(f"Creating project at specified path: {args.output}")

    if args.force and os.path.isdir(args.output):
        logger.info(f"Deleting existing project directory: {args.output}")
        shutil.rmtree(args.output, ignore_errors=True)

    if '/host_' in args.rootfs or '/host_' in args.output:
        logger.info("Note messages referencing /host paths reflect automatically-mapped shared directories based on your command line arguments")

    # Ensure output parent directory exists
    if not os.path.exists(os.path.dirname(args.output)):
        os.makedirs(os.path.dirname(args.output))

    out_config_path = Path(args.output, "config.yaml")
    config = fakeroot_gen_config(args.rootfs, out_config_path, args.output, args.verbose)

    if not config:
        # We failed to generate a config. We'll have written a result file to the output dir
        logger.error(f"Failed to generate config for {args.rootfs}. See {args.output}/result for details.")


def add_patch_arguments(parser):
    parser.add_argument('config', type=str, help='Path to the full config file to be updated')
    parser.add_argument('patch', type=str, help='Path to the config patch')
    parser.add_argument('-v','--verbose', action='store_true', help='Set log level to debug')

def penguin_patch(args):
    '''
    Given a config to be updated and a partial config (the patch), update each
    field in the config with the corresponding field in the patch.
    '''

    config = Path(args.config)
    patch = Path(args.patch)

    if not config.exists():
        raise ValueError(f"Config file does not exist: {args.config}")

    if not patch.exists():
        raise ValueError(f"Patch file does not exist: {args.patch}")

    # Read both yaml files
    with open(config, 'r') as f:
        base_config = yaml.safe_load(f)

    with open(patch, 'r') as f:
        patch_config = yaml.safe_load(f)

    # Merge configs.
    def _recursive_update(base, new):
        for k, v in new.items():
            if isinstance(v, dict):
                base[k] = _recursive_update(base.get(k, {}), v)
            else:
                base[k] = v
        return base

    for key, value in patch_config.items():
        # Check if the key already exists in the base_config
        if key in base_config:
            # If the value is a dictionary, update subfields
            if isinstance(value, dict):
                # Recursive update to handle nested dictionaries
                base_config[key] = _recursive_update(base_config.get(key, {}), value)
            elif isinstance(value, list):
                # Replace the list with the incoming list
                base_config[key] = value
            else:
                # Replace the base value with the incoming value
                base_config[key] = value
        else:
            # New key, add all data directly
            base_config[key] = value

    # Replace the original config with the updated one
    with open(config, 'w') as f:
        yaml.dump(base_config, f)

def add_docs_arguments(parser):
    #parser.add_argument('filename', type=str,
    #    help='Documentation file to render. If unset, filenames are printed.',
    #    default=None)
    parser.add_argument('--filename', type=str, default=None, nargs='?',
        help='Documentation file to render. If unset, filenames are printed.')
    parser.add_argument('-v','--verbose', action='store_true', help='Set log level to debug')


def penguin_docs(args):
    #docs_path = join(dirname(dirname(__file__)), "docs")
    # Only valid in container
    docs_path = "/docs"

    if args.filename:
        if not args.filename.endswith(".md"):
            args.filename += ".md"
        full_path = join(docs_path, args.filename)

        if '..' in args.filename:
            raise ValueError("Invalid filename")

        if not os.path.isfile(full_path):
            logger.info(f"Documentation file not found: {args.filename}")
        else:
            # How many lines are in the file?
            with open(full_path, 'r') as f:
                lines = len(f.readlines())

            # How many lines are in the terminal (if available)
            try:
                rows, _ = os.get_terminal_size()
            except OSError:
                rows = None

            glow_args = ["glow", full_path]
            if rows and lines > rows:
                # We'll render with a pager
                subprocess.run(glow_args + ["--pager"])
            else:
                # Otherwise print directly
                subprocess.run(glow_args)
    else:
        logger.info("Available documentation files. Select one to view by running penguin docs --filename <filename>")
        for f in os.listdir(docs_path):
            logger.info("  %s", f)

def add_run_arguments(parser):
    parser.add_argument('config', type=str, help='Path to a config file within a project directory.')
    parser.add_argument('--output', type=str, help='The output directory path. Defaults to results/X in project directory where X auto-increments.', default=None)
    parser.add_argument('--force', action='store_true', default=False, help="Forcefully delete output directory if it exists.")
    parser.add_argument('-v','--verbose', action='store_true', help='Set log level to debug')

def penguin_run(args):
    if args.force and os.path.isdir(args.output):
        shutil.rmtree(args.output, ignore_errors=True)

    config = Path(args.config)
    if not config.exists():
        raise ValueError(f"Config file does not exist: {args.config}")

    # Allow config to be the project dir (which contains config.yaml)
    if os.path.isdir(args.config) and os.path.exists(os.path.join(args.config, "config.yaml")):
        args.config = os.path.join(args.config, "config.yaml")

    # Sanity check, should have a 'base' directory next to the config
    if not os.path.isdir(os.path.join(os.path.dirname(args.config), "base")):
        raise ValueError(f"Config directory does not contain a 'base' directory: {os.path.dirname(args.config)}.")

    if args.output is None:
        # Expect a config like ./project/myfirmware/config.yaml, get myfirmware from there
        # and create ./project/myfirmware/results/X and auto-increment X
        results_base = os.path.dirname(args.config) + "/results/"

        if not os.path.exists(results_base):
            os.makedirs(results_base)
            idx = 0
        else:
            results = [int(d) for d in os.listdir(results_base) if os.path.isdir(os.path.join(results_base, d))]
            if len(results) == 0:
                idx = 0
            else:
                idx = max(results) + 1
        args.output = results_base + str(idx)

    logger.info(f"Running config {args.config}")
    logger.info(f"Saving results to {args.output}")

    if '/host_' in args.config or '/host_' in args.output:
        logger.info("Note messages referencing /host paths reflect automatically-mapped shared directories based on your command line arguments")

    run_from_config(args.config, args.output, verbose=args.verbose)

def main():
    parser = argparse.ArgumentParser(description=f"""
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
    """,
    formatter_class=argparse.RawTextHelpFormatter)

    subparsers = parser.add_subparsers(help='subcommand', dest='cmd', required=False)

    parser_cmd_init = subparsers.add_parser('init', help='Create project from firmware root filesystem archive')
    add_init_arguments(parser_cmd_init)

    parser_cmd_patch = subparsers.add_parser('patch', help='Patch a config file')
    add_patch_arguments(parser_cmd_patch)

    parser_cmd_run = subparsers.add_parser('run', help='Run from a config')
    add_run_arguments(parser_cmd_run)

    parser_cmd_docs = subparsers.add_parser('docs', help='Show documentation')
    add_docs_arguments(parser_cmd_docs)

    # NYI
    #parser_cmd_explore = subparsers.add_parser('explore', help='Explore configuration space')
    #add_explore_arguments(parser_cmd_explore)

    # Add help and --wrapper-help stub
    parser.add_argument('--wrapper-help', action='store_true', help='Show help for host penguin wrapper')


    args = parser.parse_args()

    # If cmd is unset show help
    if not args.cmd:
        parser.print_help()
        return

    if args.verbose:
        # Set level to debug
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    if args.cmd == "init":
        penguin_init(args)
    elif args.cmd == "run":
        penguin_run(args)
    elif args.cmd == "patch":
        penguin_patch(args)
    elif args.cmd == "docs":
        penguin_docs(args)
    elif args.cmd == "explore":
        raise NotImplementedError("Exploration not yet implemented")
        #penguin_explore(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
