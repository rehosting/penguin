#!/usr/bin/env python3

import os
import shutil
import subprocess
import tarfile
from tempfile import TemporaryDirectory
from collections import Counter
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import E_FLAGS, E_FLAGS_MASKS
from os.path import join, dirname
from .penguin_static import extend_config_with_static
from .common import yaml
from .manager import graph_search, PandaRunner, report_best_results

from .defaults import default_init_script, default_plugins, default_version, default_netdevs, default_pseudofiles
from .utils import load_config, dump_config, arch_end

static_dir = "/igloo_static/"
DEFAULT_KERNEL = "4.10"

def get_mount_type(path):
    try:
        stat_output = subprocess.check_output(['stat', '-f', '-c', '%T', path])
        return stat_output.decode('utf-8').strip().lower()
    except subprocess.CalledProcessError:
        return None
def binary_filter(fsbase, name):
    base_directories = ["sbin","bin","usr/sbin","usr/bin"]
    for base in base_directories:
        if name.startswith(join(fsbase, base)):
            return True
    # might be good to add "*.so" to this list
    return name.endswith("busybox")

def arch_filter(header):
    supported_map = {
        "X86_64": "intel64",
        "386": "intel",
        "ARM": "armel",
        "AARCH64": "arm64",
        "PPC": "ppc",
        "PPC64": "ppc64",
    }

    if not isinstance(header.e_machine, str):
        # It's an int sometimes? That's no good
        return "unknown"

    arch = header.e_machine.replace("EM_","")

    if "EI_DATA" in header.e_ident:
        endianness = header.e_ident["EI_DATA"]
        if endianness == "ELFDATA2MSB":
            if arch != 'MIPS':
                # Only mips big endian is supported for now
                return arch + "EB"

    if arch in supported_map:
        return supported_map[arch]

    if arch == "MIPS":
        # Mips is more complicated. We could have 32 bit binaries that only run on a 64-bit
        # system (i.e., mips64 with the n32 ABI). Other permutations will likely cause issues
        # later so trying to future-proof this a bit. Masks/comparisons based off readelf.py
        # from PyElfTools.
        endianness = header.e_ident["EI_DATA"]
        bits = header.e_ident["EI_CLASS"]
        flags = header['e_flags']

        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
            mips_arch ="mips1"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_2:
            mips_arch ="mips2"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_3:
            mips_arch ="mips3"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_4:
            mips_arch ="mips4"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_5:
            mips_arch ="mips5"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32R2:
            mips_arch ="mips32r2"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64R2:
            mips_arch ="mips64r2"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_32:
            mips_arch ="mips32"
        if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_64:
            mips_arch ="mips64"


        if (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O32):
            abi = "o32"
        elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O64):
            abi = "o64" # never seen this before - unsupported for now?
        elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI32):
            abi = "n32"
        elif (flags & E_FLAGS_MASKS.EFM_MIPS_ABI_EABI64):
            abi = "n64"
        else:
            abi = None

        # Some extra flags that only affect what gets printed
        description = 'mips'
        if flags & E_FLAGS.EF_MIPS_NOREORDER:
            description += ", noreorder"
        if flags & E_FLAGS.EF_MIPS_PIC:
            description += ", pic"
        if flags & E_FLAGS.EF_MIPS_CPIC:
            description += ", cpic"
        if (flags & E_FLAGS.EF_MIPS_ABI2):
            description += ", abi2"
        if (flags & E_FLAGS.EF_MIPS_32BITMODE):
            description += ", 32bitmode"

        if mips_arch.startswith('mips64'):
            bits = 64
        else:
            bits = 32

        #print(f"Identified MIPS firmware: arch={mips_arch}, bits={bits}, abi={abi}, endian={endianness}, extras={description}")

        if bits == 32:
            if endianness == "ELFDATA2LSB":
                return "mipsel"
            else:
                return "mipseb"

        # 64 bits
        return "mips64eb"

    return "unknown"

def find_architecture(infile):
    tf = tarfile.open(infile)
    fsbase = tf.firstmember.path
    arch_counts = Counter()
    for member in tf.getmembers():
        if member.isfile() and binary_filter(fsbase, member.name):
            #print(f"Checking architecture in {member.name}")
            member_file = tf.extractfile(member.name)
            if member_file.read(4) != b'\x7fELF':
                continue
            member_file.seek(0)
            ef = ELFFile(member_file)
            arch_counts[arch_filter(ef.header)] += 1

            # If we have a sum of >= 10 in our counter, we can stop, we've seen enough
            if sum(arch_counts.values()) >= 10:
                break

    # Now select the most common architecture
    if len(arch_counts) == 0:
        return None
    return arch_counts.most_common(1)[0][0]

def _build_image(fs_tar_gz, output_dir, static_dir):
    def _makeImage(_output_dir):
        # Build our fakeroot command to run makeImage with a dynamic output directory
        cmd = ["fakeroot", os.path.join(*[dirname(dirname(__file__)), "scripts", "makeImage.sh"]),
                fs_tar_gz,
                _output_dir]
        # Check output and report it on error
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            # Also print the command we ran
            print(" ".join(cmd))

            print(e.output.decode('utf-8'))
            if e.stderr:
                print(e.stderr.decode('utf-8'))
            raise e

    if os.path.isdir(output_dir):
        try:
            os.rmdir(output_dir)
        except OSError:
            raise RuntimeError(f"Output directory {output_dir} already exists and is not empty. Refusing to destroy")

    # If we ever change makeImage back to extracting the archive, we'll want to restore old logic
    # to check if output directory is mounted lustre-fs and if so, use $TMPDIR to do our extraction
    # to avoid permissions issues in extraction
    os.mkdir(output_dir)
    _makeImage(output_dir)

def extract_and_build(fw, output_dir):
    base = os.path.join(output_dir, "base")
    os.makedirs(base)

    if not fw.endswith(".tar.gz"):
        raise ValueError(f"Penguin should begin post extraction and be given a .tar.gz archive of a root fs, not {fw}")

    if not os.path.isfile(fw):
        raise ValueError(f"Rootfs file {fw} not found")

    if not (arch_identified := find_architecture(fw)):
        raise Exception("Unable to determine architecture of rootfs")

    if arch_identified not in ["mipseb", "mipsel", "armel"]:
        #raise Exception(f"Architecture {arch_identified} unsupported")
        with open(f"{output_dir}/result", 'w') as f:
            f.write(f"unsupported arch: {arch_identified}")
        return None, None

    print(f"Identified architecture as {arch_identified}")
    arch, endianness = arch_end(arch_identified)
    if not arch or not endianness:
        raise Exception("Arch_end fails to parse {arch_identified}")

    # Generate a qcow image in output_dir/base/image.qcow
    _build_image(fw, base, static_dir)

    if not os.path.isfile(f"{base}/image.qcow"):
        raise Exception("Failed to generate qcow image with MakeImage")

    # Make our base qcow image read-only
    os.chmod(f"{base}/image.qcow", 0o444)
    return arch, endianness

def build_config(firmware, output_dir, auto_explore=False, use_vsock=True, timeout=None):
    '''
    Given a firmware binary and an output directory, this function will
    extract the firmware, build a qemu image, and create a config file
    in output_dir/base/config.yaml.

    Timeout enforced if it's provided.
    If it's None and auto_explore is true, we'll use 300s

    Returns the path to the config file.
    '''
    # If auto_explore we'll turn on zap and nmap to automatically generate coverage
    # Note that there's no way for a user to control that flag yet.

    if not os.path.isfile(firmware):
        raise RuntimeError(f"FATAL: Firmware file not found: {firmware}")

    #if os.path.isdir(output_dir):
    #    raise RuntimeError(f"FATAL: Output directory already exists: {output_dir}. Refusing to destroy")

    # extract into output_dir/base/{image.qcow,fs.tar}
    arch, end = extract_and_build(firmware, output_dir)
    if arch is None:
        return None

    kernel = static_dir + f"kernels/{DEFAULT_KERNEL}/" + ("zImage" if arch == "arm" else "vmlinux") + f".{arch}{end}"

    data = {}
    data['core'] = {
        'arch': arch+end,
        'kernel': kernel,
        'fs': os.path.join(output_dir, "base/fs.tar"),
        'qcow': os.path.join(output_dir, "base/image.qcow"),
        'root_shell': True,
        'show_output': False,
        'strace': False,
        #'netdevnames': ['eth0', 'eth1', 'eth2', 'eth3', 'wlan0', 'wlan1'], # This doesn't seem to be good
        'version': default_version,
    }

    data['blocked_signals'] = []
    data['netdevs'] = default_netdevs

    data['env'] = {}
    data['pseudofiles'] = default_pseudofiles

    data['static_files'] = {
        "/igloo/init": {
            'type': "file",
            'contents': default_init_script,
            'mode': 0o111,
        },
        '/igloo/utils/sh': {
            "type": "symlink",
            'target': "/igloo/utils/busybox",
        },
        '/igloo/utils/sleep': {
            'type': "symlink",
            'target': "/igloo/utils/busybox",
        },
    }

    data['static_files']["/igloo/keys/"] = {
        'type': "dir",
        'mode': 0o755,
    }
    for f in os.listdir(os.path.join(*[dirname(dirname(__file__)), "resources", "static_keys"])):
        data['static_files'][f"/igloo/keys/{f}"] = {
            'type': "file",
            #'contents': open(static_dir + f"static_keys/{f}", 'rb').read(),
            'hostpath': os.path.join(*[dirname(dirname(__file__)), "resources", "static_keys", f]),
            'mode': 0o444,
        }

    #for t in "console" "libnvram" "utils.bin" "utils.source" "vpn"; do
    #    UTILS="$STATIC_DIR/$t"
    #    [ -d "$UTILS" ] || { echo "FATAL: Missing utilities directory $UTILS" >&2; exit 1; }
    #
    #    for f in "$UTILS"/*.${ARCH} "$UTILS"/*.all; do
    #        [ -e "$f" ] || { echo "WARN: No files matching pattern $f"; continue; }
    #        fname=$(basename "$f")
    #        dest="${IGLOO}/utils/${fname%.*}"
    #        cp "$f" "$dest"
    #        chmod +x "$dest"
    #    done
    #done
    data['static_files']["/igloo"] = {
        'type': "dir",
        'mode': 0o755,
    }
    data['static_files']["/igloo/utils"] = {
        'type': "dir",
        'mode': 0o755,
    }

    arch_suffix = f".{arch}{end}"

    for util_dir in ["console", "libnvram", "utils.bin", "utils.source", "vpn"]:
        for f in os.listdir(join(static_dir, util_dir)):
            if f.endswith(arch_suffix) or f.endswith(".all"):
                out_name = f.replace(arch_suffix, "").replace(".all", "")
                data['static_files'][f"/igloo/utils/{out_name}"] = {
                    'type': "file",
                    'hostpath': f"/igloo_static/{util_dir}/{f}",
                    'mode': 0o755,
                }


    data['plugins'] =  default_plugins

    # Explicitly placing this at the end
    data['nvram'] = {}

    if not use_vsock:
        # Without vsock you can't have the VPN
        data['plugins']['vpn']['enabled'] = False

    if auto_explore:
        # If auto_explore, we'll enable extra plugins to generate coverage - unless we're told the VPN is disabled.
        if 'vpn' in data['plugins'] and data['plugins']['vpn'].get('enabled', True):
            # If we have VPN (which we will if we have vsock), turn on zap and nmap
            for p in ['nmap', 'zap']:
                if p in data['plugins']:
                    data['plugins'][p]['enabled'] = True

        # Also disable root shell and set timeout to 5 minutes (unless told otherwise)
        data['core']['root_shell'] = False
        data['plugins']['core']['timeout'] = timeout if timeout else 300
    else:
        # Interactive, let's enable root shell and fully delete some plugins
        data['core']['root_shell'] = True
        for p in ['zap', 'nmap', 'health', 'shell', 'coverage', 'env', 'interfaces']:
            if p in data['plugins']:
                del data['plugins'][p]

    # Make sure we have a base directory to store config
    # and static results in.
    if not os.path.isdir(os.path.join(output_dir, "base")):
        os.makedirs(os.path.join(output_dir, "base"))

    # If we create files (e.g., base/*.yaml, output/*.yaml), we want them to be
    # readable/writable by everyone since non-container users will want to access them
    os.umask(0o000)

    data = extend_config_with_static(data, f"{output_dir}/base/", auto_explore)

    if auto_explore and 'igloo_init' in data['env']:
        # Make sure we didn't set an igloo_init in our env if there are multiple potential values
        with open(f"{output_dir}/base/env.yaml", 'r') as f:
            static_env = yaml.safe_load(f)
            if 'igloo_init' in static_env:
                if len(static_env['igloo_init']) > 1:
                    del data['env']['igloo_init']

    # Data includes 'meta' field with hypotheses about files/devices
    # Let's drop that. It's stored in base/{env,files}.yaml
    if 'meta' in data:
        del data['meta']

    # Write config to both output and base directories. Disable flow style and width
    # so that our multi-line init script renders the way we want
    for idx, outfile in enumerate([f"{output_dir}/base/initial_config.yaml",
                                   f"{output_dir}/config.yaml"]):
        if idx == 1 and os.path.isfile(outfile):
            # Don't clobber existing config.yaml in main output dir
            # (but do clobber the initial_config.yaml in base if it exists)
            print(f"Not overwriting existing config file: {outfile}")
            continue
        dump_config(data, outfile)

    # Config is a path to output_dir/base/config.yaml
    return f"{output_dir}/config.yaml"

def run_from_config(config_path, output_dir, niters=1, nthreads=1, timeout=None):
    if not os.path.isfile(config_path):
        raise RuntimeError(f"Config file not found: {config_path}")

    config = load_config(config_path)

    if not os.path.isfile(config['core']['qcow']):
        # The config specifies where the qcow should be. Generally this is in
        # the base directory, but it could be elsewhere.
        raise RuntimeError(f"Base qcow not found: {config['core']['qcow']}")

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
            else:
                raise RuntimeError(f"Static analysis failed to identify an init script. Please specify one in {output_dir}/config.yaml and run again with --config.")

    run_base = os.path.dirname(output_dir)
    PandaRunner().run(config_path, run_base, run_base, output_dir, init=init, timeout=timeout)
    report_best_results(run_base, os.path.join(run_base, "output"), os.path.dirname(output_dir))

def main():
    from sys import argv
    import argparse

    # Create the parser
    parser = argparse.ArgumentParser(description="""

    Configuration based firmware rehosting. Penguin can generate configs from a firmware or run a config.

        EXAMPLE USAGE:
            # First generate a config for firmware.bin at /output/myfirmware/config.yaml
            penguin /fws/firmware.bin /results/myfirmware

            # Then run with that config and log results to the results directory
            penguin --config /results/myfirmware/config.yaml /results/myfirmware/results
        """,
        formatter_class=argparse.RawTextHelpFormatter)


    parser.add_argument('--config', type=str, help='Path to a config file. If set, the firmware argument is not required.')
    parser.add_argument('--nthreads', type=int, default=1, help='Number of workers to use (not actually threads). Default 1.')
    parser.add_argument('--novsock', action='store_true', default=False, help='Run running without vsock. Disabled by default')
    parser.add_argument('--timeout', type=int, default=None, help='Timeout in seconds for each run. Default is 300s if auto-explore or no timeout otherwise')

    parser.add_argument('--auto', action='store_true', default=False, help="Automatically explore the provided firmware for niters. Configuration will be generated with automation plugins enabled. Meaningless with --config. Default False.")
    parser.add_argument('--niters', type=int, default=1, help='How many interations to run. Default 1')
    parser.add_argument('--force', action='store_true', default=False, help="Forcefully delete output directory")

    parser.add_argument('firmware', type=str, nargs='?', help='The firmware path. Required if --config is not set, otherwise this must not be set.')
    parser.add_argument('output_dir', type=str, help='The output directory path.')

    args = parser.parse_args()

    if not args.config and not args.firmware:
        # We must have either a config or a firmware
        parser.error("you must specify a config file (with --config) or a firmware file.")

    if args.config and args.firmware:
        # Can't have both
        parser.error("you provided both a config file and a firmware file. Please choose one.")

    if not args.novsock and not os.path.exists("/dev/vhost-vsock"):
        raise RuntimeError("FATAL: No vsock device found. Please load the vhost_vsock"\
                            " module. Or run with --novsock if you want to run "\
                            " without networking")

    if args.config and args.niters == 0:
        # Nothing to do if you have a config and niters is 0
        parser.error("you provided a config file and set niters=0. That won't do anything")

    if args.force and os.path.isdir(args.output_dir):
        shutil.rmtree(args.output_dir, ignore_errors=True)

    if not args.config:
        # We don't have a config. Generate one.
        # Set up for auto exploration if --auto
        print(f"Generating config for {args.firmware}")

        if args.firmware.endswith(".yaml"):
            # We were given a config, not a firmware
            raise RuntimeError("FATAL: It looks like provided a config file ending with .yaml."\
                               "Please provide a firmware file or run with --config to "\
                               "use the config file.")

        args.config = build_config(args.firmware, args.output_dir, auto_explore=args.auto, use_vsock=not args.novsock, timeout=args.timeout)

        if args.config is None:
            # We failed to generate a config. We'll have written a result file to the output dir
            print(f"Failed to generate config for {args.firmware}. See {args.output_dir}/result for details.")
            return

        # If we were given a firmware, by default we won't run it, but if niters != 1, we will
        if args.auto and args.niters > 0:
            print(f"Running {args.niters} run(s) from {args.config} with {args.nthreads} thread(s). Storing results in {args.output_dir}/runs")

            # XXX we behave diffrently if niters is 1 in run_from_config. If niters is one we'll spit results into /output
            # otherwise we'll do runs/X/output
            output_dir = os.path.join(args.output_dir, "output") if args.niters == 1 else args.output_dir
            run_from_config(os.path.join(args.output_dir, "config.yaml"), output_dir, niters=args.niters, nthreads=args.nthreads, timeout=args.timeout)

    else:
        # We have a config. Run for the specified number of iterations
        print(f"Running {args.niters} run(s) from {args.config} with {args.nthreads} thread(s)")
        run_from_config(args.config, args.output_dir, niters=args.niters, nthreads=args.nthreads)


if __name__ == "__main__":
    main()
