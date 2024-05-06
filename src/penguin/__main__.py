#!/usr/bin/env python3

import os
import shutil
import subprocess
import tarfile
import logging
import coloredlogs
from pathlib import Path
from tempfile import TemporaryDirectory
from collections import Counter
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import E_FLAGS, E_FLAGS_MASKS
from os.path import join, dirname
from .penguin_static import extend_config_with_static
from .common import yaml
from .manager import graph_search, PandaRunner, report_best_results, calculate_score

from .defaults import default_init_script, default_plugins, default_version, default_netdevs, default_pseudofiles, default_lib_aliases
from .utils import load_config, dump_config, arch_end

coloredlogs.install(level='INFO', fmt='%(asctime)s %(name)s %(levelname)s %(message)s')
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

    # If our enviornment specifies a TEMP_DIR (e.g., LLSC) we should do the unpacking in there
    # to avoid issues with NFS and get better perf. At the end we just move result to output
    if get_mount_type(dirname(output_dir)) == "lustre":
        # This FS doesn't support the operations we need to do in converting raw->qcow. Instead try using /tmp
        if "ext3" not in get_mount_type("/tmp"):
            raise RuntimeError("Incompatible filesystem. Neither output_dir nor /tmp are ext3")

        # Copy the tar.gz to tempdir, makeImage, then move to output_dir
        with TemporaryDirectory() as temp_dir:
            shutil.copy(fs_tar_gz, temp_dir)
            _makeImage(temp_dir)
            os.unlink(os.path.join(temp_dir, os.path.basename(fs_tar_gz))) # Don't leave input .tar.gz in base, we already have fs.tar
            shutil.copytree(temp_dir, output_dir)
    else:
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

    if arch_identified not in ["mipseb", "mipsel", "armel", "mips64eb"]:
        #raise Exception(f"Architecture {arch_identified} unsupported")
        with open(f"{output_dir}/result", 'w') as f:
            f.write(f"unsupported arch: {arch_identified}\n")
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

def build_config(firmware, output_dir, auto_explore=False, timeout=None, niters=1, derive_from=None):
    '''
    Given a firmware binary and an output directory, this function will
    extract the firmware, build a qemu image, and create a config file
    in output_dir/base/config.yaml.

    Timeout enforced if it's provided.
    If it's None and auto_explore is true, we'll use 300s

    Auto controls if we turn on nmap scanning (auto = yes)
    If niters is 1 we'll select a default init and set the /dev/gpio ioctl model to return 0
    (Otherwise we'll learn both of these dynamically)

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
        'fs': "base/fs.tar",
        'qcow': "base/image.qcow",
        'root_shell': True,
        'show_output': False,
        'strace': False,
        'version': default_version,
    }

    data['blocked_signals'] = []
    data['netdevs'] = default_netdevs

    data['env'] = {}
    data['pseudofiles'] = default_pseudofiles
    data['lib_inject'] = {'aliases': default_lib_aliases}

    data['static_files'] = {
        "/igloo/init": {
            'type': "inline_file",
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
            'type': "host_file",
            #'contents': open(static_dir + f"static_keys/{f}", 'rb').read(),
            'host_path': os.path.join(*[dirname(dirname(__file__)), "resources", "static_keys", f]),
            'mode': 0o444,
        }

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
                    'type': "host_file",
                    'host_path': f"/igloo_static/{util_dir}/{f}",
                    'mode': 0o755,
                }

    data['plugins'] =  default_plugins

    # Explicitly placing this at the end
    data['nvram'] = {}

    if auto_explore:
        # If auto_explore, we'll enable extra plugins to generate coverage - unless we're told the VPN is disabled.
        if 'vpn' in data['plugins'] and data['plugins']['vpn'].get('enabled', True):
            # If we have VPN (which we will if we have vsock), turn on zap and nmap
            for p in ['nmap']:
                if p in data['plugins']:
                    data['plugins'][p]['enabled'] = True

        # Also disable root shell and set timeout to 5 minutes (unless told otherwise)
        data['core']['root_shell'] = False
        data['plugins']['core']['timeout'] = timeout if timeout else 300
    else:
        # Interactive, let's enable root shell and fully delete some plugins
        data['core']['root_shell'] = True
        for p in ['zap', 'nmap' 'coverage']:
            if p in data['plugins']:
                del data['plugins'][p]

    # Make sure we have a base directory to store config
    # and static results in.
    if not os.path.isdir(os.path.join(output_dir, "base")):
        os.makedirs(os.path.join(output_dir, "base"))

    # If we create files (e.g., base/*.yaml, output/*.yaml), we want them to be
    # readable/writable by everyone since non-container users will want to access them
    os.umask(0o000)

    data = extend_config_with_static(output_dir, data, f"{output_dir}/base/", auto_explore)

    if niters == 1:
        # We want to build this configuration for a single-shot rehost.
        # We'll ensure it has an igloo_init set and we'll specify an ioctl model for all our pseudofiles in /dev
        print(f"Tailoring configuration for single-iteration: selecting init and configuring default catch-all ioctl models")

        with open(f"{output_dir}/base/env.yaml", 'r') as f:
            static_env = yaml.safe_load(f)
            if 'igloo_init' in static_env and len(static_env['igloo_init']) > 0:
                data['env']['igloo_init'] = static_env['igloo_init'][0]
                print(f"\tinit set to: {data['env']['igloo_init']}")
                if len(static_env['igloo_init']) > 1:
                    print(f"\tOther options are: {', '.join(static_env['igloo_init'][1:])}")

        # For all identified pseudofiles, try adding them. This reliably causes kernel panics - are we running
        # out of kernel memory or are we clobbering important things?
        '''
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
        '''

        # Now we'll set a default ioctl model for all our pseudofiles in /dev
        for dev in data['pseudofiles']:
            if dev.startswith("/dev/"):
                data['pseudofiles'][dev]['ioctl'] = {
                    '*': {
                            "model": "return_const",
                            "val": 0,
                        }
                }

    else:
        # Automated mode

        # Turn on force_www -> it will probably help?
        data['core']['force_www'] = True

        # Make sure we dont' have an igloo_init set
        if 'igloo_init' in data['env']:
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

    # If we have a derive_from, we'll load it and update our data with it
    if derive_from:
        if not os.path.isfile(derive_from):
            raise RuntimeError(f"Derive_from file not found: {derive_from}")

        print(f"Refining configuration with provided configuration overrides {derive_from}")
        with open(derive_from, 'r') as f:
            data.update(yaml.safe_load(f))

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

    proj_dir = os.path.dirname(config_path)

    try:
        config = load_config(config_path)
    except UnicodeDecodeError:
        raise RuntimeError(f"Config file {config_path} is not a valid unicode YAML file. Is it a firmware file instead of a configuration?")

    if not os.path.isfile(os.path.join(proj_dir, config['core']['qcow'])):
        # The config specifies where the qcow should be. Generally this is in
        # the base directory, but it could be elsewhere.
        raise RuntimeError(f"Base qcow not found in project {proj_dir}: {config['core']['qcow']}")

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
                print(f"Config does not specify init. Selecting first option: {init}." + ((" Other options are: " + ", ".join(env['igloo_init'][1:])) if len(env['igloo_init']) > 1 else ""))
            else:
                raise RuntimeError(f"Static analysis failed to identify an init script. Please specify one in {output_dir}/config.yaml and run again with --config.")

    # XXX is this the right run_base? It's now our project dir
    proj_dir = os.path.dirname(config_path)
    print(f"Generating initial filesystem and launching emulation. Please wait a minute")
    PandaRunner().run(config_path, proj_dir, output_dir, init=init, timeout=timeout, show_output=True) # niters is 1

    # Single iteration: there is not best - don't report that
    #report_best_results(run_base, output_dir, os.path.dirname(output_dir))

    # But do calculate and report scores. Unlike multi-run mode, we'll write scores right into output dir instead of in parent
    best_scores = calculate_score(output_dir)
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
    parser.add_argument('--derive_from', type=str, help='Baseline YAML configuration to override defaults when generating a new config', default=None)
    parser.add_argument('--force', action='store_true', default=False, help="Forcefully delete project directory if it exists")
    parser.add_argument('--output_base', type=str, help="Default project directory base. Default is 'projects'", default="projects")

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
        print(f"Creating project at generated path: {args.output}")
    else:
        print(f"Creating project at specified path: {args.output}")

    if args.force and os.path.isdir(args.output):
        print(f"Deleting existing project directory: {args.output}")
        shutil.rmtree(args.output, ignore_errors=True)

    # Ensure output parent directory exists
    if not os.path.exists(os.path.dirname(args.output)):
        os.makedirs(os.path.dirname(args.output))

    config = build_config(args.rootfs, args.output, auto_explore=False, timeout=None, niters=1,derive_from=args.derive_from)

    if not config:
        # We failed to generate a config. We'll have written a result file to the output dir
        print(f"Failed to generate config for {args.rootfs}. See {args.output}/result for details.")

def add_patch_arguments(parser):
    parser.add_argument('config', type=str, help='Path to the full config file to be updated')
    parser.add_argument('patch', type=str, help='Path to the config patch')

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

def add_run_arguments(parser):
    parser.add_argument('config', type=str, help='Path to a config file within a project directory.')
    parser.add_argument('--output', type=str, help='The output directory path. Defaults to results/X in project directory where X auto-increments.', default=None)
    parser.add_argument('--force', action='store_true', default=False, help="Forcefully delete output directory if it exists.")

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

    logger = logging.getLogger("PENGUIN")
    logger.info(f"Running config {args.config}")
    logger.info(f"Saving results to {args.output}")

    if '/host_' in args.config or '/host_' in args.output:
        logger.info("Note messages referencing /host paths reflect automatically-mapped shared directories based on your command line arguments")


    run_from_config(args.config, args.output)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="""
    Configuration based firmware rehosting. PENGUIN can generate a project with a configuration for a firmware,
    run a rehosting as specified in a config, or automatically refine a configuration.

    # First generate a project for a given FW root filesystem which creates
    # a config file and other artifactrs in results/myfirmware/
    penguin init myfirmware.bin --output projects/myfirmware

    # Then run with that config and log results to the results directory
    penguin run projects/myfirmware/config.yaml projects/myfirmware/results/myresults
    """,
    formatter_class=argparse.RawTextHelpFormatter)

    subparsers = parser.add_subparsers(help='subcommand', dest='cmd')

    parser_cmd_init = subparsers.add_parser('init', help='Create project from firmware root filesystem archive')
    add_init_arguments(parser_cmd_init)

    parser_cmd_patch = subparsers.add_parser('patch', help='Patch a config file')
    add_patch_arguments(parser_cmd_patch)

    parser_cmd_run = subparsers.add_parser('run', help='Run from a config')
    add_run_arguments(parser_cmd_run)

    # NYI
    #parser_cmd_explore = subparsers.add_parser('explore', help='Explore configuration space')
    #add_explore_arguments(parser_cmd_explore)

    # Add help and --wrapper-help stub
    parser.add_argument('--wrapper-help', action='store_true', help='Show help for host penguin wrapper')

    args = parser.parse_args()
    if args.cmd == "init":
        penguin_init(args)
    elif args.cmd == "run":
        penguin_run(args)
    elif args.cmd == "patch":
        penguin_patch(args)
    elif args.cmd == "explore":
        raise NotImplementedError("Exploration not yet implemented")
        #penguin_explore(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
