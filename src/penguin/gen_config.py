import click
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import yaml
from pathlib import Path
from collections import Counter
from os.path import join, dirname
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import E_FLAGS, E_FLAGS_MASKS
from penguin import getColoredLogger
from .penguin_static import extend_config_with_static
from .penguin_config import dump_config
from .defaults import default_init_script, default_plugins, default_version, default_netdevs, default_pseudofiles, default_lib_aliases, static_dir, DEFAULT_KERNEL

logger = getColoredLogger("penguin.gen_confg")

def arch_end(value):
    arch = None
    end = None

    tmp = value.lower()
    if tmp.startswith("mips64"):
        arch = "mips64"
    elif tmp.startswith("mips"):
        arch = "mips"
    elif tmp.startswith("arm"):
        arch = "arm"
    if tmp.endswith("el"):
        end = "el"
    elif tmp.endswith("eb"):
        end = "eb"
    return (arch, end)

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

        logger.debug(f"Identified MIPS firmware: arch={mips_arch}, bits={bits}, abi={abi}, endian={endianness}, extras={description}")

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
            logger.debug(f"Checking architecture in {member.name}")
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

def make_config(fs, out, artifacts, timeout=None, auto_explore=False):
    logger.info(f"Generating new configuration for {fs}...")
    '''
    Given a filesystem as a .tar.gz make a configuration

    When called as a function return the path to the configuration.

    Timeout enforced if it's provided.
    If it's None and auto_explore is true, we'll use 300s

    Auto controls if we turn on nmap scanning (auto = yes)
    If niters is 1 we'll select a default init and set the /dev/gpio ioctl model to return 0
    (Otherwise we'll learn both of these dynamically)

    Returns the path to the config file.
    '''
    # If auto_explore we'll turn on zap and nmap to automatically generate coverage
    # Note that there's no way for a user to control that flag yet.

    if not os.path.isfile(fs):
        raise RuntimeError(f"FATAL: Firmware file not found: {fs}")

    if not fs.endswith(".tar.gz"):
        raise ValueError(f"Penguin should begin post extraction and be given a .tar.gz archive of a root fs, not {fs}")

    tmpdir = None
    if artifacts is None:
        tmpdir = tempfile.TemporaryDirectory()
        output_dir = tmpdir.name
    else:
        output_dir = Path(artifacts)
        output_dir.mkdir(exist_ok=True)

    # extract into output_dir/base/{image.qcow,fs.tar}
    arch_identified =  find_architecture(fs)
    if arch_identified is None:
        logger.error(f"Failed to determine architecture for {fs}")
        return
    arch, end = arch_end(arch_identified)

    kernel = static_dir + f"kernels/{DEFAULT_KERNEL}/" + ("zImage" if arch == "arm" else "vmlinux") + f".{arch}{end}"

    base_dir = Path(output_dir, "base")
    base_dir.mkdir(exist_ok=True, parents=True)
    base_fs = Path(base_dir, "fs.tar.gz")
    shutil.copy(fs, base_fs)
    data = {}
    data['core'] = {
        'arch': arch+end,
        'kernel': kernel,
        'fs': "./base/fs.tar.gz",
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

    if not auto_explore:
        # We want to build this configuration for a single-shot rehost.
        # We'll ensure it has an igloo_init set and we'll specify an ioctl model for all our pseudofiles in /dev
        logger.info(f"Tailoring configuration for single-iteration: selecting init and configuring default catch-all ioctl models")

        with open(f"{output_dir}/base/env.yaml", 'r') as f:
            static_env = yaml.safe_load(f)
            if 'igloo_init' in static_env and len(static_env['igloo_init']) > 0:
                data['env']['igloo_init'] = static_env['igloo_init'][0]
                logger.info(f"\tinit set to: {data['env']['igloo_init']}")
                if len(static_env['igloo_init']) > 1:
                    logger.debug(f"\tOther options are: {', '.join(static_env['igloo_init'][1:])}")

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

    # Write config to both output and base directories. Disable flow style and width
    # so that our multi-line init script renders the way we want
    for idx, outfile in enumerate([f"{output_dir}/base/initial_config.yaml",
                                   f"{output_dir}/config.yaml"]):
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
        default_out =  f"{output_dir}/base/config.yaml"
        if not shutil._samefile(outfile, default_out):
            shutil.copy(outfile, default_out)
        final_out = default_out

    if tmpdir:
        tmpdir.cleanup()

    return final_out

def fakeroot_gen_config(fs, out, artifacts, verbose):
    o = Path(out)
    cmd = ["fakeroot", "gen_config",
           "--fs", str(fs),
           "--out", str(o),
           "--artifacts", artifacts]
    if verbose:
        cmd.extend(["--verbose"])
    p = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()
    if o.exists():
        return str(o)

@click.command()
@click.option('--fs', required=True, help="Path to a filesystem as a tar gz")
@click.option('--out', required=True, help="Path to a config to be created")
@click.option('--artifacts', default=None, help="Path to a directory for artifacts")
@click.option('-v', '--verbose', count=True)
def makeConfig(fs, out, artifacts, verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)

    config = make_config(fs, out, artifacts)
    if not config:
        logger.error(f"Error! Could not generate config for {fs}")
    else:
        logger.info(f"Generated config at {config}")

if __name__ == "__main__":
    makeConfig()
