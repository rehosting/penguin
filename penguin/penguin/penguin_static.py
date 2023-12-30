import tarfile
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from copy import deepcopy

from .common import yaml

'''
Given a config with a filesystem .tar, analyze
the filesystem and populate metadata fields
    - potential_init: list of potential init scripts
    - potential_dev: list of potential device files
    - potential_env: dict of potential environment variables (keys = None or list of values)
    - potential_proc: list of potential /proc/ files
'''


def _find_in_fs(target_regex, tar_path, only_files=True):
    '''
    Given a regex pattern to match against, search the filesystem
    and track matches + counts.
    Returns a dict of {match: {count: int, files: [str]}
    '''
    results = {}

    boring_vars = ["TERM"]

    # Open tar archive
    with tarfile.open(tar_path, 'r') as tar:
        # Iterate through each file in the tar archive
        for member in tar.getmembers():
            # Skip our files
            if member.path.startswith('./igloo'):
                continue

            # Skip directories and non-regular files
            if only_files and not member.isfile():
                continue
            
            # Open file
            f = tar.extractfile(member)
            if f is None:
                continue

            # Read content and convert to string
            content = f.read().decode('utf-8', 'replace')
            
            # Apply regex pattern
            matches = target_regex.findall(content)
            for match in matches:
                if match not in results and match not in boring_vars:
                    results[match] = {'count': 0, 'files': []}

                results[match]['count'] += 1
                results[match]['files'].append(member.name)
    return results

def _get_devfiles_in_fs(tar_path):
    '''
    Get a list of all device files in the filesystem
    '''
    results = set()

    # Open tar archive
    with tarfile.open(tar_path, 'r') as tar:
        # Iterate through each file in the tar archive
        for member in tar.getmembers():
            if not member.path.startswith('./dev/'):
                continue
            results.add(member.path[1:])
    return results


def get_directories_from_tar(tarfile_path):
    with tarfile.open(tarfile_path, "r") as tar:
        # Trim leading . from path, everything is ./
        results = {member.name[1:] for member in tar.getmembers() if member.isdir()}
    # For each result, recursively add all parent directories
    # e.g., /etc/hosts -> /etc, /
    for r in list(results):
        parts = r.split('/')
        for i in range(len(parts)):
            results.add('/'.join(parts[:i+1]))
    return results

def get_files_from_tar(tarfile_path):
    with tarfile.open(tarfile_path, "r") as tar:
        return {member.name for member in tar.getmembers() if member.isfile()}

def find_strings_in_file(file_path, pattern):
    result = subprocess.run(['strings', file_path], capture_output=True, text=True)
    #return [line for line in result.stdout.splitlines() if pattern in line]
    # Pattern is a regex
    return [line for line in result.stdout.splitlines() if re.search(pattern, line)]

def find_executables(tmp_dir, target_dirs=None):
    if not target_dirs:
        target_dirs = {'/'}
    for root, dirs, files in os.walk(tmp_dir):
        # Exclude the '/igloo' path
        if '/igloo' in root:
            continue
        
        for file in files:
            file_path = Path(root) / file
            # Check if the file is executable and in one of the target directories
            if file_path.is_file() and os.access(file_path, os.X_OK) and any(str(file_path).endswith(d) for d in target_dirs):
                yield file_path

def find_shell_scripts(tmp_dir):
    for root, dirs, files in os.walk(tmp_dir):
        # Exclude the '/igloo' path
        if '/igloo' in root:
            continue
        
        for file in files:
            file_path = Path(root) / file
            # Check if the file is executable and in one of the target directories
            if file_path.is_file() and os.access(file_path, os.X_OK) and str(file_path).endswith('.sh'):
                yield file_path

def pre_shim(config):
    '''
    Static modifications to filesystem. Make directories that we think are missing, add some standard files.
    Update config with these suggested changes.
    '''
    fs_path = config['core']['fs'] # tar archive

    # Directories we want to make sure exist in the FS. This list is based on firmadyne and firmae. Added /dev explicitly because we need
    # it for devtmpfs (e.g., devtmpfs could try mounting before /igloo/init runs and makes the directory)
    directories = ["/dev", "/proc", "/dev/pts", "/etc_ro", "/tmp", "/var", "/run", "/sys", "/root", "/tmp/var", "/tmp/media", "/tmp/etc",
                    "/tmp/var/run", "/tmp/home", "/tmp/home/root", "/tmp/mnt", "/tmp/opt", "/tmp/www", "/var/run", "/var/lock",
                    "/usr/bin", "/usr/sbin"]

    existing_dirs = get_directories_from_tar(fs_path)

    for d in directories:
        if d in existing_dirs:
            continue
        config["static_files"][d] = {
            'type': 'dir',
            'mode': 0o755
        }

    # Temporary directory for tar file extraction
    with tempfile.TemporaryDirectory() as tmp_dir:
        tar = tarfile.open(fs_path)
        tar.extractall(path=tmp_dir)
        tar.close()
        
        # FIRMAE_BOOT mitigation: find path strings in binaries, make their directories if they don't already exist
        for f in find_executables(tmp_dir, {'/bin', '/sbin', '/usr/bin', '/usr/sbin'}):
            # For things that look like binaries, find unique strings that look like paths
            for dest in list(set(find_strings_in_file(f, '^(/var|/etc|/tmp)(.+)([^\/]+)$'))):
                if any([x in dest for x in ['%s', '%c', '%d', '/tmp/services']]):
                    # Ignore these paths, printf format strings aren't real directories to create
                    # Not sure what /tmp/services is or where we got that from?
                    continue

                config['static_files'][dest] = {
                    'type': 'dir',
                    'mode': 0o755
                }

        
        # CUSTOM mitigation: Try adding referenced mount points
        for f in find_shell_scripts(tmp_dir):
            for dest in list(set(find_strings_in_file(f, '^/mnt/[a-zA-Z0-9._/]+$'))):
                config['static_files'][dest] = {
                    'type': 'dir',
                    'mode': 0o755
                }

        # If /etc/tz is missing, add it
        if not os.path.isfile(tmp_dir + '/etc/tz'):
            config['static_files']['/etc/tz'] = {
                'type': 'file',
                'contents': 'EST5EDT',
                'mode': 0o755
            }

        # If no /bin/sh, add it as a symlink to /bin/busybox
        if not os.path.isfile(tmp_dir + '/bin/sh'):
            config['static_files']['/bin/sh'] = {
                'type': 'symlink',
                'target': '/igloo/utils/busybox',
            }

        # Find any files named insmod or modprobe, we want to replace these with symlinks to exit0
        #for INSMOD in $(find "$TMP_DIR" -xdev -type f,l -executable \( -name "insmod" -o -name "modprobe" \)); do
        for f in find_executables(tmp_dir):
            if os.path.basename(f) in ['insmod', 'modprobe']:
                config['static_files'][f] = {
                    'type': 'symlink',
                    'target': '/igloo/utils/exit0.sh',
                }

		# Ensure we have an entry for localhost in /etc/hosts
        hosts = ""
        if os.path.isfile(tmp_dir + '/etc/hosts'):
            with open(tmp_dir + '/etc/hosts', 'r') as f:
                hosts = f.read()
        #if '127.0.0.1 localhost' not in hosts:
        # Regex with whitespace and newlines
        if not re.search(r'^127\.0\.0\.1\s+localhost\s*$', hosts, re.MULTILINE):
            if not hosts.endswith('\n'):
                hosts += "\n"
            hosts += "127.0.0.1 localhost\n"
            config['static_files']['/etc/hosts'] = {
                'type': 'file',
                'contents': hosts,
                'mode': 0o755,
            }

        # Linksys specific hack from firmae
        if all(os.path.isfile(tmp_dir + x) for x in ['/bin/gpio', '/usr/lib/libcm.so', '/usr/lib/libshared.so']):
            config['pseudofiles']['/dev/gpio/in'] = {
                'read': {
                    'model': 'return_const',
                    'value': 0xffffffff,
                }
            }

		# Delete some files that we don't want. securetty is general, limits shell access. Sys_resetbutton is some FW-specific hack?
        for f in ['/etc/securetty', '/etc/scripts/sys_resetbutton']:
            if os.path.isfile(tmp_dir + f):
                config['static_files'][f] = {
                    'type': 'delete',
                }

        # NVRAM specific hacks
        for (file, query, value) in [
                ('/sbin/rc', 'ipv6_6to4_lan_ip', 'ipv6_6to4_lan_ip=2002:7f00:0001::'),
                ('/lib/libacos_shared.so', 'time_zone_x', 'time_zone_x=0'),
                ('/usr/sbin/httpd', 'rip_multicast', 'rip_multicast=0'),
                ('/usr/sbin/httpd', 'bs_trustedip_enable', 'bs_trustedip_enable=0'),
                ('/usr/sbin/httpd', 'filter_rule_tbl', 'filter_rule_tbl='),
                ('/sbin/acos_service', 'rip_enable', 'rip_enable=0')]:

            if os.path.isfile(tmp_dir + file):
                with open(tmp_dir + file, 'r') as f:
                    if query in f.read():
                        config['nvram'][query] = value

def _kernel_version_to_int(potential_name):
    try:
        # Seems like a kernel version! Let's compare to existing value.
        # Treat major version as an 10 000x, minor as 100x, patch as 1x
        # e.g., 4.4.0 -> 40 40 0
        comps = [int(x) for x in potential_name.split(".")]
    except ValueError:
        return None
    return comps[0] * 10000 + comps[1] * 100 + comps[2]


def shim_configs(config):
    '''
    Identify binaries in the guest FS that we want to shim
    and add symlinks to go from guest bin -> igloo bin
    into our config.

    '''
    fs_path = config['core']['fs'] # tar archive

    # (guest bin, path relative to /igloo/utils)
    shim_targets = [('ssh-keygen', 'ssh-keygen'), ('openssl', 'openssl'), ('sh', 'busybox'), ('bash', 'busybox')]
    shim_results = {}
    target_exists = {t[1]: False for t in shim_targets}

    # Does the file exist in the FS tar?
    with tarfile.open(fs_path) as fs:
        for fname in fs.getmembers(): # getmembers for full path
            path = fname.path[1:] # Trim leading .
            basename = os.path.basename(path)

            if path.startswith("/igloo/"):
                # It's an igloo added file. Update state so we can track if we're missing any shim targets
                igloo_match = [x for x in shim_targets if x[1] == basename] # 
                if len(igloo_match):
                    target_exists[igloo_match[0][1]] = True
            else:
                # It's a non-igloo path. If it's one of our targets, store it's path -> shim
                guest_match = [x for x in shim_targets if x[0] == basename]
                if len(guest_match):
                    shim_results[path] = f"/igloo/utils/{guest_match[0][1]}"

    # Sanity check: make sure all of our target destinations exist
    for k, found_in_fs in target_exists.items():
        if not found_in_fs:
            raise ValueError(f"penguin_static adds shims for /igloo/utils/{k} but it's not in FS")

    for guest_path, shim_path in shim_results.items():
        config['static_files'][guest_path] = {
            'type': 'symlink',
            'target': shim_path,
        }

	# Identify original kernel version and shim /lib/modules/4.10.0 to it's /lib/modules path
    kernel_version = None
    with tarfile.open(fs_path) as fs:
        for member in fs.getmembers():
            if member.name.startswith("./lib/modules/") and member.isdir():
                potential_name = os.path.basename(member.name)
                if len(potential_name.split(".")) == 3:
                    if this_version := _kernel_version_to_int(potential_name):
                        if kernel_version is None or this_version > _kernel_version_to_int(kernel_version):
                            kernel_version = potential_name

    if kernel_version:
        # We have a kernel version, add it to our config
        IGLOO_KERNEL_VERSION = '4.10.0'
        config['static_files'][f'/lib/modules/{IGLOO_KERNEL_VERSION}'] = {
            'type': 'symlink',
            'target': f'/lib/modules/{kernel_version}'
        }
            

def _is_init_script(tarinfo):
    if tarinfo.name.startswith('./igloo'):
        return False

    # Check if it is a file (and not a directory)
    if tarinfo.isreg() or tarinfo.issym():
        name = os.path.basename(tarinfo.name)
        # Add more specific conditions to match the init script names. Exclude standard linux script names that aren't init scripts
        if any([x in name for x in ["init", "start"]]) and not any([x in name for x in ["inittab", "telinit"]]):

            # If start is in the name, we want something with a clear "start" not "restart" or "startup".
            # Consider _ - and . as word boundaries and check
            if "start" in name:
                if not re.search(r'[\W_\-\.]start[\W_\-\.]', name):
                    return False
                
            # If we have init in the name, make sure it's not named .init (e.g., rc.d startup names)
            if "init" in name and name.endswith(".init"):
                return False

            if tarinfo.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True
            # TODO: we could prioritize those on standard paths:
            # if tarinfo.name.startswith(('./sbin/', './etc/init.d/', './etc/rc.d/')):
    return False

def add_init_meta(base_config, output_dir):
    # Examine the filesystem and find any binaries that might be an init binary
    fs_path = base_config['core']['fs'] # tar archive
    inits = []

    try:
        with tarfile.open(fs_path) as fs:
            # Use generator expression for more efficient filtering
            inits = [member.name[1:].strip() for member in fs.getmembers() if _is_init_script(member)]
    except FileNotFoundError:
        print(f"Target filesystem {fs_path} was not found.")
        raise
    except tarfile.TarError:
        print(f"Target filesystem {fs_path} is not a valid tar.gz archive.")
        raise

    # Sort inits by length shortest to longest
    inits.sort(key=lambda x: -len(x))

    # Next examine init.txt in the output_dir - these are particularly interesting
    # because they're the ones we saw in kernel args
    kernel_inits = []
    try:
        with open(output_dir + "/init.txt", 'r') as f:
            kernel_inits = [x.strip() for x in f.readlines()]
        # Now remove the inits file, we're done with it
        os.remove(output_dir + "/init.txt")
    except FileNotFoundError:
        # No init.txt - it's okay, we don't really depend on it
        pass

    if len(kernel_inits):
        # Anything in both lists should go to the top. This filters out junk (e.g.,
        # values identified in kernel_inits that aren't in fs) while prioritizing
        # static analysis.
        common_inits = [x for x in kernel_inits if x in inits]
        only_fs_inits = [x for x in inits if x not in common_inits]

        # Sort both sets by length shortest to longest
        common_inits.sort(key=lambda x: len(x))
        only_fs_inits.sort(key=lambda x: len(x))

        # Then combine with common_inits before only_fs_inits
        inits = common_inits + only_fs_inits

    base_config['meta']['potential_init'] = inits


def add_dev_proc_meta(base_config, output_dir):
    pattern = re.compile(r'\/dev\/([A-Za-z0-9_/]+)', re.MULTILINE)

    tar_path = base_config['core']['fs'] # Should all be the same
    potential_devfiles = ["/dev/" + x for x in _find_in_fs(pattern, tar_path).keys()]

    # Drop anything already in the FS or in our list of known device files
    # this list comes from igloo's utils/devtable.txt
    igloo_added_devices = ['/dev/mem', '/dev/kmem', '/dev/null', '/dev/zero', '/dev/random', '/dev/urandom', 
         '/dev/armem', '/dev/tt', '/dev/console', '/dev/ptmx', '/dev/tty0', '/dev/ttyS', '/dev/adsl0', '/dev/ppp',
         '/dev/hidraw0', '/dev/mtd', '/dev/mtd/0', '/dev/mtd/1', '/dev/mtd/2', '/dev/mtd/3', '/dev/mtd/4',
         '/dev/mtd/5', '/dev/mtd/6', '/dev/mtd/7', '/dev/mtd/8', '/dev/mtd/9', '/dev/mtd/10', '/dev/mtd',
         '/dev/mtdr', '/dev/tts/0', '/dev/tts/1', '/dev/tts/2', '/dev/tts/3', '/dev/mtdblock/0', '/dev/mtdblock/1',
         '/dev/mtdblock/2', '/dev/mtdblock/3', '/dev/mtdblock/4', '/dev/mtdblock/5', '/dev/mtdblock/6',
         '/dev/mtdblock/7', '/dev/mtdblock/8', '/dev/mtdblock/9', '/dev/mtdblock/10'] + \
         ['/dev/mtdblock', '/dev/tts', '/dev/mtd'] # Directories created by IGLOo as part of adding subfiles. Can't make as files now

    for k in list(_get_devfiles_in_fs(tar_path)) + igloo_added_devices:
        if k in potential_devfiles:
            potential_devfiles.remove(k)

    # Drop any directories
    directories_to_remove = set()

    # Populate set with directories that have subpaths
    for k in potential_devfiles:
        parent_path_parts = k.split('/')[:-1]
        for i in range(len(parent_path_parts)):
            parent_path = '/'.join(parent_path_parts[:i+1])
            if parent_path in potential_devfiles:
                directories_to_remove.add(parent_path)

    # Create the filtered list
    filtered_devfiles = [k for k in potential_devfiles if k not in directories_to_remove]

    pattern = re.compile(r'\/proc\/([A-Za-z0-9_/]+)', re.MULTILINE)
    proc_files = ["/proc/" + x for x in _find_in_fs(pattern, tar_path).keys()]
    # Drop any that we expect to already have. TODO

    # Add all these to our meta field
    potential_files = filtered_devfiles + proc_files

    with open(output_dir + "/pseudofiles.yaml", 'w') as f:
        yaml.dump(potential_files, f)

    base_config['meta']['potential_files'] = potential_files

def add_env_meta(base_config, output_dir):
    # We want to search the filesystem for shell scripts accessing /proc/cmdline
    # and try to guess at what environment variables we might want to set
    # based on that. Store in meta ['potential_env'] field - we'll set them later
    tar_path = base_config['core']['fs'] # Should all have the same FS
    pattern = re.compile(r'\/proc\/cmdline.*?([A-Za-z0-9_]+)=', re.MULTILINE)
    potential_keys = _find_in_fs(pattern, tar_path).keys()

    # Three magic values for igloo_task_size
    task_options = [0xbf000000, 0x7f000000, 0x3f000000]

    # We should have called add_init_meta before this, so we should have
    # a list of potential init scripts in meta['potential_init']
    potential_env = {
        'igloo_task_size': task_options,
        'igloo_init': base_config['meta']['potential_init'],
    }

    # Drop any keys from potential_keys if the key is in boring_vars
    boring_vars = ["TERM"]
    for k in boring_vars:
        if k in potential_keys:
            potential_keys.remove(k)

    # Add all these to our meta field
    #if 'potential_env' not in base_config['meta']:
    #    base_config['meta']['potential_env'] = {}

    # We've been finding keys, not values they'd get set to
    # We could update our static analysis to search for those too if we'd like
    for k in potential_keys:
        known_vals = None
        pattern = re.compile(k + r'=([A-Za-z0-9_]+)', re.MULTILINE)
        potential_vals = _find_in_fs(pattern, tar_path).keys()

        if len(potential_vals):
            known_vals = list(potential_vals)

        #base_config['meta']['potential_env'][k] = known_vals
        potential_env[k] = known_vals

    with open(output_dir + "/env.yaml", 'w') as f:
        yaml.dump(potential_env, f)

    base_config['meta']['potential_env'] = potential_env

    # We moved potential_init into potential_env
    if 'potential_init' in base_config['meta']:
        del base_config['meta']['potential_init']

    # We need to pick an init binary, or we'll kernel panic! Let's grab the first
    if len(base_config['meta']['potential_env']['igloo_init']):
        base_config['env']['igloo_init'] = base_config['meta']['potential_env']['igloo_init'][0]
    else:
        base_config['env']['igloo_init'] = "TODO_MANUALLY_SET_ME"
        print("WARNING: no init binaries identified. Manually set one in config['env']['igloo_init']")

    return base_config

def extend_config_with_static(base_config, outdir):

    if 'meta' not in base_config:
        base_config['meta'] = {}

    pre_shim(base_config)

    # Search the filesystem for filenames that we want to shim with igloo-utils
    # We shim them all, every time
    shim_configs(base_config)

    # Next we want to identify potential device files and environment variables
    # These are stored in our metadata: [meta][potential_dev] and [meta][potential_env]
    # and they write to base/{env,files,init}.yaml
    add_init_meta(base_config, outdir)
    add_env_meta(base_config, outdir)
    add_dev_proc_meta(base_config, outdir)

    # TODO: Additional static analysis of shell scripts to find more environment variables?
    # We could do some LLM-based shell script analysis

    return base_config

def main():
    from sys import argv
    from os.path import dirname
    if len(argv) != 3:
        print("Usage: python3 penguin_static.py <config> [outdir]")
        exit(1)

    # We'll dump the static analysis outputs into outdir/{env,files}.yaml
    # We don't use the returned object with the meta fields when called directly
    inconf = yaml.load(open(argv[1]), Loader=yaml.FullLoader)
    outdir = argv[2] if len(argv) > 2 else dirname(argv[1])
    extend_config_with_static(inconf, outdir)

if __name__ == '__main__':
    main()