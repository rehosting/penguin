import sys
import yaml
import tarfile
import re
from os.path import dirname, join as pjoin
from pandare import PyPlugin

outfile = "missing_envvars.yaml"
ENV_MAGIC_VAL = "DYNVAL"

'''
# Calculate module name and offset
def addr_to_mod_off(self, cpu, addr):
    mappings = self.panda.get_mappings(cpu)
    module_name = None
    offset = None
    for mapping in mappings:
        if mapping.base <= addr and (mapping.base + mapping.size) > addr:
            module_name = self.panda.ffi.string(mapping.name).decode() if mapping.name != self.panda.ffi.NULL else None
            offset = addr - mapping.base
            break
    return (module_name, offset)
'''

def var_interesting(var):
    for prefix in ["LC_", "LD_", "XDG_", "QT_", "GTK_", "GDK_", "GIO_", "PERL"]:
        if var.startswith(prefix):
            return False
        
    # Other unimportant variables we've seen before (expand as needed)
    if var in   'BLKID_FILE \
                CONSOLE \
                HOME \
                HZ \
                KRB5CCNAME \
                LANG \
                LANGUAGE \
                LOCALDOMAIN \
                LOCPATH \
                MKE2FS_CONFIG \
                MKE2FS_DEVICE_SECTSIZE \
                MKE2FS_SYNC \
                NLDBG \
                PATH \
                POSIXLY_CORRECT \
                PROC_NET_PSCHED \
                PROC_ROOT \
                RES_OPTIONS \
                SHELL \
                SNMPCONFPATH \
                SNMPDLMODPATH \
                SNMP_PERSISTENT_DIR \
                SNMP_PERSISTENT_FILE \
                TERM \
                TICKS_PER_USEC \
                TMPDIR \
                TZ'.split():
        return False

    # Otherwise it IS interesting
    return True

class EnvTracker(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.env_vars = set() # set of env vars that were read through libc getenv

        @panda.hook_symbol("libc-", "getenv")
        def hook_getenv(cpu, tb, h):
            # Get the argument
            try:
                s = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
            except ValueError:
                return
            if not var_interesting(s):
                return
            self.env_vars.add(s)

    def uninit(self):
        # Real uninit: dump env vars
        with open(pjoin(self.outdir, "/env_vars.yaml"), "w") as f:
            yaml.dump(list(self.env_vars), f)

def potential_env_vals(config, varname):
    results = []

    # First option(s) - search filesystem for "[varname]=[valid value]" and try them
    # first we build our regex. Value can only be a-zA-Z0-9_-
    test = re.compile(f"{varname}=([a-zA-Z0-9_-]+)")
    matches = set()

    fs_tar_path = config['base']['fs']
    # Open the tarfile
    tar = tarfile.open(fs_tar_path, "r")
    # Iterate through members
    for member in tar.getmembers():
        # For each file in the archive, look for key=value strings that might be valid
        if not member.isfile():
            continue

        data = tar.extractfile(member.name).read()
        # Note data is bytes, not str, but test is a str regex
        # so we need to decode to str
        data = data.decode(errors='ignore')

        # Now check for matches
        for match in test.findall(data):
            matches.add(match)

    for match in matches:
        results.append(match)

    # Next option: Constant
    results.apend(1)

    # Final option: dynamically find values we compare to
    results.append(ENV_MAGIC_VAL) # Magic string checked against elsewhere

    return results

def propose_mitigations(config, result_dir, quiet=False):
    with open(f"{result_dir}/{outfile}") as f:
        env_accesses = yaml.load(f, Loader=yaml.FullLoader)

    mitigations = []
    existing_vars = [x.split('=')[0] for x in config['append']]
    for varname in env_vails:
        if varname in existing_vars:
            continue
        if not quiet:
            print(f"\tSaw env var access: {varname}")
        for potential_var in potential_env_vals(config, varname):
            mitigations.append((('setenv', varname, potential_var), 0.5)) # Less important than a device accessed/ioctl'd once

    # We can also propose things out of meta['potential_env'], though these have key=value already. Less likely vs things we've seen accessed
    for kv in config['meta']['potential_env']:
        if '=' in kv: # Specific value
            k, v = kv.split("=")
            vals = [v]
        else:
            # Only identified variable name
            k = kv
            vals = potential_env_vals(config, k)

        if k in existing_vars or k in env_accesses:
            continue

        for val in vals:
            mitigations.append((('setenv', k, val), 0.25))

    return mitigations
