import sys
import yaml
import tarfile
import re
from os.path import dirname, join as pjoin
from pandare import PyPlugin
from copy import deepcopy

outfile = "missing_envvars.yaml"
ENV_MAGIC_VAL = "DYNVAL"
DEFAULT_VALUES = [
    "1",
    "0",
    "no",
    "0.0.0.0",
    "00:00:00:00:00:00",
]

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
        with open(pjoin(self.outdir, outfile), "w") as f:
            yaml.dump(list(self.env_vars), f)

def potential_env_vals(config, varname):
    results = [] # (weight, val)

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
            # It's promising that we saw this in the FS
            matches.add((10, match)) # WEIGHT: 10

    for match in matches:
        results.append(match)

    # Next option: Constant values
    for const in ["1"]:
        results.append((0.5, const)) # WEIGHT: 0.5

    # Final option: dynamically find values we compare to
    # This requires multiple steps so it's tricky
    # and we can't do this if we already have any other ENV_MAGIC_VALs set in our config
    if not any([ENV_MAGIC_VAL in x.split("=")[1] for x in config['append']]):
        results.append((1, ENV_MAGIC_VAL)) # Magic string checked against by targetcmp

    return results

def propose_configs(config, result_dir, quiet=False):
    with open(pjoin(result_dir, outfile)) as f:
        env_accesses = yaml.load(f, Loader=yaml.FullLoader)

    new_configs = []
    existing_vars = [x.split('=')[0] for x in config['append']]

    # FIRST: for all variables we saw accessed, we proppose
    # setting them to various values. XXX: Here we're just guessing
    # based on static analysis and consts, nothing fancy
    for varname in env_accesses:
        if varname in existing_vars:
            continue
        if not quiet:
            print(f"\tSaw env var access: {varname}")

        for (var_weight, potential_var) in potential_env_vals(config, varname):
            # Build a new config with key=potential val. WEIGHT=1
            # Drop alternatives for this key in potential_env
            new_config = deepcopy(config)

            new_config['append'].append(f"{varname}={potential_var}")
            new_config['meta']['delta'].append(f"env {varname}={potential_var}")

            for k in list(new_config['meta']['potential_env']):
                if "=" in k:
                    k=k.split("=")[0]
                if k == varname:
                    new_config['meta']['potential_env'].remove(k)
            new_configs.append((var_weight, new_config))

    # SECOND: for variables we have in our potential_env, we can propose
    # setting these too. Less likely to succeed - note we have our igloo_task_size
    # in here which sometimes matters

    for key_name, default_values in config['meta']['potential_env'].items():

        if key_name in existing_vars:
            # We've already set this to something concrete - don't try anything else
            continue

        if default_values is not None:
            vals = [(2, x) for x in default_values] # WEIGHT 2 because we have concrete values in FS
        else:
            vals = [(0.5, x) for x in  DEFAULT_VALUES] # WEIGHT 0.5 because we're winging it

        # Dynamically search for new values at runtime!
        vals.append((1, ENV_MAGIC_VAL))

        # We have specific values! Try them out
        for (val_weight, val) in vals:
            new_config = deepcopy(config)
            new_config['append'].append(f"{key_name}={val}")
            new_config['meta']['delta'].append(f"env {key_name}={val}")
            new_configs.append((val_weight, new_config))

    return new_configs
