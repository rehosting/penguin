import sys
import yaml
import tarfile
import re
from os.path import dirname, join as pjoin
from pandare import PyPlugin
from copy import deepcopy
try:
    from penguin import PenguinAnalysis
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object

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

class EnvTrackerAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "env"

    def parse_failures(self, output_dir):
        with open(pjoin(output_dir, outfile)) as f:
            env_accesses = yaml.safe_load(f)

        # It's a list - easy pz
        return env_accesses

    def get_potential_mitigations(self, config, varname):
        existing_vars = list(config[self.ANALYSIS_TYPE].keys()) if config else []

        if varname == 'igloo_task_size':
            # This is a special case. Already have all the values we could need
            return []
        
        if varname in existing_vars:
            return []

        results = []
        # Start with some placeholders
        for val in DEFAULT_VALUES:
            results.append(val)

        # Do a dynamic search
        results.append(ENV_MAGIC_VAL)

        '''
        # XXX: how can we avoid redoing this?
        # XXX do we even have access to the FS here?

        # Check FS for potential values
        test = re.compile(f"{varname}=([a-zA-Z0-9_-]+)")
        matches = set()

        fs_tar_path = config['base']['fs']
        tar = tarfile.open(fs_tar_path, "r")
        for member in tar.getmembers():
            if not member.isfile():
                continue
            data = tar.extractfile(member.name).read()
            # Note data is bytes, not str, but test is a str regex
            # so we need to decode to str
            data = data.decode(errors='ignore')

            for match in test.findall(data):
                matches.add(match)

        for m in matches:
            results.append(m)
        '''
        return results

    def implement_mitigation(self, config, failure, mitigation):
        # Given a mitigation, add it to a copy of the config and return
        new_config = deepcopy(config)

        assert(failure not in new_config[self.ANALYSIS_TYPE])
        new_config[self.ANALYSIS_TYPE][failure] = mitigation

        return new_config