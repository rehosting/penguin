import sys
import tarfile
import re
from os.path import dirname, join as pjoin
from pandare import PyPlugin
from copy import deepcopy
try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object
    import yaml

outfile = "missing_envvars.yaml"
ENV_MAGIC_VAL = "DYNVAL"
DEFAULT_VALUES = [
    "1",
    "0",
    "no",
    "0.0.0.0",
    "00:00:00:00:00:00",
]

def var_interesting(var):
    for prefix in ["LC_", "LD_", "XDG_", "QT_", "GTK_", "GDK_", "GIO_", "PERL"]:
        if var.startswith(prefix):
            return False
        
    # Other unimportant variables we've seen before (expand as needed)
    if var in  'BLKID_FILE \
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

        # Return a dict with no contents. One key per env val
        return {k: {} for k in env_accesses}

    def get_mitigations_from_static(self, varname, values):
        # Static pass gives us varname and a set of potential values
        results = []

        # Static analysis gave us some results - use them!
        for value in values or []:
            results.append({'value': value, 'weight': 0.8}) # Statically-identified seeds are promising

        # Also seed with default and dynamic search values
        results += self.get_potential_mitigations(None, varname, None)

        return results

    def get_potential_mitigations(self, config, varname, _):
        existing_vars = list(config[self.ANALYSIS_TYPE].keys()) if config else []
        
        if varname in existing_vars:
            return []

        results = []
        # Start with some placeholders
        for val in DEFAULT_VALUES:
            results.append({'value': val, 'weight': 0.1}) # WEIGHT 0.1 to use a default

        # Do a dynamic search
        results.append({'value': ENV_MAGIC_VAL, 'weight': 0.5}) # WEIGHT 0.5 to do a dynamic search

        '''
        # XXX: how can we avoid redoing this?
        # XXX do we even have access to the FS here?
        # XXX we could move into parse failures, I think?

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
        new_config[self.ANALYSIS_TYPE][failure] = mitigation['value']
        return new_config