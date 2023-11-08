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

ENV_MAGIC_VAL = 'DYNVALDYNVALDYNVAL' # We want this to be longer than the other strings we might compare to
# If we change this we also need to change the regex below

cmp_output = "env_cmp.txt"
cmp_output_cpp = "env_cmp_cpp.txt" # C++ analysis with callstackinstr dumps everything here (good)
cmp_output_py = "env_cmp_py.txt"   # Python with libc fn hooks dumps everything here (not too good)

missing_output = "env_missing.yaml"

class EnvTracker(PyPlugin):
    '''
    Track environment variables that appear to be read
    and store them in missing_output if they aren't in our env
    '''
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.env_vars = set() # set of env vars that were read through libc getenv
        self.default_env_vars = ["root", "console", "clocksource", "elevator", "nohz", "idle", "acpi"]

        @panda.hook_symbol("libc-", "getenv")
        def hook_getenv(cpu, tb, h):
            # Get the argument
            try:
                s = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
            except ValueError:
                return
            if not self.var_interesting(s):
                return
            self.addvar(cpu, s)

        @panda.hook_symbol(None, "strstr")
        def hook_strstr(cpu, tb, h):
            '''
            A key-value lookup typically will require a search of a set
            of key=value pairs for "targetkey=". We know the ground-truth
            for /proc/cmdline - so let's check if anyone is ever doing
            a strstr on that while looking for a new key
            '''
            a1 = panda.arch.get_arg(cpu, 0)
            a2 = panda.arch.get_arg(cpu, 1)

            try:
                s1 = panda.read_str(cpu, a1, max_length=100)
                s2 = panda.read_str(cpu, a2, max_length=100)
            except ValueError:
                return

            # /proc/cmdline check. If we see match in one, target is the other
            keyword = "root=/dev/vda"
            target = s2 if keyword in s1 else s1 if keyword in s2 else None

            if target and target.endswith('='):
                match = target.rstrip('=')
                if not self.var_interesting(match):
                    return
                self.addvar(cpu, match)

    def addvar(self, cpu, match):
        proc = self.panda.get_process_name(cpu)
        self.env_vars.add(match)

    def uninit(self):
        with open(pjoin(self.outdir, missing_output), "w") as f:
            missing = [x for x in self.env_vars if x not in self.default_env_vars]
            yaml.dump(missing, f)

    @staticmethod
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


class TargetCmp(PyPlugin):
    '''
    Our 2nd pyplugin for environemnt tracking.

    Here we examine config to see if any env variable is set to
    our magic value. If so, we'll track values it's comapred to
    using the C++ targetcmp plugin. We'll also try to detect
    comparisons with library hooks, though those don't
    have much success.

    Most of the time this plugin doesn't do anything since
    there's no magic value in our env
    '''
    def __init__(self, panda):
        self.target_key = self._get_target_str_in_config(self.get_arg('conf'))
        if not self.target_key:
            return

        self.outdir = self.get_arg("outdir")
        print("TargetCMP loaded with outdir:", self.outdir)
        assert(self.outdir is not None), f"NO OUTDIR"
        self.env_var_matches = set()
        # Touch the files so we know this analysis is actually running
        # Otherwise these files won't get created

        open(pjoin(self.outdir, cmp_output), "w").close()
        open(pjoin(self.outdir, cmp_output_cpp), "w").close()
        open(pjoin(self.outdir, cmp_output_py), "w").close()

        # Load C plugins to dynamically track potential comparisons
        panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
        panda.load_plugin("callwitharg")
        panda.load_plugin("targetcmp",
            args={
                "output_file": pjoin(self.outdir, cmp_output_cpp),
                "target_str": ENV_MAGIC_VAL,
                })

        # Also explicitly hook strcmp/strncmp
        @panda.hook_symbol("libc-", "strcmp")
        def hook_strcmp(cpu, tb, h):
            try:
                str1 = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
                str2 = panda.read_str(cpu, panda.arch.get_arg(cpu, 1))
            except ValueError:
                return
            
            self.consider(str1, str2)

        @panda.hook_symbol("libc-", "strncmp")
        def hook_strncmp(cpu, tb, h):
            # Get two strings being compared - are either IGLOOENVVAR
            n = panda.arch.get_arg(cpu, 2)
            try:
                str1 = panda.read_str(cpu, panda.arch.get_arg(cpu, 0), max_length=n)
                str2 = panda.read_str(cpu, panda.arch.get_arg(cpu, 1), max_length=n)
            except ValueError:
                return
            self.consider(str1, str2)

    def consider(self,str1, str2):
        if str1 == ENV_MAGIC_VAL:
            match = str2
        elif str2 == ENV_MAGIC_VAL:
            match = str1
        else:
            return

        if match not in self.env_var_matches:
            self.env_var_matches.add(match)
            with open(pjoin(self.outdir, cmp_output_py), "a") as f:
                f.write(match + "\n")

    def uninit(self):
        if not self.target_key:
            # We weren't doing anything, nothing to report
            return

        # Read the C++ collected data and combine with our python tracked data
        with open(pjoin(self.outdir, cmp_output_cpp), "r") as f:
            for x in f.read().splitlines():
                self.env_var_matches.add(x.strip())

        # Then filter and combine into output_file
        valid_vars = self.filter_env_var_values(self.target_key, self.env_var_matches)
        with open(pjoin(self.outdir, cmp_output), "w") as f:
            for x in valid_vars:
                f.write(x + "\n")

    @staticmethod
    def filter_env_var_values(target_key, values):
        # Starts with special symbol, contains our special string, or contains a space
        likely_invalid_pattern = re.compile(r'^[-=!<>()*?]|DYNVAL| ') # XXX ENV_MAGIC_VAL is in here manually
        
        # Define a regex pattern for likely valid env var values, allowing '_', '-', and '.'
        likely_valid_pattern = re.compile(r'^[A-Za-z0-9_.-]+$')

        filtered_values = []
        for val in values:
            if likely_invalid_pattern.search(val):
                continue
            if '=' in val:
                continue
            if val == target_key:
                continue
            filtered_values.append(val)

        # Rank the remaining values based on likely validity
        ranked_values = sorted(filtered_values, key=lambda x: (
            -bool(likely_valid_pattern.match(x)),  # Likely valid values first
            -len(x),  # Longer values next
            x.lower()  # Alphabetically as a last resort
        ))

        return ranked_values

    @staticmethod
    def _get_target_str_in_config(config):
        if "env" not in config:
            return None
        matches = [k for k, v in config['env'].items() if v == ENV_MAGIC_VAL]
        if not len(matches):
            return None
        if len(matches) > 1:
            raise ValueError(f"Multiple matches for ENV_MAGIC_VAL ({ENV_MAGIC_VAL}) in config: {matches}")
        return matches[0]

class EnvTrackerAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "env"

    DEFAULT_VALUES = [
        "1",
        "0",
        "no",
        "0.0.0.0",
        "00:00:00:00:00:00",
    ]


    def parse_failures(self, output_dir):
        with open(pjoin(output_dir, missing_output)) as f:
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
        for val in self.DEFAULT_VALUES:
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