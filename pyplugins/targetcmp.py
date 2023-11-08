import re
from pandare import PyPlugin
from os.path import dirname, isfile, join as pjoin
from copy import deepcopy
try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object
    import yaml

target_str = 'DYNVALDYNVALDYNVAL' # We want this to be longer than the other strings we might compare to

output_file = "targetcmp.txt"         # Combined results filtered based on realistic env var values. And ranked, I guess
output_file_cpp = "targetcmp_cpp.txt" # C++ analysis with callstackinstr dumps everything here (good)
output_file_py = "targetcmp_py.txt"   # Python with libc fn hooks dumps everything here (not too good)

def filter_env_var_values(target_key, values):
    # Starts with special symbol, contains our special string, or contains a space
    likely_invalid_pattern = re.compile(r'^[-=!<>()*?]|DYNVAL| ')
    
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

def _get_target_str_in_config(config):
    if "env" not in config:
        return None

    matches = [k for k, v in config['env'].items() if v == target_str]

    if not len(matches):
        return None
    
    if len(matches) > 1:
        raise ValueError(f"Multiple matches for target_str in config: {matches}")

    return matches[0]

class TargetCmp(PenguinAnalysis):
    ANALYSIS_TYPE = "env" # Not the only env-plugin XXX need to figure this out. Merge?

    '''
    def parse_failures(self, output_dir):
        # "Failure" here just means our target_str was compared to something

        # Open [outdir]/targetcmp.txt and read each line
        outdir = output_dir
        if not isfile(f"{outdir}/{output_file}") or not isfile(f"{outdir}/{output_file2}"):
            # No targetcmp: plugin wasn't doing anything or didn't find any results
            return []

        target_var = [x.split("=")[0] for x in config['append'] if f'={target_str}' in x]
        assert(len(target_var) == 1), f"Target var cannot be multiple values: {target_var}"
        target_var = target_var[0]

        new_configs = []
        compared_vals = set()

        for line in open(f"{outdir}/{output_file}", "rb").read().splitlines() + \
                    open(f"{outdir}/{output_file2}", "rb").read().splitlines():

            l = line.strip()
            # Check if line is alphanumeric or _ or -
            if len(l) and l.replace(b"_", b"").replace(b"-", b"").isalnum():
                compared_vals.add(l.decode(errors='ignore'))

        for new_val in compared_vals:
            new_config = deepcopy(config)

            new_config['append'] = [f"{target_var}={new_val}" if ('=' in x and x.split('=')[0] == target_var) else x for x in config['append']]
            new_config['meta']['delta'].append(f"env {target_var}={new_val}")

            # We saw a concrete comparison - this is pretty promising!
            # XXX: we'll calculate this as a relative score to the run with DYNVAL
            # but we really want to calculate it based on the grandparent's score
            # because DYNVAL was definitely wrong
            new_configs.append((15, new_config))
        return new_configs
    '''

class TargetCmp(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.env_var_matches = set()

        with open(self.outdir + "/config.yaml", "r") as f:
            config = yaml.safe_load(f)

        match = _get_target_str_in_config(config)
        if not match:
            return
        
        self.target_key = match

        # Touch the files so we know this analysis is actually running
        # Otherwise these files won't get created
        open(pjoin(self.outdir, output_file), "w").close()
        open(pjoin(self.outdir, output_file_py), "w").close()
        open(pjoin(self.outdir, output_file_cpp), "w").close()

        # Load C plugins to dynamically track potential comparisons
        panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
        panda.load_plugin("callwitharg")
        panda.load_plugin("targetcmp",
            args={
                "output_file": pjoin(self.outdir, output_file_cpp),
                "target_str": target_str
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
        if str1 == target_str:
            match = str2
        elif str2 == target_str:
            match = str1
        else:
            return

        if match not in self.env_var_matches:
            self.env_var_matches.add(match)
            with open(pjoin(self.outdir, output_file_py), "a") as f:
                f.write(match + "\n")

    def uninit(self):
        # Read the C++ collected data and combine with our python tracked data
        with open(pjoin(self.outdir, output_file_cpp), "r") as f:
            for x in f.read().splitlines():
                self.env_var_matches.add(x.strip())

        # Then filter and combine into output_file
        print("POTENTIAL VARS:", self.env_var_matches)
        valid_vars = filter_env_var_values(self.target_key, self.env_var_matches)
        print("VALID VARS:", valid_vars)
        with open(pjoin(self.outdir, output_file), "w") as f:
            for x in valid_vars:
                f.write(x + "\n")