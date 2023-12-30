import sys
import tarfile
import re
from os.path import dirname, join as pjoin, isfile
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
shell_env_output = "shell_env.csv"

uboot_output = "env_uboot.txt"
missing_output = "env_missing.yaml"
mtd_output = "env_mtd.txt"

class EnvTracker(PyPlugin):
    '''
    Track environment variables that appear to be read
    and store them in missing_output if they aren't in our env
    '''
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.env_vars = set() # set of env vars that were read through libc getenv
        self.uboot_vars = set() # set of env vars that were read through libc getenv
        self.mtd_vars = set() # set of mtd partitions read out of /proc/mtd

        self.default_env_vars = ["root", "console", "clocksource", "elevator", "nohz", "idle", "acpi"]
        self.conf = self.get_arg("conf")
        if "env" in self.conf:
            # Track the set env variables so we know they're set
            self.default_env_vars += list(self.conf["env"].keys())

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

            # I haven't (yet) seen these without a trailing =s, but it could happen
            # maybe we should be less conservative here?
            if target and target.endswith('='):
                match = target.rstrip('=')
                if not self.var_interesting(match):
                    return
                self.addvar(cpu, match)

            # uboot env check. IFF we put this in the uboot env
            keyword = "igloo_uboot_env=placeholder"

            target = s2 if keyword in s1 else s1 if keyword in s2 else None
            if target:
                match = target.rstrip('=') # Optional, have seen lookups without the trailing =s

                if not self.uboot_var_interesting(match):
                    return
                self.uboot_addvar(cpu, match)

            # MTD search (e.g., /proc/mtd)
            # This is for *partition names* not the contents or anything that fancy
            keyword = "mtd0: "

            target = s2 if keyword in s1 else s1 if keyword in s2 else None
            if target:
                # We can trim "s, because the name is always quoted (e.g., we could search "foo" when looking for foo)
                target = target.strip('"')
                if 'env' in self.conf and 'mtdparts' in self.conf['env'] and f"({target})" in self.conf['env']['mtdparts']:
                    # We've set this partition up already. Yay!
                    return
                self.mtd_addvar(cpu, target)

    def addvar(self, cpu, match):
        #proc = self.panda.get_process_name(cpu)
        self.env_vars.add(match)

    def uboot_addvar(self, cpu, match):
        #proc = self.panda.get_process_name(cpu)
        #print(f"UBOOTVAR: {match} in {proc}")
        self.uboot_vars.add(match)

    def mtd_addvar(self, cpu, match):
        #proc = self.panda.get_process_name(cpu)
        #print(f"MTDVAR: {match} in {proc}")
        self.mtd_vars.add(match)

    def uninit(self):
        # Write environment vars
        with open(pjoin(self.outdir, missing_output), "w") as f:
            missing = [x for x in self.env_vars if x not in self.default_env_vars]
            yaml.dump(missing, f)

        # Write uboot vars
        with open(pjoin(self.outdir, uboot_output), "w") as f:
            vals = list(self.uboot_vars)
            yaml.dump(vals, f)

        # Write mtd vars
        with open(pjoin(self.outdir, mtd_output), "w") as f:
            vals = list(self.mtd_vars)
            yaml.dump(vals, f)

    @staticmethod
    def uboot_var_interesting(var):
        # XXX do we want to ignore any?
        return True

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
        #open(pjoin(self.outdir, cmp_output), "w").close()
        #open(pjoin(self.outdir, cmp_output_cpp), "w").close()
        #open(pjoin(self.outdir, cmp_output_py), "w").close()

        # Load C plugins to dynamically track potential comparisons
        panda.load_plugin("callstack_instr", args={
                                                    #"stack_type": "heuristic",
                                                    "stack_type": "asid", # But MIPS asids are bad?
                                                    #"stack_type": "threaded", # Segfaults. See PANDA #1405
                                                    "verbose": False})
        panda.load_plugin("callwitharg")
        panda.load_plugin("targetcmp", # Or targetcmp2 for dev (in penguin_plugins)
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
        # These are unsorted so we sort for determinism between runs
        with open(pjoin(self.outdir, cmp_output_cpp), "r") as f:
            for x in sorted(f.read().splitlines()):
                self.env_var_matches.add(x.strip())

        # Then filter and combine into output_file
        # THese are sorted based on how much we like them
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
    VERSION = "1.0.0"

    DEFAULT_VALUES = [
        "1",
        "0",
        "no",
        "0.0.0.0",
        "00:00:00:00:00:00",
    ]


    def parse_failures(self, output_dir, global_state=None, global_lock=None):
        '''
        Parse failures from env_missing.yaml for unset env variables.
        Also if we have shell_env.csv, look in there for unset variables too.

        If we have a DYNVALDYNVALDYNVAL in our env, that's the only
        failure we're allowed to return (since we must "mitigate" it before moving on)
        '''

        with open(pjoin(output_dir, 'core_config.yaml')) as f:
            config = yaml.safe_load(f)

            # Is any env variable set to ENV_MAGIC_VAL?
            magic_is_set = any(x == ENV_MAGIC_VAL for x in config['env'].values())

        if magic_is_set:
            # We had an ENV_MAGIC_VAL for target_var
            target_var = [k for k, v in config['env'].items() if v == ENV_MAGIC_VAL][0]
            #print(f"ENV_MAGIC_VAL ({ENV_MAGIC_VAL}) is set for {target_var}. Looking for dynamic values:")

            dyn_vals = set()
            if isfile(pjoin(output_dir, cmp_output)):
                # Looks like we were running with ENV_MAGIC_VAL. Let's record these results too
                # We don't know the name of the env_var though. Hmm.
                with open(pjoin(output_dir, cmp_output)) as f:
                    for line in f.readlines():
                        dyn_vals.add(line.strip())

            #print(f"Found {len(dyn_vals)} dynamic values for {target_var}: {dyn_vals}")

            # We found things dynamically. Cool
            if len(dyn_vals) > 0:
                return {target_var: dyn_vals}
            else:
                # We found nothing. Time to give up on this. Probably an uninteresting variable
                return {}

        with open(pjoin(output_dir, missing_output)) as f:
            env_accesses = yaml.safe_load(f)

        if isfile(pjoin(output_dir, shell_env_output)):
            # Shell plugin may have detected some env accesses too. Let's take a look
            seen_envs = {} # name -> values
            with open(pjoin(output_dir, shell_env_output)) as f:
                env_accesses = {}
                for line in f.readlines()[1:]: # Skip header
                    # Recover the env list from the line.
                    # This storage format is kinda gross
                    idx = line.index(",[")
                    envs = line[idx+1:].strip()
                    if not len(envs):
                        continue
                    env_tuples = eval(envs) # XXX sad eval
                    if not len(env_tuples):
                        continue
                    for (name, val) in env_tuples:
                        if name not in seen_envs:
                            seen_envs[name] = set()
                        seen_envs[name].add(val)

            # Now look through the env names we've seen. Try finding any names that were always None.
            # Add these to our env_accesses list if they're not already there
            for k, v in seen_envs.items():
                if len(k) == 0 or not k[0].isalpha():
                    # We only want sane variable names. Exclude anythign that starts with a symbol or non-alpha
                    continue
                if None in v and k not in env_accesses:
                    env_accesses[k] = {}


        ## DEBUG: only return SXID
        #print("WARNING HACKY ENV SXID ONLY: dropping", env_accesses.keys())
        #if 'sxid' in env_accesses:
        #    env_accesses = {'sxid': {}}
        #else:
        #    env_accesses = []

        # Return a dict. Keys are variables. Values is an empty list
        return {k: [] for k in env_accesses}

    def get_mitigations_from_static(self, varname, values):
        # Static pass gives us varname and a set of potential values
        results = []

        # Static analysis gave us some results - use them!
        for value in values or []:
            results.append({'value': value, 'weight': 0.8}) # Statically-identified seeds are promising

        # Also seed with default and dynamic search values
        results += self.get_potential_mitigations(None, varname, None)

        return results

    def get_potential_mitigations(self, config, varname, dynvals, global_state=None, global_lock=None):
        '''
        Dynvals will be a list of dynamic values we found for varname IFF we were doing a dynamic
        search. Otherwise it's empty
        '''
        results = []

        # If we just ran a dynamic search that's the only mitigation we'll apply
        if config and any(v == ENV_MAGIC_VAL for k, v in config[self.ANALYSIS_TYPE].items()):
            target_var = [k for k, v in config[self.ANALYSIS_TYPE].items() if v == ENV_MAGIC_VAL][0]
            # Refuse to get mitigations for any other vars
            if varname != target_var:
                print(f"Refusing to provide mitigations for {varname} after we did a dynval search on {target_var}")
                return results

            # We just ran a dynamic search for target_var the dynvals argument should tell us
            # what those values might be
            if len(dynvals):
                for val in dynvals:
                    results.append({'value': val, 'weight': 0.9}) # We like results from dynamic search

                # Let's add these to global state
                if global_state is not None:
                    #print(f"Setting cached values for env {varname}: {dynvals}")
                    with global_lock:
                        if self.ANALYSIS_TYPE not in global_state:
                            global_state[self.ANALYSIS_TYPE] = {}
                        if varname not in global_state[self.ANALYSIS_TYPE]:
                            global_state[self.ANALYSIS_TYPE][varname] = set()
                        global_state[self.ANALYSIS_TYPE][varname].update(dynvals)
            else:
                # Dynamic search failed. Let's add some default values instead
                print("env dynamic search found no results. Adding some low-weight defaults:", self.DEFAULT_VALUES)
                # Start with some placeholders
                for val in self.DEFAULT_VALUES:
                    results.append({'value': val, 'weight': 0.1}) # WEIGHT 0.1 to use a default

            return results

        # If we get here we're NOT doing a dynamic search.
        assert(dynvals is None or not len(dynvals)), f"Unexpected duynvals for non-dynamic search: {dynvals}"

        # Is this varname set in our config? If so we can't mitigate it (since it's not set to ENV_MAGIC_VAL)
        existing_vars = list(config[self.ANALYSIS_TYPE].keys()) if config else []
        if varname in existing_vars:
            return []

        # Load potential values from global state learned on other runs with ENV_MAGIC_VALUE
        if global_state is not None and self.ANALYSIS_TYPE in global_state and varname in global_state[self.ANALYSIS_TYPE]:
            for val in global_state[self.ANALYSIS_TYPE][varname]:
                results.append({'value': val, 'weight': 0.8}) # We like these. Might be stale so slightly lower weight than non-stale dynsearch
        else:
            # We haven't searched before - let's queue up a search. Less important than pseudofiles
            results.append({'value': ENV_MAGIC_VAL, 'weight': 0.4})
        return results

    def implement_mitigation(self, config, failure, mitigation):
        # Given a mitigation, add it to a copy of the config and return
        new_config = deepcopy(config)

        #assert(failure not in new_config[self.ANALYSIS_TYPE]) # This is okay - for DYNVAL-based analyses we'll clobber
        new_config[self.ANALYSIS_TYPE][failure] = mitigation['value']
        return new_config