import itertools
import re
from copy import deepcopy
from os.path import isfile
from os.path import join as pjoin
from typing import List

from pandare import PyPlugin

from penguin import getColoredLogger

try:
    from penguin import yaml
    from penguin.analyses import PenguinAnalysis
    from penguin.graphs import Configuration, Failure, Mitigation
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object
    import yaml

ENV_MAGIC_VAL = "DYNVALDYNVALDYNVAL"  # We want this to be longer than the other strings we might compare to
# If we change this we also need to change the regex below

cmp_output = "env_cmp.txt"
cmp_output_cpp = (
    "env_cmp_cpp.txt"  # C++ analysis with callstackinstr dumps everything here (good)
)
cmp_output_py = (
    "env_cmp_py.txt"  # Python with libc fn hooks dumps everything here (not too good)
)
shell_env_output = "shell_env.csv"

uboot_output = "env_uboot.txt"
missing_output = "env_missing.yaml"
mtd_output = "env_mtd.txt"

DEFAULT_ENV_VARS = [
    "root",
    "console",
    "clocksource",
    "elevator",
    "nohz",
    "idle",
    "acpi",
    "LD_LIBRARY_PATH",
]


class EnvTracker(PyPlugin):
    """
    Track environment variables that appear to be read
    and store them in missing_output if they aren't in our env
    """

    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.env_vars = set()  # set of env vars that were read through libc getenv
        self.uboot_vars = set()  # set of env vars that were read through libc getenv
        self.mtd_vars = set()  # set of mtd partitions read out of /proc/mtd
        self.logger = getColoredLogger("plugins.env_tracker")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        self.default_env_vars = DEFAULT_ENV_VARS
        self.conf = self.get_arg("conf")
        if "env" in self.conf:
            # Track the set env variables so we know they're set
            self.default_env_vars += list(self.conf["env"].keys())

        self.ppp.Core.ppp_reg_cb("igloo_getenv", self.on_getenv)
        self.ppp.Core.ppp_reg_cb("igloo_strstr", self.on_strstr)

    def on_strstr(self, cpu, s1, s2):
        # /proc/cmdline check. If we see match in one, target is the other
        keyword = "root=/dev/vda"
        target = s2 if keyword in s1 else s1 if keyword in s2 else None

        # I haven't (yet) seen these without a trailing =s, but it could happen
        # maybe we should be less conservative here?
        if target and target.endswith("="):
            match = target.rstrip("=")
            if not self.var_interesting(match):
                return
            self.addvar(cpu, match)

        # uboot env check. IFF we put this in the uboot env
        keyword = "igloo_uboot_env=placeholder"

        target = s2 if keyword in s1 else s1 if keyword in s2 else None
        if target:
            match = target.rstrip(
                "="
            )  # Optional, have seen lookups without the trailing =s

            if not self.uboot_var_interesting(match):
                return
            self.uboot_addvar(cpu, match)

        # MTD search (e.g., /proc/mtd)
        # This is for *partition names* not the contents or anything that fancy
        # If we have an MTD device with a name "fakemtd" we'll look for it!

        if "pseudofiles" in self.conf and any(
            x.startswith("/dev/mtd") and "name" in data and data["name"] == "fakemtd"
            for x, data in self.conf["pseudofiles"].items()
        ):

            for keyword in ["fakemtd", "mtd100:"]:
                target = s2 if keyword in s1 else s1 if keyword in s2 else None
                if target:
                    # We can trim "s, because the name is always quoted (e.g., we could search "foo" when looking for foo)
                    target = target.strip('"')
                    self.mtd_addvar(cpu, target)

    def on_getenv(self, cpu, s):
        if self.var_interesting(s):
            self.addvar(cpu, s)

    def addvar(self, cpu, match):
        # proc = self.panda.get_process_name(cpu)
        if match not in self.default_env_vars and match not in self.env_vars:
            self.logger.debug(f"New environment variable referenced: {match}")
        self.env_vars.add(match)

    def uboot_addvar(self, cpu, match):
        # proc = self.panda.get_process_name(cpu)
        # print(f"UBOOTVAR: {match} in {proc}")
        if match not in self.default_env_vars and match not in self.uboot_vars:
            self.logger.debug(f"New uboot environment variable referenced: {match}")
        self.uboot_vars.add(match)

    def mtd_addvar(self, cpu, match):
        # proc = self.panda.get_process_name(cpu)
        # print(f"MTDVAR: {match} in {proc}")
        if match not in self.default_env_vars and match not in self.mtd_vars:
            self.logger.debug(f"New mtd partition referenced: {match}")
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
            for var in self.mtd_vars:
                f.write(var + "\n")

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
        if (
            var
            in "BLKID_FILE \
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
                    TZ".split()
        ):
            return False

        # Otherwise it IS interesting
        return True


class TargetCmp(PyPlugin):
    """
    Our 2nd pyplugin for environemnt tracking.

    Here we examine config to see if any env variable is set to
    our magic value. If so, we'll track values it's comapred to
    using the C++ targetcmp plugin. We'll also try to detect
    comparisons with library hooks, though those don't
    have much success.

    Most of the time this plugin doesn't do anything since
    there's no magic value in our env
    """

    def __init__(self, panda):
        self.target_key = self._get_target_str_in_config(self.get_arg("conf"))
        if not self.target_key:
            return

        # XXX: We need to disable tb_chaining to detect more comparisons. Unfortunately
        # this hurts performance, but without it we definitely miss some comparisons
        # in targetcmp/callwitharg/callstack_instr.
        panda.disable_tb_chaining()

        self.logger = getColoredLogger("plugins.TargetCmp")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        self.outdir = self.get_arg("outdir")
        self.logger.info(f"Dynamically searching for {self.target_key}")
        assert self.outdir is not None, "NO OUTDIR"
        self.env_var_matches = set()

        # Load C plugins to dynamically track potential comparisons
        panda.load_plugin(
            "callstack_instr",
            args={
                # "stack_type": "heuristic",
                "stack_type": "asid",  # But MIPS asids are bad?
                # "stack_type": "threaded", # Segfaults. See PANDA #1405
                "verbose": False,
            },
        )
        panda.load_plugin("callwitharg")
        panda.load_plugin(
            "targetcmp",  # Or targetcmp2 for dev (in penguin_plugins)
            args={
                "output_file": pjoin(self.outdir, cmp_output_cpp),
                "target_str": ENV_MAGIC_VAL,
            },
        )

        self.ppp.Core.ppp_reg_cb("igloo_string_cmp", self.on_string_compare)

    def on_string_compare(self, cpu, s):
        """
        LD_PRELOAD based hooks for strcmp/strncmp
        the guest strcmp/strncmps s to our DYNVAL string
        """
        if s not in self.env_var_matches:
            self.env_var_matches.add(s)
            with open(pjoin(self.outdir, cmp_output_py), "a") as f:
                f.write(s + "\n")

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
        # These are sorted based on how much we like them
        valid_vars = self.filter_env_var_values(self.target_key, self.env_var_matches)
        with open(pjoin(self.outdir, cmp_output), "w") as f:
            for x in valid_vars:
                self.logger.debug(f"Found potential value {x}")
                f.write(x + "\n")

    @staticmethod
    def filter_env_var_values(target_key, values):
        # Starts with special symbol, contains our special string, or contains a space
        likely_invalid_pattern = re.compile(
            r"^[-=!<>()*?]|DYNVAL| "
        )  # XXX ENV_MAGIC_VAL is in here manually

        # Define a regex pattern for likely valid env var values, allowing '_', '-', and '.'
        likely_valid_pattern = re.compile(r"^[A-Za-z0-9_.-]+$")

        filtered_values = []
        for val in values:
            if likely_invalid_pattern.search(val):
                continue
            if "=" in val:
                continue
            if val == target_key:
                continue
            filtered_values.append(val)

        # Rank the remaining values based on likely validity
        ranked_values = sorted(
            filtered_values,
            key=lambda x: (
                -bool(likely_valid_pattern.match(x)),  # Likely valid values first
                -len(x),  # Longer values next
                x.lower(),  # Alphabetically as a last resort
            ),
        )

        return ranked_values

    @staticmethod
    def _get_target_str_in_config(config):
        matches = [
            k
            for k, v in itertools.chain(
                config.get("env", {}).items(),
                config.get("uboot_env", {}).items(),
            )
            if v == ENV_MAGIC_VAL
        ]
        if not len(matches):
            return None
        if len(matches) > 1:
            raise ValueError(
                f"Multiple matches for ENV_MAGIC_VAL ({ENV_MAGIC_VAL}) in config: {matches}"
            )
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

    def parse_failures(self, output_dir) -> List[Failure]:
        """
        Parse failures from env_missing.yaml for unset env variables.
        Also if we have shell_env.csv, look in there for unset variables too.

        If we have a DYNVALDYNVALDYNVAL in our env, it should be from an exclusive
        config so we're the only plugin that can analyze. In that case, it's
        the only failure we should consider (since we must address before we
        move on.
        """

        with open(pjoin(output_dir, "core_config.yaml")) as f:
            config = yaml.safe_load(f)

        # Check for our magic variable in boot env, uboot env, and pseudofile read models
        magic_is_set = any(x == ENV_MAGIC_VAL for x in config["env"].values()) or any(
            x == ENV_MAGIC_VAL for x in config.get("uboot_env", {}).values()
        )

        if not magic_is_set:
            for path, file_details in config.get("pseudofiles", {}).items():
                if (
                    file_details.get("read", None)
                    and file_details["read"].get("model", None) == "const_buf"
                ):
                    if (
                        const_buf := file_details["read"].get("buf", None)
                        and const_buf == ENV_MAGIC_VAL
                    ):
                        magic_is_set = True
                        break

        if magic_is_set:
            target_var = [k for k, v in config["env"].items() if v == ENV_MAGIC_VAL][0]

            dyn_vals = set()
            if isfile(pjoin(output_dir, cmp_output)):
                # Looks like we were running with ENV_MAGIC_VAL. Let's record these results too
                # We don't know the name of the env_var though. Hmm.
                with open(pjoin(output_dir, cmp_output)) as f:
                    for line in f.readlines():
                        line = line.strip()
                        # Regex to check if it's a valid environment variable
                        if re.match(r"^[A-Za-z_0-9][A-Za-z0-9-_\./]*$", line):
                            dyn_vals.add(line)
                        else:
                            print(
                                "Ignoring cpp-discovered dynval as it doesn't match regex:",
                                line,
                            )

            if len(dyn_vals) > 10:
                print(
                    f"Warning, found {len(dyn_vals)} dynamic values for {target_var}. This is a lot! Filtering to first 3"
                )
                sorted_vals = sorted(
                    dyn_vals, key=lambda x: len(x)
                )  # Sort is so we'll generate the same ones in future analyses
                dyn_vals = sorted_vals[:3]

            # print(f"Found {len(dyn_vals)} dynamic values for {target_var}: {dyn_vals}")

            # We found things dynamically. Cool. This is a single failure with details for these values
            if len(dyn_vals) > 0:
                return [
                    Failure(
                        f"dynval_{target_var}",
                        self.ANALYSIS_TYPE,
                        {"var": target_var, "values": dyn_vals, "source": "dynamic"},
                    )
                ]
            else:
                # We found nothing. Time to give up on this. Probably an uninteresting variable
                return []

        with open(pjoin(output_dir, missing_output)) as f:
            env_accesses = yaml.safe_load(f)
            assert isinstance(
                env_accesses, list
            ), f"Expected list of env accesses, got {env_accesses}"

        if isfile(pjoin(output_dir, shell_env_output)):
            # Shell plugin may have detected some env accesses too. Let's take a look
            seen_envs = {}  # name -> values
            with open(pjoin(output_dir, shell_env_output)) as f:
                for line in f.readlines()[1:]:  # Skip header
                    # Recover the env list from the line.
                    # This storage format is kinda gross
                    idx = line.index(",[")
                    envs = line[idx + 1 :].strip()
                    if not len(envs):
                        continue
                    env_tuples = eval(envs)  # XXX sad eval
                    if not len(env_tuples):
                        continue
                    for name, val in env_tuples:
                        if name not in seen_envs:
                            seen_envs[name] = set()
                        seen_envs[name].add(val)

            # Now look through the env names we've seen. Try finding any names that were always None.
            # Add these to our env_accesses list if they're not already there
            for k, v in seen_envs.items():
                # TODO: should we add the seen value to the failure?
                if len(k) == 0 or not k[0].isalpha():
                    # We only want sane variable names. Exclude anything that starts with a symbol or non-alpha
                    continue
                if None in v and k not in env_accesses:
                    env_accesses.append(k)

        # for env in env_accesses:
        #    if not (2 < len(env) < 16):
        #        print(f"Skipping unset env {env} since it's too long or too short")
        default_env_vars = DEFAULT_ENV_VARS
        if "env" in config:
            # Track the set env variables so we know they're set
            default_env_vars += list(config["env"].keys())

        env_failures = [
            Failure("unset_" + env, self.ANALYSIS_TYPE, {"var": env, "source": "unset"})
            for env in env_accesses
            if 2 < len(env) < 16 and env not in default_env_vars
        ]

        # Another failure class is MTD accesses - if we have anything in env_mtd.txt
        # we'll add those as failures too. TODO
        # if isfile(pjoin(output_dir, mtd_output)):
        #    with open(pjoin(output_dir, mtd_output)) as f:
        #        mtd_accesses = [x.strip() for x in f.readlines() if len(x.strip()) > 0]
        #        # Value is only used for pretty-printing here
        #        env_failures += [Failure('mtd_' + mtd, self.ANALYSIS_TYPE, {'var': mtd, 'value':'[mtd]', 'source': 'mtd'})
        #                         for mtd in mtd_accesses]

        return env_failures

    def get_potential_mitigations(self, config, failure: Failure) -> List[Mitigation]:
        # If we just ran a dynamic search that's the only mitigation we'll apply
        # Expect failure_type to be envone, not env?

        fail_info = failure.info
        var_name = fail_info["var"]

        if config and any(
            v == ENV_MAGIC_VAL for k, v in config[self.ANALYSIS_TYPE].items()
        ):
            results = []
            if fail_info["source"] != "dynamic":
                # Should only be here after a dynamic search
                raise ValueError(
                    f"Expected source=dynamic for config with {ENV_MAGIC_VAL} but got {fail_info}"
                )

            if len(fail_info["values"]) > 0:
                # If we found some dynamic values, those are our mitigations!
                # We'll have a base weight of 20 and we'll add up to 50 depending on length
                for dynval in fail_info["values"]:
                    if len(dynval) < 1:
                        continue
                    if len(dynval) > 16:
                        # Warn but skip
                        print(
                            f"Ignoring potential dynval {dynval} since it's quite long"
                        )
                        continue

                    weight = 10 + max(min(20, len(dynval)), 90)
                    results.append(
                        Mitigation(
                            dynval,
                            self.ANALYSIS_TYPE,
                            {
                                "value": dynval,
                                "var": var_name,
                                "weight": weight,
                                "source": "from_dynamic",
                            },
                        )
                    )
            else:
                # Otherwise, dynamic search failed. If we still see varname as 'unset' in our failure log,
                # it's not being controlled by the kernel boot args - we should store this in our global
                # state and move on. (TODO). For now we'll just add some defaults whenever we don't get
                # results from dynamic, but if we were smarter we'd be able to give up on un-settable vars
                for val in self.DEFAULT_VALUES:
                    results.append(
                        Mitigation(
                            val,
                            self.ANALYSIS_TYPE,
                            {
                                "value": val,
                                "var": var_name,
                                "weight": 0.1,
                                "source": "default",
                            },
                        )
                    )
            return results

        # If we get here we're NOT doing a dynamic search.
        existing_vars = list(config[self.ANALYSIS_TYPE].keys()) if config else []
        if var_name in existing_vars:
            # Can't mitigate an unset variable that's already set by our config. If it was magic
            # value, we would've handled above. But we're here so it must be set to a concrete value
            # raise ValueError(f"{var_name} was already set but it was also our failure - what's happening")
            return []

        # Otherwise: variable was unset. The only mitigation we can propose here is to try magic values.
        # If that fails, we'll add some defaults
        return [
            Mitigation(
                "magic_" + var_name,
                self.ANALYSIS_TYPE,
                {
                    "value": ENV_MAGIC_VAL,
                    "var": var_name,
                    "weight": 1,
                    "source": "need_dynamic",
                },
                exclusive=True,
            )
        ]

    def implement_mitigation(
        self, config: Configuration, failure: Failure, mitigation: Mitigation
    ) -> List[Configuration]:
        # Given a mitigation, add it to a copy of the config and return
        name = f'{mitigation.info["var"]}={mitigation.info["value"][:4]}'

        assert (
            mitigation.type == self.ANALYSIS_TYPE
        ), f"Unexpected mitigation type: {mitigation.type}"

        # Properties are the parent's plus we set the variable to the mitigation value
        new_props = deepcopy(config.info)
        new_props[self.ANALYSIS_TYPE][mitigation.info["var"]] = mitigation.info["value"]

        exclusive = None

        if mitigation.info["source"] == "need_dynamic":
            # Exclusive node!
            exclusive = self.ANALYSIS_TYPE
        return [Configuration(name, new_props, exclusive=exclusive)]
