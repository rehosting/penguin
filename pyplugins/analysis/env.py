import itertools
import re
from os.path import join as pjoin
from penguin import plugins, Plugin, yaml

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
    # Vars that control penguin's init script - ignore
    "SHARED_DIR",
    "ROOT_SHELL",
    "WWW",
    "CID",
    "STRACE",
    "igloo_init"
]


class EnvTracker(Plugin):
    """
    Track environment variables that appear to be read
    and store them in missing_output if they aren't in our env
    """

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.env_vars = set()  # set of env vars that were read through libc getenv
        self.uboot_vars = set()  # set of env vars that were read through libc getenv
        self.mtd_vars = set()  # set of mtd partitions read out of /proc/mtd
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        self.default_env_vars = DEFAULT_ENV_VARS
        self.conf = self.get_arg("conf")
        if "env" in self.conf:
            # Track the set env variables so we know they're set
            self.default_env_vars += list(self.conf["env"].keys())
        plugins.subscribe(plugins.Events, "igloo_getenv", self.on_getenv)
        plugins.subscribe(plugins.Events, "igloo_strstr", self.on_strstr)

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


class TargetCmp(Plugin):
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

    def __init__(self):
        self.target_key = self._get_target_str_in_config(self.get_arg("conf"))
        if not self.target_key:
            return
        panda = self.panda

        # XXX: We need to disable tb_chaining to detect more comparisons. Unfortunately
        # this hurts performance, but without it we definitely miss some comparisons
        # in targetcmp/callwitharg/callstack_instr.
        panda.disable_tb_chaining()
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

        plugins.subscribe(plugins.Events, "igloo_string_cmp", self.on_string_compare)

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
