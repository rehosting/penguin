from pandare import PyPlugin
from os.path import dirname, isfile, join as pjoin
import yaml
from copy import deepcopy

target_str = 'DYNVAL'
output_file = "/targetcmp.txt" # C++ analysis with callstackinstr
output_file2 = "/targetcmppy.txt" # Python with libc fn hooks

def propose_configs(config, outdir, quiet=False):
    # Open [outdir]/targetcmp.txt and read each line
    if not isfile(f"{outdir}/{output_file}") or not isfile(f"{outdir}/{output_file2}"):
        print("WARNING: missing targetcmp results - was plugin loaded?", outdir)
        return []

    target_var = [x.split("=")[0] for x in config['append'] if f'={target_str}' in x][0]

    new_configs = []
    compared_vals = set()

    for line in open(f"{outdir}/{output_file}", "rb").read().splitlines() +
                open(f"{outdir}/{output_file2}", "rb").read().splitlines():

        l = line.strip()
        # Check if line is alphanumeric or _ or -
        if len(l) and l.replace(b"_", b"").replace(b"-", b"").isalnum():
            compared_vals.add(l.decode(errors='ignore'))

    for new_val in compared_vals:
        new_config = deepcopy(config)

        new_config['append'] = [f"{target_var}={new_val}" if ('=' in x and x.split('=')[0] == target_var) else x for x in config['append']]
        new_config['meta']['delta'].append(f"env {target_var}={new_val}")

        # We saw a concrete comparison, I guess that beats just guessing at random
        # WEIGHT 2
        new_configs.append((2, new_config))

    return new_configs


class TargetCmp(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.env_var_matches = set()

        with open(dirname(self.outdir) + "/config.yaml", "r") as f:
            self.current_config = yaml.safe_load(f)

        if 'append' not in self.current_config and not any([f"={target_str}" in x for x in self.current_config['append']]):
            print("TargetCmp inactive")
            return
        
        # XXX: should check to make sure we never have 2 vars = target_str at once?

        print("TargetCmp active, outdir=", self.outdir)
        # Config specifies DYNVAL, so we'll dynamically analyze
        panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
        panda.load_plugin("targetcmp", args={"output_file": pjoin(self.outdir, output_file), "target_str": target_str})

        # Also explicitly hook strcmp/strncmp
        @panda.hook_symbol("libc-", "strcmp")
        def hook_strcmp(cpu, tb, h):
            try:
                str1 = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
                str2 = panda.read_str(cpu, panda.arch.get_arg(cpu, 1))
            except ValueError:
                return

            if str1 == target_str:
                self.env_var_matches.add(str2)
            elif str2 == target_str:
                self.env_var_matches.add(str1)

        @panda.hook_symbol("libc-", "strncmp")
        def hook_strncmp(cpu, tb, h):
            # Get two strings being compared - are either IGLOOENVVAR
            try:
                str1 = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
                str2 = panda.read_str(cpu, panda.arch.get_arg(cpu, 1))
            except ValueError:
                return

            if str1 == target_str:
                self.env_var_matches.add(str2)
            elif str2 == target_str:
                self.env_var_matches.add(str1)

    def unint(self):
        print("TargetCmp(PY) shutting down")
        with open(pjoin(self.outdir, output_file2), "w") as f:
            for x in self.env_var_matches:
                f.write(x + "\n")