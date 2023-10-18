from pandare import PyPlugin
from os.path import dirname
import yaml

# WIP: pair with generate_bb_profile.py. Run target busybox with a custom init
# script and dynamically search for getenv-style function calls in that busybox

class FindCmp(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")

        with open(dirname(self.outdir) + "/config.yaml", "r") as f:
            self.current_config = yaml.safe_load(f)

        # Read current_config[files] until we find a one with 'path' = '/igloo/init/test'
        #'contents': '#!{bb_path}\n\necho $testvarone; eval $testvartwo; ls $testvarthree;\n'

        envvars = set()
        for f in self.current_config['files']:
            if f['path'] == '/igloo/init_test':
                # We found our file, let's parse it!
                # File contains a few $vars - we want to extract these strings
                for tok in " ".join(f['contents'].splitlines()).replace('"', "").split(" "):
                    if tok.startswith("$"):
                        envvars.add(tok)

        for envvar in envvars:
            print("FindCMP searching for env var:", envvar)

        if len(envvars) > 0:
            print("FindCMP looking for env vars:", envvars)
            panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
            panda.load_plugin("callwitharg", args={
                "verbose": 1,
                "targets": "_".join([x for x in envvars]),
                "output_file": self.outdir + "/findcall.txt"} # XXX This one is consumed by findcall need to fix that bug
                )
            panda.load_plugin("findcall", args={
                "output_file": self.outdir + "/findcall.txt", # XXX NYI
            })
