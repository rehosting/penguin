import signal
import os
import time
import threading
from pandare import PyPlugin
try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    import yaml
    PenguinAnalysis = object

class Core(PyPlugin):
    '''
    Simple sanity checks and basic core logic.
    1) Validate we're getting the expected args.
    2) Write config and loaded plugins to output dir
    3) On siguser1 gracefully shutdown emulation
    4) After a (non-crash) shutdown, create a .ran file in the output
       if and only if there's no kernel crash in console.log.

    TODO: can we detect if another pyplugin raised an uncaught
    exception and abort?
    '''

    def __init__(self, panda):
        for arg in "plugins CID conf fs fw outdir".split():
            if not self.get_arg(arg):
                raise ValueError(f"[core] Missing required argument: {arg}")

        self.outdir = self.get_arg("outdir")
        plugins = self.get_arg("plugins")
        conf = self.get_arg("conf")

        # If we have an option of root_shell we need to add ROOT_SHELL=1 into env
        # so that the init script knows to start a root shell
        if conf['core'].get('root_shell', False):
            conf['env']['ROOT_SHELL'] = "1"

        # Same thing, but for a shared directory
        if conf['core'].get('shared_dir', False):
            conf['env']['SHARED_DIR'] = "1"

        # Record loaded plugins
        with open(os.path.join(self.outdir, "core_plugins.yaml"), "w") as f:
            f.write(yaml.dump(plugins)) # Names and args

        # Record config in outdir:
        with open(os.path.join(self.outdir, "core_config.yaml"), "w") as f:
            f.write(yaml.dump(self.get_arg("conf")))

        signal.signal(signal.SIGUSR1, self.graceful_shutdown)

        # Load the "timeout" plugin which is a misnomer - it's just going
        # to report the number of blocks executed at shutdown.
        # XXX bb_limit / unique_bbs break our pypanda based analyses
        # because end_analysis is never called

        if self.get_arg("timeout") is not None:
            # If a timeout is provided, enforce it
            timeout = int(self.get_arg("timeout"))

            # Log info on how many blocks get executed
            log_path = self.outdir + "/core_shutdown.csv"
            panda.load_plugin("timeout", {
                    #"bb_limit": BB_MAX,
                    #'unique_bbs': UNIQUE,
                    "log": log_path
                    })

            self.shutdown_event = threading.Event()
            self.shutdown_thread = threading.Thread(
                    target=self.shutdown_after_timeout,
                    args=(panda, timeout, self.shutdown_event))
            self.shutdown_thread.start()

    def shutdown_after_timeout(self, panda, timeout, shutdown_event):
        wait_time = 0
        while wait_time < timeout:
            # Check if the event is set
            if shutdown_event.is_set():
                try:
                    print("Shutdown thread: Guest shutdown detected, exiting thread.")
                except OSError:
                    pass # Can't print but it's not important
                return

            # Sleep briefly
            time.sleep(1)
            wait_time += 1

        try:
            print(f"Shutdown thread: execution timed out after {timeout}s - shutting down guest")
        except OSError:
            # During shutdown, stdout might be closed!
            pass
        panda.end_analysis()

    def graceful_shutdown(self, sig, frame):
        print("Caught SIGUSR1 - gracefully shutdown emulation")
        self.panda.end_analysis()

    def uninit(self):
        if hasattr(self, 'shutdown_event'):
            # Tell the shutdown thread to exit if it was started
            self.shutdown_event.set()

        # Create .ran
        open(os.path.join(self.outdir, ".ran"), "w").close()

class CoreAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "core"
    VERSION = "1.0.0"
    def parse_failures(self, output_dir):
        '''
        We don't really parse failures mitigations, we just make sure there's no python
        errors during our analysis
        '''
        # First: sanity checks. Do we see any errors in console.log? If so abort
        with open(os.path.join(output_dir, "console.log"), "rb") as f:
            for line in f:
                if b"BUG" in line:
                    print(f"KERNEL BUG: {repr(line)}")
                    raise RuntimeError(f"Found BUG in {output_dir}/console.log")

        with open(os.path.join(output_dir, "qemu_stderr.txt")) as f:
            for line in f.readlines():
                if "Traceback " in line:
                    raise RuntimeError(f"Python analysis crashed in {output_dir}")
        return {}

    def get_mitigations_from_static(self, varname, values):
        return []

    def get_potential_mitigations(self, config, failure):
        return []

    def implement_mitigation(self, config, failure, mitigation):
        raise NotImplementedError("Core doesn't do mitigations")