import time
from os import path
from pandare import PyPlugin
from penguin import getColoredLogger
import Levenshtein as lv


class FICD:
    """
    FICD metric based on Pandawan, see https://github.com/BUseclab/Pandawan/blob/main/plugins/pandawan/ficd.py
    The goal here is to produce a faithful representation of that metric in PENGUIN

    "To this end, FICD considers that a firmware image reached If in if no previously unseen (i.e., unique) tasks are launched within tf seconds. We refer to tf as the time frame parameter"
    "In our re-hosting experiments we use three (Py)PANDA plugins (coverage, syscalls_logger, and SyscallToKmodTracer) along with the FICD plugin, which results in the optimal tf = 220sec and tf = 300sec"
    """
    def __init__(self, start_time, outdir, time_frame=300):
        self.time_frame = time_frame
        self.init_time = start_time
        self.unique_proc_times = {}
        self.seen_procs = set()
        self.prev_time = time.time()
        self.if_reached = False
        self.outfile = path.join(outdir, "ficd.txt")
        self.last_proc_time = 0

        # FICD isn't reached until it is
        with open(self.outfile, "w") as f:
            f.write("0")

    def on_exec(self, newproc):
        self.prev_time = time.time()

        for proc in self.seen_procs:
            lev_ratio = lv.ratio(proc, newproc)
            if lev_ratio >= 0.5:
                self.unique_proc_times[newproc] = [round(self.prev_time - self.init_time, 2), "Not Unique"]
                return

        self.last_proc_time = self.prev_time
        self.seen_procs.add(newproc)
        self.unique_proc_times[newproc] = [round(self.prev_time - self.init_time, 2), "Unique"]

    def done(self):
        """
        TODO: Since we aren't killing emulation after "If" is reached, it is possible that we stick 
        around long enough for a new unique process to
        be created. Which would violate the underlying assumption about the
        latching nature of FICD. Might be worth tracking to see if this ever happens.
        """
        prev_time = time.time()
        measured_tf = prev_time - self.last_proc_time
        if measured_tf > self.time_frame:
            with open(self.outfile, "w") as f:
                f.write("1")
        with open(path.join(path.dirname(self.outfile), "ficd_times.txt"), "w") as f:
            f.write(f"Measured TF: {measured_tf}\n")
            f.write(f"Last Proc Start Time: {self.last_proc_time - self.init_time}\n")
            f.write(f"Total Execution Time: {prev_time - self.init_time}\n")
            f.write(f"Time Executed past TF: {measured_tf - self.time_frame}\n")


class Health(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.panda = panda
        self.start_time = time.time()
        self.exiting = False
        self.logger = getColoredLogger("plugins.health")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        if self.get_arg_bool("ficd"):
            self.ficd = FICD(self.start_time, self.outdir)
        else:
            self.ficd = None

        # XXX no longer used to track time
        self.events = {  # Class: [(time, score)]
            "nproc": [(0, 0)],
            "nproc_args": [(0, 0)],
            "nfiles": [(0, 0)],
            "nuniquedevs": [(0, 0)],
            "nbound_sockets": [(0, 0)],
            "nsyscalls": [(0, 0)],
            "nexecs": [(0, 0)],
            "nexecs_args": [(0, 0)],
            "nioctls": [(0, 0)],
        }

        self.final_events = {k: 0 for k in self.events.keys()}

        # Per event data storage
        self.binds = set()
        self.procs = set()
        self.procs_args = set()
        self.devs = set()

        self.ppp_cb_boilerplate("igloo_exec")

        # panda.load_plugin("coverage", {"filename": self.outdir+"/cov.csv", "mode": "osi-block",
        #                               "summary": 'true'})
        self.ppp.Events.listen("igloo_ipv4_bind", self.on_ipv4_bind)
        self.ppp.Events.listen("igloo_ipv6_bind", self.on_ipv6_bind)
        self.ppp.Events.listen("igloo_open", self.health_detect_opens)

        # TODO: replace with hypercall mechanism
        @panda.ppp("syscalls2", "on_sys_execve_enter")
        def health_execve(cpu, pc, fname_ptr, argv_ptr, envp):
            if self.exiting:
                return
            try:
                fname = panda.read_str(cpu, fname_ptr)
            except ValueError:
                return

            if fname not in self.procs:
                self.procs.add(fname)
                self.increment_event("nexecs")

            # Now get args
            try:
                argv_buf = panda.virtual_memory_read(cpu, argv_ptr, 96, fmt="ptrlist")
            except ValueError:
                if self.ficd:
                    self.ficd.on_exec(fname)
                return

            # Read each argument pointer into argv list
            argv = []
            nullable_argv = []
            for ptr in argv_buf:
                if ptr == 0:
                    break
                try:
                    argv.append(panda.read_str(cpu, ptr))
                    nullable_argv.append(panda.read_str(cpu, ptr))
                except ValueError:
                    argv.append(f"(error: 0x{ptr:x})")
                    nullable_argv.append(None)
            self.ficd.on_exec(fname + " " + " ".join(argv))

            try:
                self.ppp_run_cb("igloo_exec", cpu, fname, nullable_argv)
            except Exception as e:
                self.logger.error("Exn in health.igloo_exec")
                self.logger.exception(e)

            unique_name = f"{fname} {' '.join(argv)}"
            if unique_name not in self.procs_args:
                self.procs_args.add(unique_name)
                self.increment_event("nexecs_args")

    def on_ipv4_bind(self, cpu, port, is_steam):
        self.health_on_bind(cpu, True, port)

    def on_ipv6_bind(self, cpu, port, is_steam):
        self.health_on_bind(cpu, False, port)

    def health_on_bind(self, cpu, is_ipv4, port):
        if self.exiting:
            return
        ipvn = 4 if is_ipv4 else 6

        if (ipvn, port) not in self.binds:
            self.binds.add((ipvn, port))
            self.increment_event("nbound_sockets")

    def health_detect_opens(self, cpu, fname, fd):
        if self.exiting:
            return
        if fname.startswith("/dev"):
            self.log_dev_open(fname)

    def increment_event(self, event):
        """
        Increment the score for the given event
        """
        # last = self.events[event][-1]
        # last_score = last[1]
        # rel_time = time.time() - self.start_time
        # self.events[event].append((rel_time, last_score + 1))
        self.final_events[event] += 1

    def log_dev_open(self, fname):
        if self.exiting:
            return
        if fname not in self.devs:
            self.devs.add(fname)
            self.increment_event("nuniquedevs")
            self.logger.debug("New device opened: %s", fname)

    def uninit(self):
        self.exiting = True
        self.logger.debug("Unloading")
        # Dump self.events to outdir/health.csv
        # Format: class, time, score

        # XXX Seems to deadlocks in here?
        # Dump to CSV over time
        # with open(f"{self.outdir}/health.csv", 'w') as f:
        #    f.write("class,time,score\n")
        #    for cls, details in self.events.items():
        #        for time, score in details:
        #            f.write(f"{cls},{time},{score}\n")

        # And dump final values to outdir/health_final.yaml
        # with open(f"{self.outdir}/health_final.yaml", 'w') as f:
        #    # For each event, dump the final score
        #    for cls, details in self.events.items():
        #        f.write(f"  {cls}: {details[-1][1]}\n")
        with open(f"{self.outdir}/health_final.yaml", "w") as f:
            for cls, score in self.final_events.items():
                f.write(f"  {cls}: {score}\n")

        # Dump list of devices accessed
        with open(f"{self.outdir}/health_devices_accessed.txt", "w") as f:
            for dev in sorted(self.devs):
                f.write(f"{dev}\n")

        # Dump processes executed
        with open(f"{self.outdir}/health_procs.txt", "w") as f:
            for proc in sorted(self.procs):
                f.write(f"{proc}\n")

        # Dump processes executed with args
        with open(f"{self.outdir}/health_procs_with_args.txt", "w") as f:
            for proc in sorted(self.procs_args):
                f.write(f"{proc}\n")
        if self.ficd:
            self.ficd.done()
