import time
from os import path
from penguin import getColoredLogger, plugins, Plugin


class Health(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.start_time = time.time()
        self.exiting = False
        self.logger = getColoredLogger("plugins.health")

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

        # panda.load_plugin("coverage", {"filename": self.outdir+"/cov.csv", "mode": "osi-block",
        #                               "summary": 'true'})
        plugins.subscribe(plugins.Events, "igloo_ipv4_bind", self.on_ipv4_bind)
        plugins.subscribe(plugins.Events, "igloo_ipv6_bind", self.on_ipv6_bind)
        plugins.subscribe(plugins.Events, "igloo_open", self.health_detect_opens)
        # Use the Execs plugin interface for exec events
        plugins.subscribe(plugins.Execs, "exec_event", self.health_exec_event)

    def health_exec_event(self, event):
        if self.exiting:
            return
        fname = event.get('procname', None)
        argv = event.get('argv', [])
        if fname and fname not in self.procs:
            self.procs.add(fname)
            self.increment_event("nexecs")
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

        # In case we are first, make sure outdir exists
        if not path.exists(self.outdir):
            path.makedirs(self.outdir)
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
