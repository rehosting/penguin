from penguin import getColoredLogger
from pandare import PyPlugin
import time
import logging

class Health(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.start_time = time.time()
        self.exiting = False
        self.logger = getColoredLogger("plugins.health")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # XXX no longer used to track time
        self.events = { # Class: [(time, score)]
            'nproc': [(0, 0)],
            'nproc_args': [(0, 0)],
            'nfiles': [(0, 0)],
            'nuniquedevs': [(0, 0)],
            'nbound_sockets': [(0, 0)],
            'nsyscalls': [(0, 0)],
            'nexecs': [(0, 0)],
            'nexecs_args': [(0, 0)],
            'nioctls': [(0, 0)]
        }

        self.final_events = {k : 0 for k in self.events.keys()}

        # Per event data storage
        self.binds = set()
        self.procs = set()
        self.procs_args = set()
        self.devs = set()

        self.ppp_cb_boilerplate('igloo_exec')

        #panda.load_plugin("coverage", {"filename": self.outdir+"/cov.csv", "mode": "osi-block",
        #                               "summary": 'true'})
        self.ppp.Core.ppp_reg_cb('igloo_bind', self.health_on_bind)
        self.ppp.Core.ppp_reg_cb('igloo_open', self.health_detect_opens)

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
                self.increment_event('nexecs')

            # Now get args
            try:
                argv_buf = panda.virtual_memory_read(cpu, argv_ptr, 96, fmt='ptrlist')
            except ValueError:
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

            try:
                self.ppp_run_cb('igloo_exec', cpu, fname, nullable_argv)
            except Exception as e:
                self.logger.error(f"Exn in health.igloo_exec")
                self.logger.exception(e)

            unique_name = f"{fname} {' '.join(argv)}"
            if unique_name not in self.procs_args:
                self.procs_args.add(unique_name)
                self.increment_event('nexecs_args')


    def health_on_bind(self, cpu, procname, is_ipv4, is_stream, port, sin_addr):
        if self.exiting:
            return
        ipvn = 4 if is_ipv4 else 6

        if (ipvn, port not in self.binds):
            self.binds.add((ipvn, port))
            self.increment_event('nbound_sockets')

    def health_detect_opens(self, cpu, fname, fd):
        if self.exiting:
            return
        if fname.startswith("/dev"):
            self.log_dev_open(fname)

    def increment_event(self, event):
        '''
        Increment the score for the given event
        '''
        #last = self.events[event][-1]
        #last_score = last[1]
        #rel_time = time.time() - self.start_time
        #self.events[event].append((rel_time, last_score + 1))
        self.final_events[event] += 1


    def log_dev_open(self, fname):
        if self.exiting:
            return
        if fname not in self.devs:
            self.devs.add(fname)
            self.increment_event('nuniquedevs')
            self.logger.debug("New device opened: %s", fname)

    def uninit(self):
        self.exiting = True
        self.logger.debug("Unloading")
        # Dump self.events to outdir/health.csv
        # Format: class, time, score

        # XXX Seems to deadlocks in here?
        # Dump to CSV over time
        #with open(f"{self.outdir}/health.csv", 'w') as f:
        #    f.write("class,time,score\n")
        #    for cls, details in self.events.items():
        #        for time, score in details:
        #            f.write(f"{cls},{time},{score}\n")

        # And dump final values to outdir/health_final.yaml
        #with open(f"{self.outdir}/health_final.yaml", 'w') as f:
        #    # For each event, dump the final score
        #    for cls, details in self.events.items():
        #        f.write(f"  {cls}: {details[-1][1]}\n")
        with open(f"{self.outdir}/health_final.yaml", 'w') as f:
            for cls, score in self.final_events.items():
                f.write(f"  {cls}: {score}\n")

        # Dump list of devices accessed
        with open(f"{self.outdir}/health_devices_accessed.txt", 'w') as f:
            for dev in sorted(self.devs):
                f.write(f"{dev}\n")

        # Dump processes executed
        with open(f"{self.outdir}/health_procs.txt", 'w') as f:
            for proc in sorted(self.procs):
                f.write(f"{proc}\n")

        # Dump processes executed with args
        with open(f"{self.outdir}/health_procs_with_args.txt", 'w') as f:
            for proc in sorted(self.procs_args):
                f.write(f"{proc}\n")