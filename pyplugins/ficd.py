import time
from os import path
from pandare import PyPlugin
from penguin import getColoredLogger
import Levenshtein as lv


class FICD(PyPlugin):
    """
    FICD metric based on Pandawan, see https://github.com/BUseclab/Pandawan/blob/main/plugins/pandawan/ficd.py
    The goal here is to produce a faithful representation of that metric in PENGUIN

    "To this end, FICD considers that a firmware image reached Ifin in if no previously unseen (i.e., unique) tasks are launched within tf seconds. We refer to tf as the time frame parameter"
    "In our re-hosting experiments we use three (Py)PANDA plugins (coverage, syscalls_logger, and SyscallToKmodTracer) along with the FICD plugin, which results in the optimal tf = 220sec and tf = 300sec"
    """

    def __init__(self, panda):
        self.time_frame = 300  # set up as arg at some point
        self.init_time = time.time()
        self.boot_time = self.init_time
        self.unique_proc_times = {}
        self.seen_procs = set()
        self.prev_time = time.time()
        self.ifin_reached = False
        self.measured_tf = 0
        self.last_proc_time = 0
        self.outfile = path.join(self.get_arg("outdir"), "ficd.yaml")
        self.panda = panda
        self.logger = getColoredLogger("plugins.ficd")
        self.stop_on_if = self.get_arg_bool("stop_on_if")
        self.logger.info("Loading FICD plugin")

        @panda.ppp("syscalls2", "on_sys_execve_enter")
        def ficd_execve(cpu, pc, fname_ptr, argv_ptr, envp):
            try:
                fname = self.panda.read_str(cpu, fname_ptr)
            except ValueError:
                return

            # Now get args
            try:
                argv_buf = self.panda.virtual_memory_read(cpu, argv_ptr, 96, fmt="ptrlist")
            except ValueError:
                self.on_exec(fname)
                return

            # Read each argument pointer into argv list
            argv = []
            nullable_argv = []
            for ptr in argv_buf:
                if ptr == 0:
                    break
                try:
                    argv.append(self.panda.read_str(cpu, ptr))
                    nullable_argv.append(self.panda.read_str(cpu, ptr))
                except ValueError:
                    argv.append(f"(error: 0x{ptr:x})")
                    nullable_argv.append(None)
            self.on_exec(fname + " " + " ".join(argv))

    def reset(self):
        self.ifin_reached = False
        self.init_time = time.time()

    def on_exec(self, newproc):
        self.prev_time = time.time()

        for proc in self.seen_procs:
            lev_ratio = lv.ratio(proc, newproc)
            if lev_ratio >= 0.5:
                self.unique_proc_times[newproc] = [round(self.prev_time - self.init_time, 2), "Not Unique"]
                measured_tf = self.prev_time - self.last_proc_time
                if measured_tf > self.time_frame:
                    self.ifin_reached = True
                    self.measured_tf = measured_tf
                    self.ifin_time = self.prev_time-self.init_time
                    self.logger.info(f"FICD Ifin reached on exec occuring {self.prev_time - self.init_time} after start")
                    if self.stop_on_if:
                        self.logger.warning(f"Stopping on Ifin reached...")
                        self.panda.end_analysis()
                return

        if self.ifin_reached:
            self.logger.warning(f"Warning! FICD Ifin reached but new exec {newproc} was seen at time {self.prev_time - self.init_time}. System is likely being exercised.")
        self.last_proc_time = self.prev_time
        self.seen_procs.add(newproc)
        self.unique_proc_times[newproc] = [round(self.prev_time - self.init_time, 2), "Unique"]

    def uninit(self):
        prev_time = time.time()
        with open(self.outfile, "w") as f:
            f.write(f"ifin_reached: {self.ifin_reached}\n")
            if self.ifin_reached:
                f.write(f"ifin_time: {self.ifin_time}\n")
            f.write(f"boot_time: {self.boot_time}\n")
            f.write(f"init_time: {self.init_time}\n")
            f.write(f"measured_tf: {self.measured_tf}\n")
            f.write(f"last_proc_start: {self.last_proc_time - self.init_time}\n")
            f.write(f"total_execution_time: {prev_time - self.init_time}\n")
            f.write(f"time_past_tf: {self.measured_tf - self.time_frame}\n")
