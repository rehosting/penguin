from pandare import PyPlugin
from os import environ as env
import socket
import time
import random


class Health(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        CID = self.get_arg("CID")

        self.start_time = time.time()

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

        # Per event data storage
        self.binds = set()
        self.procs = set()
        self.procs_args = set()
        self.devs = set()

        panda.load_plugin("coverage", {"filename": self.outdir+"/cov.csv", "mode": "osi-block",
                                       "summary": 'true'})

        @panda.ppp("syscalls2", "on_sys_bind_enter")
        def health_bind(cpu, pc, sockfd, sockaddrin_addr, addrlen):
            try:
                sin_family  = panda.virtual_memory_read(cpu, sockaddrin_addr, 2, fmt='int')
                sockaddr_in = panda.virtual_memory_read(cpu, sockaddrin_addr, 14)
            except ValueError:
                print("Could not read SIN_FAMILY on bind")
                return

            if sin_family not in [2, 10]: # IPv4, IPv6
                return
            
            # Calculate port
            try: # port is 2 bytes starting 2 bytes into the struct for both v4/v6
                sin_port = panda.virtual_memory_read(cpu, sockaddrin_addr+2, 2, fmt='int')
                sin_port = int.from_bytes(int.to_bytes(sin_port, 2, panda.endianness), 'little')
                port  = int(socket.htons(sin_port))
            except ValueError:
                print("Could not read SIN_PORT on bind")
                return
            
            if (sin_family, sin_port not in self.binds):
                self.binds.add((sin_family, sin_port))
                self.increment_event('nbound_sockets')

        @panda.ppp("syscalls2", "on_sys_execve_enter")
        def health_execve(cpu, pc, fname_ptr, argv_ptr, envp):
            try:
                fname = panda.read_str(cpu, fname_ptr)
            except ValueError:
                return

            if fname not in self.procs:
                self.procs.add(fname)
                self.increment_event('nexecs')

            # Now get args
            try:
                argv_buf = panda.virtual_memory_read(cpu, argv_ptr, 100, fmt='ptrlist')
            except ValueError:
                return
            
            # Read each argument pointer into argv list
            argv = []
            for ptr in argv_buf:
                if ptr == 0:
                    break
                try:
                    argv.append(panda.read_str(cpu, ptr))
                except ValueError:
                    argv.append(f"(error: 0x{ptr:x})")

            unique_name = f"{fname} {' '.join(argv)}"
            if unique_name not in self.procs_args:
                self.procs_args.add(unique_name)
                self.increment_event('nexecs_args')

        @panda.ppp("syscalls2", "on_sys_open_return")
        def detect_dev_open(cpu, pc, fname, mode, flags):
            # Just get pathname:
            fname = panda.read_str(cpu, fname)
            if fname.startswith("/dev"):
                self.log_dev_open(fname, mode)

        @panda.ppp("syscalls2", "on_sys_openat_return")
        def detect_dev_openat(cpu, pc, fd, fname, mode, flags):
            base = ''
            if fd != -100: # CWD
                proc = self.panda.plugins['osi'].get_current_process(cpu)
                if proc == self.panda.ffi.NULL:
                    return
                basename_c = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
                if basename_c == self.panda.ffi.NULL:
                    return
                base = self.panda.ffi.string(basename_c)
            path = base + "/" + panda.read_str(cpu, fname)
            if path.startswith("/dev"):
                self.log_dev_open(path, mode)


    def increment_event(self, event):
        '''
        Increment the score for the given event
        '''
        last = self.events[event][-1]
        last_score = last[1]
        rel_time = time.time() - self.start_time
        self.events[event].append((rel_time, last_score + 1))


    def log_dev_open(self, fname, mode):
        if fname not in self.devs:
            self.devs.add(fname)
            self.increment_event('nuniquedevs')

    def uninit(self):
        print("Health unloaded")
        # Dump self.events to outdir/health.csv
        # Format: class, time, score

        # Dump to CSV over time
        with open(f"{self.outdir}/health.csv", 'w') as f:
            f.write("class,time,score\n")
            for cls, details in self.events.items():
                for time, score in details:
                    f.write(f"{cls},{time},{score}\n")

        # And dump final values to outdir/health_final.yaml
        with open(f"{self.outdir}/health_final.yaml", 'w') as f:
            # For each event, dump the final score
            for cls, details in self.events.items():
                f.write(f"  {cls}: {details[-1][1]}\n")

        # Dump list of devices accessed
        with open(f"{self.outdir}/devices_accessed.txt", 'w') as f:
            for dev in self.devs:
                f.write(f"{dev}\n")