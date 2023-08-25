import sys
import yaml
from os.path import dirname
from pandare import PyPlugin

# Paths we don't care about:
# /firmadyne/libnvram anything - this reveals the nvram values read though
# socket:{RAW,UDP,TCP,...}
# /proc/*/{mounts,stat,cmdline} - boring?

def ignore_ioctl_path(path):
    if path.startswith("/firmadyne/libnvram"):
        return True
    if path.startswith("/proc/"):
        return True
    if path.startswith("socket:"):
        return True
    if path.startswith("pipe:"):
        return True
    return False

def ignore_cmd(ioctl):
    # Ignore TTY ioctls, see ioctls.h for T*, TC*, and TIO* ioctls
    if ioctl >= 0x5400 and ioctl <= 0x54FF:
        return True
    return False

def path_interesting(path):
    # /dev and /proc are interesting, with some exceptions
    if path.startswith("/dev/"):
        return True

    if path.startswith("/proc/"):
        return True

    '''
    # Libraries are boring
    if path.endswith(".so"):
        return False

    if ".so." in path:
        return False

    # XXX default which way?
    return True
    '''

    return False

def var_interesting(var):
    for prefix in ["LC_", "LD_", "XDG_", "QT_", "GTK_", "GDK_", "GIO_", "PERL"]:
        if var.startswith(prefix):
            return False
        
    # Other unimportant variables we've seen before (expand as needed)
    if var in   'BLKID_FILE \
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
                TICKS_PER_USEC \
                TMPDIR \
                TZ'.split():
        return False

    # Otherwise it IS interesting
    return True

class FailDetect(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

        #self.panda.load_plugin("callstack_instr", {'stack_type': 'threaded'})

        self.ioctl_failures = {} # path: {IOCTL: (proc_name, [(mod, off), (mod, off), ...])}
        self.file_failures = {} # path: {mode: count}
        self.env_vars = set() # set of env vars that were read through libc getenv
        self.env_var_matches = set() # set of strings compared to 'IGLOOENVVAR' placeholder
        self.did_uninit = False

        with open(dirname(self.outdir) + "/config.yaml", "r") as f:
            self.current_config = yaml.safe_load(f)

        @panda.ppp("syscalls2", "on_sys_ioctl_return")
        def fail_detect_on_sys_ioctl_return(cpu, pc, fd, request, arg):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv < 0:

                if ignore_cmd(request):
                    return

                # Convert FD to filename with OSI
                proc = self.panda.plugins['osi'].get_current_process(cpu)
                if proc == self.panda.ffi.NULL:
                    return

                filename_c = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
                if filename_c == self.panda.ffi.NULL:
                    return

                filename = self.panda.ffi.string(filename_c).decode()

                if ignore_ioctl_path(filename):
                    return

                try:
                    proc_name = self.panda.get_process_name(cpu)
                except ValueError:
                    proc_name = None


                # Check if it's hooked with our ioctl faker (TODO: only if this is loaded?)
                if self.ppp.IoctlFakerC.is_ioctl_hooked(filename, request):
                    # We need to dynamically check this, unlike with files becasue we don't know
                    # the order in which the IoctlFakerC vs faildetect will run
                    return

                # Debug print
                module_name, offset = self.addr_to_mod_off(cpu, pc)
                print(f"IOCTL FAILURE: {filename} {request:#x} {proc_name} in {module_name} + {(offset if offset else 0):#x}", file=sys.stderr)

                if filename not in self.ioctl_failures:
                    self.ioctl_failures[filename] = {}

                if request not in self.ioctl_failures[filename]:
                    self.ioctl_failures[filename][request] = []

                # Result is a list of (proc_name, [(module_name, offset), ... callers]
                '''
                mod_offset_callers = []
                for c in self.panda.callstack_callers(10, cpu):
                    if c == 0:
                        break
                    mod_offset_callers.append(self.addr_to_mod_off(cpu, c))
                result = (proc_name, [(module_name, offset)] + mod_offset_callers)

                for callers in result[1]:
                    caller_module_name, caller_offset = callers
                    print(f"  {caller_module_name}, {hex(caller_offset) if caller_offset else '??'}", file=sys.stderr)

                if result not in self.ioctl_failures[filename][request]:
                    self.ioctl_failures[filename][request].append(result)
                '''

        @panda.ppp("syscalls2", "on_sys_open_return")
        def fail_detect_open(cpu, pc, fname, mode, flags):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            # Just get pathname:
            fname = panda.read_str(cpu, fname)
            self.log_open_failure(fname, rv, mode)

        @panda.ppp("syscalls2", "on_sys_openat_return")
        def fail_detect_openat(cpu, pc, fd, fname, mode, flags):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

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
            self.log_open_failure(path, rv, mode)

        @panda.hook_symbol("libc-", "getenv")
        def hook_getenv(cpu, tb, h):
            # Get the argument
            try:
                s = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
            except ValueError:
                return
            
            if not var_interesting(s):
                return
            self.env_vars.add(s)

        if any([x.split("=")[1] == 'IGLOOENVVAR' for x in self.current_config['append']]):
            # If our current config has an IGLOOENVVAR we can hook strcmp to see if it's being used
            # and if so, what it's being compared to - we can then use these as new hypotheses!

            @panda.hook_symbol("libc-", "strcmp")
            def hook_strcmp(cpu, tb, h):
                # Get two strings being compared - are either IGLOOENVVAR
                try:
                    str1 = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
                    str2 = panda.read_str(cpu, panda.arch.get_arg(cpu, 1))
                except ValueError:
                    return
                
                if str1 == 'IGLOOENVVAR':
                    self.env_var_matches.add(str2)
                elif str2 == 'IGLOOENVVAR':
                    self.env_var_matches.add(str1)

            @panda.hook_symbol("libc-", "strncmp")
            def hook_strncmp(cpu, tb, h):
                # Get two strings being compared - are either IGLOOENVVAR
                try:
                    str1 = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
                    str2 = panda.read_str(cpu, panda.arch.get_arg(cpu, 1))
                except ValueError:
                    return

                if str1 == 'IGLOOENVVAR':
                    self.env_var_matches.add(str2)
                elif str2 == 'IGLOOENVVAR':
                    self.env_var_matches.add(str1)

    # Calculate module name and offset
    def addr_to_mod_off(self, cpu, addr):
        mappings = self.panda.get_mappings(cpu)
        module_name = None
        offset = None
        for mapping in mappings:
            if mapping.base <= addr and (mapping.base + mapping.size) > addr:
                module_name = self.panda.ffi.string(mapping.name).decode() if mapping.name != self.panda.ffi.NULL else None
                offset = addr - mapping.base
                break
        return (module_name, offset)


    def log_open_failure(self, path, rv, mode):
        if not path_interesting(path):
            return
        
        if rv != -2: # ENOENT - we only care about files that don't exist
            return

        if path not in self.file_failures:
            self.file_failures[path] = {}
        
        if mode not in self.file_failures[path]:
            self.file_failures[path][mode] = 0
        self.file_failures[path][mode] += 1


    def uninit(self):
        if self.did_uninit:
            return # We're setting ourself up to work via ctrl-C or graceful shutdown
        self.did_uninit = True

        # Examine console.log for any "BUG" messages
        with open(self.outdir + "/console.log", "rb") as f:
            for line in f:
                if b"BUG" in line:
                    print("Found BUG LINE:", line)
                    raise ValueError("Found BUG in console.log")

        # Create .ran to indicate we ran this config - only if there's no bug!
        open(self.outdir + "/.ran", "w").close()

        # Dump all file failures to disk
        with open(self.outdir + "/file_failures.csv", "w") as f:
            f.write("filename,mode,count\n")
            for fname in self.file_failures:
                for mode in self.file_failures[fname]:
                    f.write(f"{fname},{mode},{self.file_failures[fname][mode]}\n")

        # Dump ioctl failures to disk
        #self.ioctl_failures[filename][request][proc_name][module_name][offset] += 1
        with open(self.outdir + "/ioctl_failures.csv", "w") as f:
            #f.write("filename,ioctl,procname,modname,offset,stackdepth\n")
            f.write("filename,ioctl\n")
            for filename, fname_details in self.ioctl_failures.items():
                print(fname_details, file=sys.stderr)
                for ioctl, ioctl_details in fname_details.items():
                    f.write(f"{filename},{ioctl:#x}\n")

                    # List of (proc_name, [(module_name, offset), ... callers]
                    '''
                    for proc_details in ioctl_details:
                        procname, callstack = proc_details[0], proc_details[1]
                        stack_depth = 0
                        for modname, offset in callstack:
                            if offset is not None:
                                f.write(f"{filename},{ioctl:#x},{procname},{modname},{offset:#x},{stack_depth}\n")
                            else:
                                # Modname and/or offset may be none, can't format with #x
                                f.write(f"{filename},{ioctl:#x},{procname},{modname},{offset},{stack_depth}\n")
                            stack_depth += 1
                    '''

        # Dump env vars to disk
        with open(self.outdir + "/env_vars.txt", "w") as f:
            for var in self.env_vars:
                f.write(var + "\n")

        # Dump env var matches to disk
        with open(self.outdir + "/env_var_matches.txt", "w") as f:
            for var in self.env_var_matches:
                f.write(var + "\n")

        with open(self.outdir + "/failures.yaml", "w") as f:
            yaml.dump({
                "file_failures": self.file_failures,
                "ioctl_failures": self.ioctl_failures,
                "getenv": self.env_vars,
                "getenv_matches": self.env_var_matches
            }, f)