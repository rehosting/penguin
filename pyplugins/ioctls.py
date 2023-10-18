from pandare import PyPlugin

from sys import path
from os.path import dirname, join as pjoin

outfile = "ioctls.yaml"

# Parse a given config to fake ioctls
'''
example_config = {
    ...
    'ioctls': [
      {
        'path': '/dev/dsa',
        'type': 'return_const',
        'cmd': 0x40046401,
        'val': 0
      },
    ]
}
'''


# XXX unused
def ignore_cmd(ioctl):
    # Ignore TTY ioctls, see ioctls.h for T*, TC*, and TIO* ioctls
    if ioctl >= 0x5400 and ioctl <= 0x54FF:
        return True
    return False

#XXX unused
def ignore_ioctl_path(path):
    # Paths we don't care about:
    # /firmadyne/libnvram anything - this reveals the nvram values read though
    # socket:{RAW,UDP,TCP,...}
    # /proc/*/{mounts,stat,cmdline} - boring?
    if path.startswith("/firmadyne/libnvram"):
        return True
    if path.startswith("/proc/"):
        return True
    if path.startswith("socket:"):
        return True
    if path.startswith("pipe:"):
        return True
    return False


class IoctlFakerC(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.default_retval = {} # path -> default_retval
        self.printed = set()
        self.save_symex = False
        self.outdir = self.get_arg("outdir")
        self.symex = None

        if self.get_arg("conf") is None or "ioctls" not in self.get_arg("conf"):
            raise ValueError("No ioctls in config: {self.get_arg('conf')}")
        
        conf_ioctls = self.get_arg("conf")["ioctls"]
        # Look through ioctls, if one has a 'cmd' of 'default'
        # store those details and then drop it
        # and should be saved + deleted
        # Dict of path -> ioctl info
        # Given lists with path, type, cmd, val. Want {path: {cmd: {type, val}}
        # Also support 'default' command with path and val
        self.ioctls = {}
        for x in conf_ioctls:
            if x['cmd'] == '*':
                self.default_retval[x['path']] = x
            else:
                if x['path'] not in self.ioctls:
                    self.ioctls[x['path']] = {}
                self.ioctls[x['path']][x['cmd']] = x

        if len(self.ioctls) or self.default_retval is not None:
            # If config gave us any ioctls or a default, we need
            # to check every ioctl return

            @panda.ppp("syscalls2", "on_sys_ioctl_return")
            def ioctlc_fake_ret(cpu, pc, fd, cmd, argp):
                rv = self.panda.arch.get_retval(cpu, convention="syscall")
                # If it's a non-negative retval, we probably don't need to fake it
                # unless It happens to match the cmd
                if rv >= 0 and not any(cmd in x for x in self.ioctls.values()) and not len(self.default_retval):
                    # Before looking at the name we know we don't care
                    return

                name = panda.get_file_name(cpu, fd)
                if name == panda.ffi.NULL or name is None:
                    sfd = panda.from_unsigned_guest(fd) 
                    if sfd < 0:
                        print(f"WARN: ioctl {cmd:#x} on invalid FD: {sfd}")
                    elif rv < 0:
                        print(f"WARN: ioctl {cmd:#x} failed with {rv} - but we can't find name for fd {fd}")
                    return

                name = name.decode(errors='ignore')

                ioctl_info, is_default = self.get_model(name, cmd)
                if not ioctl_info:
                    return

                model_type = ioctl_info['type']
                if not hasattr(self, "do_" + model_type):
                    raise ValueError(f"Unknown ioctl type: {model_type}")
                
                if model_type == 'symex':
                    self.save_symex = True
                
                # Decode the ioctl and report it's details
                #decoded_ioctl = self.decode_ioctl(cmd)
                #for key, value in decoded_ioctl.items():
                #    print(f"{key}: {value}")

                #print(f"Modeling ioctl {cmd:#x} on {name} using model {model_type}")
                #print(self.decode_ioctl(cmd))


                f = getattr(self, "do_" + model_type)
                new_rv = f(cpu, ioctl_info, name=name, cmd=cmd, argp=argp)
                if new_rv is not None:
                    #print(f"Faked ioctl {cmd:#x} on {name} using model {model_type}: had rv={rv:#x} changed to rv={new_rv:#x} {'default' if is_default else ''}")
                    fail = False
                    if new_rv < 0:
                        new_rv = panda.to_unsigned_guest(rv)
                        fail = True
                    self.panda.arch.set_retval(cpu, new_rv, convention='syscall', failure=fail)

    def initialize_symex(self):
        # Add this directory to python path so we can import symex
        path.append(dirname(__file__))
        from symex import PathExpIoctl
        self.symex = PathExpIoctl(self.get_arg("outdir"))


    def get_model(self, name, cmd):
        ''' return model, is_default '''
        # First check if we have a mapping for this specific name+cmd
        if name in self.ioctls and cmd in self.ioctls[name]:
            # It's one of ours - need to fake it!
            return self.ioctls[name][cmd], False
        elif name in self.default_retval:
            return self.default_retval[name], True
        else:
            # Not one of ours
            return None, False

    @PyPlugin.ppp_export
    def is_ioctl_hooked(self, path, cmd):
        ioctl_info, is_default = self.get_model(path, cmd)

        if not ioctl_info:
            return False
        
        if ioctl_info['type'] == 'symbolic': # XXX do we want this?
            return False

    @PyPlugin.ppp_export
    def hypothesize_models(self):
        if not self.symex or not self.save_symex:
            return {}
        return self.symex.hypothesize_models()

    def do_return_const(self, cpu, conf, **kwargs):
        # Return a specified const
        rv = conf['val']
        fail = getattr(conf, 'fail', False) #  Optional
        self.panda.arch.set_retval(cpu, rv, convention='syscall', failure=fail)
        return rv

    def do_symbolic_cache(self, cpu, conf, name, cmd, argp):
        '''
        Return a concrete value, but if it's our first time seeing this IOCTL
        use a symex to explore potential paths and record them.

        This guides future runs
        '''

        # If we've already seen this ioctl, just return the concrete value
        if not hasattr(self, "symbolic_cache"):
            self.symbolic_cache = []

        if not self.symex:
            self.initialize_symex()

        if (name, cmd) in self.symbolic_cache:
            return self.do_return_const(cpu, conf)
        self.symbolic_cache.append((name, cmd))

        with open(self.get_arg("outdir") + "/ioctl.log", "a") as f:
            f.write(f"Trying symbolic model for ioctl {cmd:#x} on {name}...\n")
            try:
                results = self.symex.do_symex(self.panda, name, cmd, argp)
            except Exception as e:
                print("ANGR EXCEPTION")
                print(e)
                results = [0]

            f.write(f"\t{' '.join([hex(x) for x in results])}\n")

        print(f"Symbolic model of ioctl {cmd:#x} on {name} gives us: {results}")

        rv = conf['val']
        print(f"\tReturning: {rv:#x}")
        return rv

    def do_symbolic(self, cpu, conf, name, cmd, argp):
        if not self.symex:
            self.initialize_symex()

        with open(self.get_arg("outdir") + "/ioctl.log", "a") as f:
            f.write(f"Trying symbolic model for ioctl {cmd:#x} on {name}...\n")
            results = self.symex.do_symex(self.panda, name, cmd, argp)
            f.write(f"\t{' '.join([hex(x) for x in results])}\n")

        print(f"Symbolic model of ioctl {cmd:#x} on {name} gives us: {results}")

        if hasattr(conf, 'val'):
            # Hack: we can both say to do symbolic but also to return a specific value
            # mostly for testing
            hack = getattr(conf, 'val')
            print(f"\tSelecting HACK: {hack:#x}")
            return hack

        pos = [x for x in results if x >= 0]

        rv = None
        # Select the lowest positive value
        if len(pos):
            rv = min(pos)
        elif len(results):
            rv = results[0]
        else:
            print("Symbolic model failed to give us any results - setting result to 0")
            rv = 0

        if rv:
            print(f"\tSelecting {rv:#x}")

        return rv
    
    def do_model_arg(self, cpu, conf, **kwargs):
        # Return a specified arg
        argc = conf['arg']
        rv = self.panda.arch.get_arg(cpu, argc, convention='syscall') # 0 is syscall num (aka ioctl)
        self.panda.arch.set_retval(cpu, rv, convention='syscall', failure=False)
        return rv

    def do_model_read_buf(self, cpu, conf, **kwargs):
        # model read behavior - given (fp, buf, size, off)
        # read up to size bytes from config-specified buffer at offset *off
        # and palce in guest memory at buf. Update offset to be offset + bytes read
        # and return number of bytes read
        buffer = conf['buffer']

        # Dereference offset to get requested offset
        offset_ptr = self.panda.arch.get_arg(cpu, 4, convention='syscall')
        offset = self.panda.virtual_memory_read(cpu, offset_ptr, 8, fmt='int')

        if offset >= len(buffer):
            # Should we indicate failure here?
            return 0

        buf = self.panda.arch.get_arg(cpu, 2, convention='syscall')
        sz = self.panda.arch.get_arg(cpu, 3, convention='syscall')

        # Now read up to sz bytes from buffer, then write into guest memory at buf
        count = min(sz, len(buffer) - offset)
        self.panda.virtual_memory_write(cpu, buf, count, buffer[offset:offset+count])

        # Update offset to bytes read and return count
        self.panda.virtual_memory_write(cpu, offset_ptr, 8, offset+count, fmt='int')
        self.panda.arch.set_retval(cpu, count, convention='syscall', failure=False)
        return count

    @staticmethod
    def decode_ioctl(ioctl_number):
        direction_enum = ["IO", "IOW", "IOR", "IOWR"]
        direction = (ioctl_number >> 30) & 0x03
        arg_size = (ioctl_number >> 16) & 0x3FFF
        cmd_num = (ioctl_number >> 8) & 0xFF
        type_num = ioctl_number & 0xFF

        return {
            "Direction": direction_enum[direction],
            "Argument Size": arg_size,
            "Command Number": cmd_num,
            "Type Number": type_num
        }

    def uninit(self):
        # Tell angrypanda to save results (pkl file, internal use/debugging?)
        if self.symex and self.save_symex:
            self.symex.save_results()

        # Dump to outfile as yaml (for iterative refinement)
        output = self.hypothesize_models()
        with open(pjoin(self.outdir, outfile), "w") as f:
            yaml.dump(output, f)

def propose_mitigations(config, result_dir, quiet=False):
    with open(pjoin(result_dir, outfile)) as f:
        ioctl_failures = yaml.safe_load(f)

    mitigations = []
    existing_ioctls = ... # XXX TODO: don't change previously-specified IOCTLs
    for path, info in ioctl_failures.items():
        # path = "/dev/device": info = {ioctl: [likeliest value, 2nd likliest value...]}

        # We need to check the *current config* to see how we're modeling this IOCTL
        # AND parent configs to avoid selecting a duplicate? Maybe?

        for ioctl, full_rvs in info.items():
            rvs = [x for x in full_rvs if x != 0] # Don't explicitly set 0 - that's already our default!
            bonus = 0
            if len(rvs) > 1:
                bonus = 1

            for idx, rv in enumerate(rvs):
                weight = 2 + (-len(rvs) / (idx+1))
                mitigations.append((('fake_ioctl', hex(ioctl), path, hex(rv)), weight + bonus))
    return mitigations