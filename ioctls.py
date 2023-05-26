from pandare import PyPlugin

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

class IoctlFakerC(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        
        if self.get_arg("conf") is None or "ioctls" not in self.get_arg("conf"):
            raise ValueError("No ioctls in config: {self.get_arg('conf')}")

        # Dict of path -> ioctl info
        # Given lists with path, type, cmd, val. Want {path: {cmd: {type, val}}
        self.ioctls = {}
        for x in self.get_arg("conf")["ioctls"]:
            if x['path'] not in self.ioctls:
                self.ioctls[x['path']] = {}
            self.ioctls[x['path']][x['cmd']] = x

        if len(self.ioctls):
            # If config gave us any ioctls, we need to dynamically check and change them
            @panda.ppp("syscalls2", "on_sys_ioctl_return")
            def ioctlc_fake_ret(cpu, pc, fd, cmd, arg):
                # On every ioctl return we check path and cmd to see if config says to change

                rv = self.panda.arch.get_retval(cpu, convention="syscall") # Test only

                name = panda.get_file_name(cpu, fd)
                if name == panda.ffi.NULL:
                    if rv < 0:
                        print(f"WARN: ioctl {cmd:#x} failed with {rv} - but we can't find name for fd {fd}")
                    return # Hmm
                
                name = name.decode(errors='ignore')

                if name not in self.ioctls or cmd not in self.ioctls[name]:
                    # Not one of ours - maybe we should log (especially on error?)
                    return

                # It's one of ours - need to fake it!
                ioctl_info = self.ioctls[name][cmd]
                model_type = ioctl_info['type']
                if not hasattr(self, "do_" + model_type):
                    raise ValueError(f"Unknown ioctl type: {model_type}")
                new_rv = getattr(self, "do_" + model_type)(cpu, ioctl_info)
                print(f"Faked ioctl {cmd:#x} on {name} using model {model_type}: had rv={rv} changed to rv={new_rv}")


    @PyPlugin.ppp_export
    def is_ioctl_hooked(self, path, cmd):
        rv = path in self.ioctls and cmd in self.ioctls[path]
        return rv

    def do_return_const(self, cpu, conf):
        # Return a specified const
        rv = conf['val']
        fail = getattr(conf, 'fail', False) #  Optional
        self.panda.arch.set_retval(cpu, rv, convention='syscall', failure=fail)
        return rv
    
    def model_arg(self, cpu, conf):
        # Return a specified arg
        argc = conf['arg']
        rv = self.panda.arch.get_arg(cpu, argc, convention='syscall') # 0 is syscall num (aka ioctl)
        self.panda.arch.set_retval(cpu, rv, convention='syscall', failure=False)
        return rv

    def model_read_buf(self, cpu, conf):
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
        return rv