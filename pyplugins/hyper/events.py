from penguin import getColoredLogger, plugins
from pandare import PyPlugin


EVENTS = {
    # MAGIC ->  (NAME,              (ARG1,...,ARGN))
    100:        ('igloo_open',            (str, int)),
    101:        ('igloo_string_cmp',      (str,)),
    102:        ('igloo_string_cmp',      (str,)),
    103:        ('igloo_getenv',          (str,)),
    104:        ('igloo_strstr',          (str, str)),
    105:        ('igloo_ioctl',           (str, int)),
    106:        ('igloo_proc_mtd',        (int, int)),
    107:        ('igloo_nvram_get_miss',  (str,)),
    108:        ('igloo_nvram_get_hit',   (str,)),
    109:        ('igloo_nvram_set',       (str, str)),
    110:        ('igloo_nvram_clear',     (str,)),
    200:        ('igloo_ipv4_setup',      (str, int)),
    201:        ('igloo_ipv4_bind',       (int, bool)),
    202:        ('igloo_ipv6_setup',      (str, int)),
    203:        ('igloo_ipv6_bind',       (int, bool)),
    204:        ('igloo_ipv4_release',    (str, int)),
    205:        ('igloo_ipv6_release',    (str, int)),
    300:        ('igloo_uname',           (int, int)),
    0x6408400B: ('igloo_syscall',         (int,)),
    0xB335A535: ('igloo_send_hypercall',  (int, int)),
    0x8507FAE1: ('igloo_shell',           (int, int, int)), # crc32("busybox")
}


class Events(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        # MAGIC -> [fn1, fn2, fn3,...]
        self.callbacks = {}
        self.logger = getColoredLogger("plugins.events")
 
        for event_num, (name, args) in EVENTS.items():
            plugins.register(self, name, register_notify=self.register_notify)

    def _setup_hypercall_handler(self, magic, arg_types):
        @self.panda.hypercall(magic)
        def generic_hypercall(cpu):
            # argument parsing
            args = [cpu]
            for i, arg in enumerate(arg_types):
                argval = self.panda.arch.get_arg(cpu, i + 1, convention="syscall")
                if arg is int:
                    args.append(argval)
                elif arg is str:
                    try:
                        s = self.panda.read_str(cpu, argval)
                    except ValueError:
                        self.logger.debug(
                            f"arg read fail: {magic} {argval:x} {i} {arg}"
                        )
                        self.panda.arch.set_retval(cpu, 1)
                        return
                    args.append(s)
                elif arg is bool:
                    args.append(argval != 0)
                else:
                    raise ValueError(f"Unknown argument type {arg}")
            plugins.publish(self, self.callbacks[magic], *args)

    def register_notify(self, name, callback):
        """
        Register a callback for an event.
        """
        for magic, (ename, arg_types) in EVENTS.items():
            if ename == name:
                if self.callbacks.get(magic, None) is None:
                    self._setup_hypercall_handler(magic, arg_types)
                    self.callbacks[magic] = []
                self.callbacks[magic] = name
                return
        raise ValueError(f"Events has no event {name}")