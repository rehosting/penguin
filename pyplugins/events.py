from pandare import PyPlugin
from penguin import getColoredLogger

EVENTS = {
    # MAGIC ->  (NAME,              (ARG1,...,ARGN))
    100:        ('open',            (int, int, str)),
    101:        ('string_cmp',      (str,)),
    102:        ('string_cmp',      (str,)),
    103:        ('getenv',          (str,)),
    104:        ('strstr',          (str, str)),
    105:        ('ioctl',           (str, int)),
    106:        ('proc_mtd',        (int, int)),
    107:        ('nvram_get_miss',  (int, int)),
    108:        ('nvram_get_hit',   (int, int)),
    109:        ('nvram_set',       (str, str)),
    110:        ('nvram_clear',     (int, int)),
    200:        ('ipv4_setup',      (int, int)),
    201:        ('ipv4_bind',       (int, bool)),
    202:        ('ipv6_setup',      (int, int)),
    203:        ('ipv6_bind',       (int, bool)),
    0x6408400B: ('syscall',         (int,)),
}

class Events(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        # MAGIC -> [fn1, fn2, fn3,...]
        self.callbacks = {}
    
    def _setup_hypercall_handler(self, magic, arg_types):
        @self.panda.hypercall(magic)
        def generic_hypercall(cpu):
            # argument parsing
            args = []
            for i,arg in enumerate(arg_types):
                argval = self.panda.arch.get_arg(cpu, i+1, convention='syscall')
                if arg is int:
                    args.append(argval)
                elif arg is str:
                    try:
                        s = self.panda.read_str(cpu, argval)
                    except ValueError:
                        self.panda.arch.set_arg(cpu, 1, 1)
                        return
                    args.append(s)
                elif arg is bool:
                    args.append(argval != 0)
                else:
                    raise ValueError(f"Unknown argument type {arg}")
            for fn in self.callbacks[magic]:
                fn(*args)
    @PyPlugin.ppp_export
    def listen(self, name, callback):
        """
        Register a callback for an event.
        """
        for magic, (ename, arg_types) in EVENTS.items():
            if ename == name:
                if self.callbacks.get(magic, None) is None:
                    self._setup_hypercall_handler(magic, arg_types)
                    self.callbacks[magic] = []
                self.callbacks[magic].append(callback)
                return
        raise ValueError(f"Events has no event {name}")