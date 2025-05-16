from penguin import getColoredLogger, plugins
from pandare2 import PyPlugin
from hyper.consts import *


EVENTS = {
    # MAGIC ->  (NAME,              (ARG1,...,ARGN))
    IGLOO_OPEN:         ('igloo_open',            (str, int)),
    101:                ('igloo_string_cmp',      (str,)),
    102:                ('igloo_string_cmp',      (str,)),
    103:                ('igloo_getenv',          (str,)),
    104:                ('igloo_strstr',          (str, str)),
    IGLOO_IOCTL_ENOTTY: ('igloo_ioctl',           (str, int)),
    107:                ('igloo_nvram_get_miss',  (str,)),
    108:                ('igloo_nvram_get_hit',   (str,)),
    109:                ('igloo_nvram_set',       (str, str)),
    110:                ('igloo_nvram_clear',     (str,)),
    IGLOO_IPV4_SETUP:   ('igloo_ipv4_setup',      (str, int)),
    IGLOO_IPV4_BIND:    ('igloo_ipv4_bind',       (int, bool)),
    IGLOO_IPV6_SETUP:   ('igloo_ipv6_setup',      (str, int)),
    IGLOO_IPV6_BIND:    ('igloo_ipv6_bind',       (int, bool)),
    IGLOO_IPV4_RELEASE: ('igloo_ipv4_release',    (str, int)),
    IGLOO_IPV6_RELEASE: ('igloo_ipv6_release',    (str, int)),
    IGLOO_HYP_UNAME:    ('igloo_uname',           (int, int)),
    IGLOO_HYP_ENOENT:   ('igloo_hyp_enoent',      (str,)),
    0xB335A535:         ('igloo_send_hypercall',  (None, int, int)),
    # crc32("busybox")
    0x8507FAE1:         ('igloo_shell',           (int, int, int)),
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
                argval = self.panda.arch.get_arg(
                    cpu, i + 1, convention="syscall")
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
                elif arg is None:
                    # ignore this argument
                    pass
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
