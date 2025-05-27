from pandare2 import PyPlugin
from penguin import plugins

MAX_PROTOCOLS = 32

class Netlink(PyPlugin):
    def __init__(self, panda):
        self.config = self.get_arg("conf")
        self.recv_callbacks = {i: None for i in range(MAX_PROTOCOLS)}

        @panda.hypercall(IGLOO_HYP_NETLINK_INIT)
        def handle_netlink_init(cpu):
            protocol_ids_addr = panda.arch.get_arg(cpu, 1, convention="syscall")
            cfg = self.config.netlink

            if "*" in cfg:
                func = getattr(getattr(plugins, cfg["*"].plugin), cfg["*"].function)
                for k, v in self.recv_callbacks.items()
                    self.recv_callbacks[k] = func

            for k, v in cfg.items():
                if k == "*":
                    continue
                assert 7 <= k < MAX_PROTOCOLS
                self.recv_callbacks[k] = getattr(getattr(plugins, v.plugin), v.function)

            panda.virtual_memory_write(
                cpu,
                protocol_ids_addr,
                [int(x is not None) for x in self.recv_callbacks.values()],
            )

        @panda.hypercall(IGLOO_HYP_NETLINK_RECV)
        def handle_netlink_recv(cpu):
            protocol = panda.arch.get_arg(cpu, 1, convention="syscall")

            self.recv_callbacks[protocol]()
