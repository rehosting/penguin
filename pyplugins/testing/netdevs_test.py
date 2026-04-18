from penguin import Plugin, plugins
from apis.net import Netdev

kffi = plugins.kffi
mem = plugins.mem


class SampleNetDev(Netdev):
    def setup(self, netdev):
        self.logger.info(f"Setting up altered network device {self.name}")
        netdev_ops = yield from kffi.deref(netdev.netdev_ops)
        netdev_ops.ndo_do_ioctl = yield from kffi.callback(self.ioctl_handler)
        netdev_ops.ndo_get_stats64 = yield from kffi.callback(self.stats64_handler)
        yield from mem.write_bytes(netdev.netdev_ops.address, bytes(netdev_ops))

    def stats64_handler(self, pt_regs, netdev_ptr, stats64_ptr):
        netdevs = yield from kffi.read_type(netdev_ptr, "net_device")
        stats64 = yield from kffi.read_type(stats64_ptr, "rtnl_link_stats64")
        self.logger.debug(f"Getting stats64 for device {kffi.ffi.string(netdevs.name)}")
        stats64.rx_packets = 1337
        stats64.tx_packets = 1338
        stats64.rx_bytes = 1339
        stats64.tx_bytes = 1340
        # Just return zeroed stats for now
        yield from mem.write_bytes(stats64_ptr, bytes(stats64))
        return stats64_ptr

    def ioctl_handler(self, pt_regs, netdev_ptr, ifreq_ptr, cmd):
        args = yield from plugins.osi.get_args()
        netdevs = yield from kffi.read_type(netdev_ptr, "net_device")
        name = kffi.ffi.string(netdevs.name)
        self.logger.debug((name, args, cmd))
        return 0


class SampleNetDev2(Netdev):
    def setup(self, netdev):
        self.logger.info(f"Setting up sample network device {self.name}")
        netdev_ops = yield from kffi.deref(netdev.netdev_ops)
        netdev_ops.ndo_do_ioctl = yield from kffi.callback(self.ioctl_handler)
        netdev_ops.ndo_get_stats64 = yield from kffi.callback(self.stats64_handler)
        yield from mem.write_bytes(netdev.netdev_ops.address, bytes(netdev_ops))

    def stats64_handler(self, pt_regs, netdev_ptr, stats64_ptr):
        netdevs = yield from kffi.read_type(netdev_ptr, "net_device")
        stats64 = yield from kffi.read_type(stats64_ptr, "rtnl_link_stats64")
        self.logger.debug(f"Getting stats64 for device {kffi.ffi.string(netdevs.name)}")
        stats64.rx_packets = 7331
        stats64.tx_packets = 8331
        stats64.rx_bytes = 9331
        stats64.tx_bytes = 431
        # Just return zeroed stats for now
        yield from mem.write_bytes(stats64_ptr, bytes(stats64))
        return stats64_ptr

    def ioctl_handler(self, pt_regs, netdev_ptr, ifreq_ptr, cmd):
        args = yield from plugins.osi.get_args()
        netdevs = yield from kffi.read_type(netdev_ptr, "net_device")
        name = kffi.ffi.string(netdevs.name)
        self.logger.info((name, args, cmd))
        return 0


class NetworkDeviceTest(Plugin):
    def __init__(self):
        # Register some sample netdevs for testing
        # Register is an alias for register_netdev, so both should work
        plugins.net.register("sample0", SampleNetDev)
        plugins.net.register_netdev("sample1", SampleNetDev)
        plugins.net.register_netdev("sample2", SampleNetDev2)
