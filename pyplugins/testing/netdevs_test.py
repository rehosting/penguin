from penguin import Plugin, plugins

kffi = plugins.kffi
mem = plugins.mem

class AlteredNetworkDevice(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        plugins.net.register_netdev("blah0", self)

    def setup(self, device_name: str, netdev):
        self.logger.info(f"Setting up altered network device {device_name}")
        netdev_ops = yield from kffi.deref(netdev.netdev_ops)
        netdev_ops.ndo_do_ioctl = yield from kffi.callback(self.ioctl_handler)
        netdev_ops.ndo_get_stats64 = yield from kffi.callback(self.stats64_handler)
        netdev_ops.ndo_start_xmit = yield from kffi.callback(self.start_xmit)
        yield from kffi.write_struct(netdev.netdev_ops, netdev_ops)
    
    def start_xmit(self, pt_regs, sk_buff_ptr, netdev_ptr):
        sk_buff = yield from kffi.read_type(sk_buff_ptr, "sk_buff")
        netdevs = yield from kffi.read_type(netdev_ptr, "net_device")
        
        skb = yield from mem.read_bytes(sk_buff.data, sk_buff.len)
        self.logger.info(f"netdev {kffi.string(netdevs.name)} received {skb} {len(skb)} bytes")
        return 0
    
    def stats64_handler(self, pt_regs, netdev_ptr, stats64_ptr):
        netdevs = yield from kffi.read_type(netdev_ptr, "net_device")
        stats64 = yield from kffi.read_type(stats64_ptr, "rtnl_link_stats64")
        self.logger.info(f"Getting stats64 for device {kffi.string(netdevs.name)}")
        stats64.rx_packets = 1337
        stats64.tx_packets = 1338
        stats64.rx_bytes = 1339
        stats64.tx_bytes = 1340
        # Just return zeroed stats for now
        yield from kffi.write_struct(stats64_ptr, stats64)
    
    def ioctl_handler(self, pt_regs, netdev_ptr, ifreq_ptr, cmd):
        args = yield from plugins.osi.get_args()
        netdevs = yield from kffi.read_type(netdev_ptr, "net_device")
        ifreq = yield from kffi.read_type(ifreq_ptr, "ifreq")
        name = str(netdevs.name)
        print(name, args, cmd)
        return 0