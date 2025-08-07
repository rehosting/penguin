#!/usr/bin/env python3
from penguin import Plugin, plugins

kffi = plugins.kffi
mem = plugins.mem
syscalls = plugins.syscalls

class ModuleTest(Plugin):

    def my_open(self, pt_regs, inode, file):
        inf = yield from kffi.read_type(inode, "inode")
        f = yield from kffi.read_type(file, "file")
        f_fop = yield from kffi.deref(f.f_op)
        return 0

    def my_read(self, pt_regs, file, user, size, loff_t):
        to_write = b"Hello from Python read!\n"

        loff = yield from mem.read_int(loff_t)  # current file position
        if loff > 0:
            return 0

        yield from mem.write_bytes(user, to_write)
        yield from mem.write_int(loff_t, len(to_write))
        return len(to_write)

    @plugins.module.module_init
    def init_module(self):
        yield from self.procfs()
        yield from self.netdev()
        mf = yield from plugins.vfs.mask_file("/proc/cpuinfo")
        self.mf = mf
        mfe = yield from kffi.read_type(mf, "masked_file_entry")
        mfe.masked_fops.open = yield from kffi.cb(self.my_open)
        mfe.masked_fops.read = yield from kffi.cb(self.my_read)
        yield from kffi.write_type(mf, mfe)
    
    def ndo_open(self, pt_regs, devptr):
        dev = yield from kffi.read_type(devptr, "net_device")
        name = "".join([chr(i) for i in dev.name]).rstrip("\x00")
        self.logger.info(f"{name} device opened")
        dev_queue = yield from kffi.deref(dev._tx)

        # yield from kffi.call("netif_start_queue", devptr)
        # breakpoint()
        # print("ndo_open called with args:", dev)
        return 0
    
    def ndo_stop(self, pt_regs, *args):
        breakpoint()
        print("ndo_stop called with args:", args)
    
    def ndo_start_xmit(self, pt_regs, skbp, netdevp):
        skb = yield from kffi.read_type(skbp, "sk_buff")
        netdev = yield from kffi.read_type(netdevp, "net_device")

        buf = yield from mem.read_bytes(skb.data.address, skb.len)

        print(f"ndo_start_xmit called with skb: {buf}")
        breakpoint()
        yield from kffi.call("consume_skb", skbp)
        # Here you would implement the logic to handle packet transmission
        return 0

    def setup_fn(self, pt_regs, netdev):
        yield from kffi.call("ether_setup", netdev)
        dev = yield from kffi.read_type(netdev, "net_device")
        netdevops = kffi.new("net_device_ops")
        netdevops.ndo_open = yield from kffi.cb(self.ndo_open)
        netdevops.ndo_stop = yield from kffi.cb(self.ndo_stop)
        netdevops.ndo_start_xmit = yield from kffi.cb(self.ndo_start_xmit)
        # Don't set ndo_get_stats - let the kernel use defaults
        # netdevops.ndo_get_stats = yield from kffi.cb(self.ndo_get_stats)
        # Set the net_device_ops to the new ops
        netdevopsptr = yield from kffi.copy_obj(netdevops)
        dev.netdev_ops = netdevopsptr
        yield from kffi.write_type(netdev, dev)
    
    def netdev(self):
        setup_fn = yield from kffi.cb(self.setup_fn)
        snet_dev = yield from kffi.call("alloc_netdev_mqs", 
                             0,  # size
                             "snet%d",  # name format
                             0,         # name assign type
                             setup_fn,  # setup function
                             1,  # num_tx_queues
                             1,  # num_rx_queues
                             )
        if snet_dev == 0:
            raise RuntimeError("Failed to allocate netdev")
        self.logger.info(f"Allocated netdev: {snet_dev:#x}")
        result = yield from kffi.call("register_netdev", snet_dev)
        if result != 0:
            self.logger.error(f"Failed to register netdev: {result}")
            yield from kffi.call("free_netdev", snet_dev)
            raise RuntimeError("Failed to register netdev")
        self.logger.info(f"Registered netdev: {snet_dev:#x}")
        return 0

    def procfs(self):
        # Create struct proc_ops and set .proc_read to trampoline fn ptr
        proc_ops = kffi.new("proc_ops")
        proc_ops.proc_read = yield from kffi.cb(self.my_proc_read)
        # Create procfs entry
        entry = yield from kffi.call("proc_create", "pyproc", 0, 0, proc_ops)
        self.logger.info(f"Created procfs entry: {entry:#x}")
    
    def my_proc_read(self, pt_regs, file, user_buf, count, ppos):
        pos = yield from mem.read_int(ppos)
        if pos > 0:
            return 0
        msg = b"Hello from Python procfs!\n"
        to_write = msg[:count]
        yield from mem.write_bytes(user_buf, to_write)
        yield from mem.write_int(ppos, len(to_write))
        return len(to_write)