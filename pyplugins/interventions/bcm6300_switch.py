"""Model the Broadcom HND internal robo-switch (SWMDK / BCM6300) register
interface so the switch daemon initialises instead of rebooting the board.

On Broadcom HND (asuswrt), ``S45swmdk`` brings up the LAN switch via CDK/MDK,
which reads/writes switch registers through ``libethswctl.so`` using the private
ioctl ``SIOCETHSWCTLOPS`` (= ``SIOCDEVPRIVATE + 13`` = ``0x89fd``) on ``eth0``,
passing a ``struct ethswctl_data`` in ``ifr_data``. penguin does not implement
it, so every op returns ``-95`` (EOPNOTSUPP) and ``cdk_dev_create`` fails with
``CDK_E_NOT_FOUND``, after which the box reboots.

``cdk_dev_create`` builds a ``cdk_dev_id {u16 vendor; u16 device; u16 rev; u16
f6;}`` from ``bcm_get_switch_info`` (op 43) and matches it against a compiled-in
device table whose BCM6300 entry is ``vendor=0x6300 device=0x6300 minrev=0
f6=0``. The readback fields land at struct offsets 200 (vendor), 204 (chip_id ->
device; chip-detect masks ``0xfff0`` and defaults to ``0x6300``) and 208 (rev).
Broadcom robo reuses the chip id as the CDK "vendor", so writing ``0x6300`` into
the vendor field (offset 200) on op 43 satisfies the match. Every other op is a
register read/write we simply let succeed -- the switch then runs in "unmanaged
mode", which tolerates the garbage register values.

Note the mixed-ABI case: 32-bit userland on a 64-bit kernel makes ``ifr_data`` a
4-byte pointer, so it is read with ``read_int(arg + IFNAMSIZ) & 0xFFFFFFFF``, not
the kernel's 8-byte word.
"""
from pydantic import Field

from penguin import Plugin, PluginArgs, plugins

IFNAMSIZ = 16
SIOCETHSWCTLOPS = 0x89FD          # SIOCDEVPRIVATE + 13
OP_GET_SWITCH_INFO = 0x2b         # bcm_get_switch_info
DUMP_LEN = 256

BCM6300 = 0x6300

# bcm_get_switch_info readback -> cdk_dev_id field offsets.
OFF_VENDOR = 200
OFF_CHIPID = 204
OFF_REV = 208


def _hex(b):
    return " ".join("%02x" % x for x in b)


class bcm6300_switch(Plugin):
    class Args(PluginArgs):
        iface: str = Field(
            default="eth0",
            description="netdev the switch daemon issues SIOCETHSWCTLOPS on")
        chip_id: int = Field(
            default=BCM6300,
            description="CDK vendor/device id to report on bcm_get_switch_info")

    def __init__(self):
        self.iface = self.get_arg("iface") or "eth0"
        self.chip_id = self.get_arg("chip_id") or BCM6300
        self.n = 0
        self.regs = {}
        self.op_counts = {}          # op -> times seen (for quiet summary)
        self.logger.setLevel("INFO")
        self.logger.info(
            f"bcm6300_switch loaded (iface={self.iface}, "
            f"chip_id=0x{self.chip_id:04x}, "
            f"ioctl=SIOCETHSWCTLOPS=0x{SIOCETHSWCTLOPS:04x})")

    @plugins.syscalls.syscall("on_sys_ioctl_return",
                              arg_filters=[None, SIOCETHSWCTLOPS, None])
    def _ethswctl(self, regs, proto, syscall, fd, request, arg):
        ifname = yield from plugins.mem.read_str(arg)
        if ifname != self.iface:
            return
        # 32-bit userland (mixed-ABI: aarch64 kernel + armel userspace), so
        # ifr_data is a 4-byte pointer, not the kernel's 8-byte word.
        data_ptr = (yield from plugins.mem.read_int(arg + IFNAMSIZ)) & 0xFFFFFFFF
        self.n += 1
        op = -1
        if data_ptr:
            op = (yield from plugins.mem.read_int(data_ptr)) & 0xFFFFFFFF
        first = self.op_counts.get(op, 0) == 0
        self.op_counts[op] = self.op_counts.get(op, 0) + 1

        # On get_switch_info (op 43), seed the chip identity so cdk_dev_create
        # matches the BCM6300 table entry (vendor==device==chip_id, rev>=0). This
        # is the one op that must be answered; every other op is a register
        # read/write we simply let succeed (unmanaged mode tolerates it).
        if data_ptr and op == OP_GET_SWITCH_INFO:
            yield from plugins.mem.write_int(data_ptr + OFF_VENDOR, self.chip_id)
            yield from plugins.mem.write_int(data_ptr + OFF_CHIPID, self.chip_id)
            yield from plugins.mem.write_int(data_ptr + OFF_REV, 0)
            self.logger.info(
                f"[{self.n}] get_switch_info: seeded vendor@{OFF_VENDOR}="
                f"chip@{OFF_CHIPID}=0x{self.chip_id:x}, rev@{OFF_REV}=0")
        elif first:
            # Log one dump per distinct op for reference, then stay quiet.
            raw = (yield from plugins.mem.read_bytes(data_ptr, DUMP_LEN)) \
                if data_ptr else b""
            self.logger.info(
                f"[{self.n}] first op={op:#x} on {ifname} "
                f"data_ptr={data_ptr:#x} raw[0:{DUMP_LEN}]= {_hex(raw)}")

        # Force success so swmdk/CDK proceeds.
        syscall.retval = 0

    def on_stop(self):
        self.logger.info(f"bcm6300_switch: {self.n} SIOCETHSWCTLOPS calls seen")
