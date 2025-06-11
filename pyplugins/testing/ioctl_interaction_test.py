#!/usr/bin/env python3
from penguin import plugins, Plugin

IFNAMSIZ = 16
SIOCGIFFLAGS = 0x8913
SIOCDEVPRIVATE = 0x89F0


class TestIoctlInteraction(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        plugins.syscalls.syscall(
            "on_sys_ioctl_return", arg_filters=[None, SIOCDEVPRIVATE])(self.siocdevprivate)
        plugins.syscalls.syscall(
            "on_sys_ioctl_return", arg_filters=[None, 0x89f1])(self.ioctl_ret)

    @plugins.portal.wrap
    def siocdevprivate(self, cpu, proto, syscall, fd, op, arg):
        interface = yield from plugins.portal.read_str(arg)
        self.logger.info(f"Interface: {interface}")
        data = yield from plugins.portal.read_int(arg + IFNAMSIZ)
        self.logger.info(f"Data: {data:#x}")

        # we overwrite the interface name, read it back, and assert it matches
        to_write = "test"
        yield from plugins.portal.write_str(arg, to_write)
        interface = yield from plugins.portal.read_str(arg)

        assert interface == to_write, f"Expected {to_write}, got {interface}, r/w failed"

        # we overwrite the data, read it back, and assert it matches
        to_write_int = 0x12345678
        yield from plugins.portal.write_int(arg + IFNAMSIZ, to_write_int)
        data = yield from plugins.portal.read_int(arg + IFNAMSIZ)

        assert data == to_write_int, f"Expected {to_write_int:#x}, got {data:#x}, r/w failed"

        fd_name = yield from plugins.portal.get_fd_name(fd) or "[???]"
        self.logger.info(f"FD: {fd_name}")

        args = yield from plugins.portal.get_args()
        self.logger.info(f"Found process: {args}")

        expected_args = [
            '/igloo/utils/test_ioctl_interaction', '0x89F0', 'eth0', '0x1338c0de']
        assert args == expected_args, f"Expected {expected_args}, got {args}"

        env = yield from plugins.portal.get_env()
        self.logger.info(f"Found env: {env}")

        assert env[
            "PROJ_NAME"] == "test_target", f"Expected test_target, got {env['PROJ_NAME']}"

        proc = yield from plugins.portal.get_proc()
        self.logger.info(f"Found pid: {proc.pid}")
        syscall.retval = 2

    '''
    struct ifreq {
    #define IFHWADDRLEN	6
        union
        {
            char	ifrn_name[IFNAMSIZ];		/* if name, e.g. "en0" */
        } ifr_ifrn;

        union {
            struct	sockaddr ifru_addr;
            struct	sockaddr ifru_dstaddr;
            struct	sockaddr ifru_broadaddr;
            struct	sockaddr ifru_netmask;
            struct  sockaddr ifru_hwaddr;
            short	ifru_flags;
            int	ifru_ivalue;
            int	ifru_mtu;
            struct  ifmap ifru_map;
            char	ifru_slave[IFNAMSIZ];	/* Just fits the size */
            char	ifru_newname[IFNAMSIZ];
            void __user *	ifru_data;
            struct	if_settings ifru_settings;
        } ifr_ifru;
    };
    '''
    @plugins.portal.wrap
    def ioctl_ret(self, cpu, proto, syscall, fd, op, arg):
        ifreq = yield from plugins.kffi.read_type(arg, "ifreq")
        interface = bytes(ifreq.ifr_ifrn.ifrn_name).decode(
            "latin-1").rstrip("\x00")
        self.logger.info(f"Interface: {interface}")
        esw_reg_ptr = ifreq.ifr_ifru.ifru_data.address
        off = yield from plugins.portal.read_int(esw_reg_ptr)
        self.logger.info(f"Code: {off:#x}")
        if off == 0x34:
            esw_reg_val = 0x12345678
            val_ptr = esw_reg_ptr+4
            # we overwrite the interface name, read it back, and assert it matches
            yield from plugins.portal.write_int(val_ptr, 0x12345678)
            val = yield from plugins.portal.read_int(val_ptr)
            assert val == esw_reg_val, f"Expected {esw_reg_val:#x}, got {val:#x}"
        syscall.retval = 1
