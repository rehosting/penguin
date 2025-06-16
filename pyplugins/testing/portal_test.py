#!/usr/bin/env python3
from penguin import Plugin, plugins

mem = plugins.mem
osi = plugins.osi
fs = plugins.fs


class PortalTest(Plugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        # if self.get_arg_bool("verbose"):
        #     self.logger.setLevel("DEBUG")
        plugins.syscalls.syscall(
            "on_sys_ioctl_return", arg_filters=[None, 0x89f3])(self.ioctl_val)

    '''
    This test checks that we can get information from our program, its arguments,
    and then checks that its parent processes are what we expect.

    A better test might check other values in the proc output.
    '''

    def test_callstack(self):
        # test our callstack reading functionality
        names = []
        callstack = []
        current_proc = None

        while True:
            p = yield from osi.get_proc(pid=current_proc)
            if not p:
                break
            names.insert(0, p.name)
            args = yield from osi.get_args(pid=p.pid)
            callstack.insert(0, args)
            current_proc = p.ppid
            if p.pid == 1:
                break

        expected_callstack = [
            ['/igloo/utils/sh', '/run_tests.sh'],
            ['/igloo/utils/sh', '/tests/portal.sh'],
            ['/igloo/utils/send_syscall', 'ioctl', '0x0', '0x89f3', 'stringval']
        ]
        assert callstack == expected_callstack, f"Expected {expected_callstack}, got {callstack}"

        expected_names = ['run_tests.sh', 'portal.sh', 'send_syscall']
        assert names == expected_names, f"Expected {expected_names}, got {names}"

    '''
    This test writes to our argument string with a range of values.

    It then reads the string back and checks that it matches the expected value.

    A better test might check within the guest that the value is correct.

    This test really only ensures that our read/write functions agree with each other
    '''

    def test_rw(self, arg):
        # NOTE: this part has to be done after callstack or it will be modified
        # test our read/write string functionality
        val_written = "someval"
        yield from mem.write_str(arg, val_written)
        val_read = yield from mem.read_str(arg)
        assert val_written == val_read, f"Expected '{val_written}', got '{val_read}'"

        # test our read/write bytes functionality
        val_written = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        yield from mem.write_bytes(arg, val_written)
        val_read = yield from mem.read_bytes(arg, len(val_written))
        assert val_written == val_read, f"Expected '{val_written}', got '{val_read}'"

        expected = 0x12345678
        yield from mem.write_ptr(arg, expected)
        val = yield from mem.read_ptr(arg)
        assert expected == val, f"Expected '{expected}', got '{val}'"

        expected = 0xabcdef12
        yield from mem.write_int(arg, expected)
        val = yield from mem.read_int(arg)
        assert expected == val, f"Expected '{expected}', got '{val}'"

        expected_long = 0x1234567890abcdef
        yield from mem.write_long(arg, expected_long)
        val = yield from mem.read_long(arg)
        assert expected_long == val, f"Expected '{expected_long}', got '{val}'"

    '''
    This test reads our file /tmp/portal_test. It checks that the file
    contains an expected value from our shell script
    '''

    def test_file_read(self):
        # test our file reading functionality
        test = yield from fs.read_file("/tmp/portal_test")
        expected = b"test read value\n"
        assert test == expected, f"Expected '{expected}', got {test}"

    '''
    This test reads our proc mappings. It checks that it can find our program
    "send_syscall" in the mapping.

    It also checks that the start and end addresses return the right mapping

    Further, it checks the memory region for the ELF header
    '''

    def test_proc_maps(self):
        # Test process mapping functionality
        maps = yield from osi.get_mappings()
        self.logger.debug(f"Found {len(maps)} mappings total")

        omaps = maps.get_mappings_by_name("send_syscall")

        for m in omaps:
            a = maps.get_mapping_by_addr(m.start)
            b = maps.get_mapping_by_addr(m.start + 1)
            c = maps.get_mapping_by_addr(m.end - 1)

            assert a == b == c == m, f"Expected {m}, got {a}, {b}, {c}"

        hdr = yield from mem.read_bytes(omaps[0].start, size=4)
        assert hdr == b"\x7fELF", f"Expected ELF header, got {hdr}"
        return omaps[0].name

    '''
    This test writes our program (/igloo/utils/send_syscall) to a file
    in /tmp. Then our shell script checks if they are the same
    '''

    def test_write_file(self, name):
        # test our file writing functionality
        b = yield from fs.read_file(name)
        yield from fs.write_file("/tmp/write_send_syscall", b)

    '''
    This iterates through all of our processes and checks that we can get
    their arguments, mappings, and file descriptors.

    It doesn't check that the values are correct which would be better.
    '''

    def test_processes_lookup(self):
        proc_handles = yield from osi.get_proc_handles()
        args_pid = {}
        mods_pid = {}
        fds_pid = {}
        for proc in proc_handles:
            pid = proc.pid
            p = yield from osi.get_proc(pid)
            args = yield from osi.get_args(pid)
            args_pid[pid] = args
            mods_pid[pid] = yield from osi.get_mappings(pid)
            fds_pid[pid] = yield from osi.get_fds(pid)

            print(f"PID: {pid}")
            print(f"Name: {p.name}")
            print(f"Args: {args}")
            print(f"Mappings:\n{mods_pid[pid]}")
            for f in fds_pid[pid]:
                print(f"FD: {f.fd} -> {f.name}")

    def ioctl_val(self, cpu, proto, syscall, fd, op, arg):
        # check our arguments
        assert fd == 0, f"Expected fd 0, got {fd:#x}"
        assert op == 0x89f3, f"Expected op 0x89f3, got {op:#x}"
        val = yield from mem.read_str(arg)
        assert val == "stringval", f"Expected 'stringval', got {val}"

        yield from self.test_callstack()
        yield from self.test_rw(arg)
        yield from self.test_file_read()
        name = yield from self.test_proc_maps()
        yield from self.test_write_file(name)
        yield from self.test_processes_lookup()
        syscall.retval = 13
