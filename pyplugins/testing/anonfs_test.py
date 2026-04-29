from penguin import Plugin, plugins
from os.path import join
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import AnonFile, SocketFile, FilePtr, CharPtr, SizeT, LoffTPtr, SocketPtr, MsgHdrPtr
from apis.syscalls import ValueFilter

syscalls = plugins.syscalls


class EmulatedCounter(AnonFile):
    """
    A generic anonymous file descriptor test.
    Acts as an adder: writes are parsed as integers and added to the counter.
    """

    def __init__(self, outdir, initval=0, **kwargs):
        self.counter = initval
        self.outdir = outdir
        super().__init__(**kwargs)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        raw = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")

        try:
            val = int(raw.decode('utf-8').strip())
            self.counter += val
        except ValueError:
            pass  # Ignore invalid writes for the test

        ptregs.retval = size_val

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)

        data = f"{self.counter}\n".encode('utf-8')

        # Handle EOF for tools like `cat`
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return

        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff, offset + chunk, size=8)
        ptregs.retval = chunk

        # Verify success condition
        if self.counter == 15:
            with open(join(self.outdir, "anonfs_test.txt"), "a") as f:
                f.write("AnonFS Counter Test: PASS\n")


class MockSocket(SocketFile):
    """
    A true kernel socket test.
    Intercepts the VFS routing specifically to ensure proto_ops are hooked.
    """
    DOMAIN = 40  # AF_VSOCK
    TYPE = 3     # SOCK_RAW
    PROTOCOL = 0

    def __init__(self, outdir, **kwargs):
        self.outdir = outdir
        super().__init__(**kwargs)

    def sendmsg(self, ptregs: PtRegsWrapper, sock: SocketPtr, msg: MsgHdrPtr, total_len: SizeT):
        # We simply log the size. The verifier will check anonfs_test.txt for this exact string.
        with open(join(self.outdir, "anonfs_test.txt"), "a") as f:
            f.write(f"MOCK_SOCKET_RECEIVED:{int(total_len)}\n")

        ptregs.retval = int(total_len)


class AnonfsTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")

        # Persistent instances so state survives across multiple open/close calls
        self.counter_file = EmulatedCounter(outdir=self.outdir, initval=10)
        self.sock_file = MockSocket(outdir=self.outdir)

        # -------------------------------------------------------------
        # 1. sys_open (Older architectures like MIPS / static busybox)
        # -------------------------------------------------------------
        syscalls.syscall("on_sys_open_enter",
                         arg_filters=[ValueFilter.string_exact(
                             "/tmp/anon_counter")]
                         )(self.on_open_counter)

        syscalls.syscall("on_sys_open_enter",
                         arg_filters=[
                             ValueFilter.string_exact("/tmp/anon_sock")]
                         )(self.on_open_sock)

        # -------------------------------------------------------------
        # 2. sys_openat (Newer architectures / glibc)
        # -------------------------------------------------------------
        syscalls.syscall("on_sys_openat_enter",
                         arg_filters=[None, ValueFilter.string_exact(
                             "/tmp/anon_counter")]
                         )(self.on_open_counter)

        syscalls.syscall("on_sys_openat_enter",
                         arg_filters=[
                             None, ValueFilter.string_exact("/tmp/anon_sock")]
                         )(self.on_open_sock)

    # Use *args so this callback cleanly handles the differing signatures
    # between sys_open (3 args) and sys_openat (4 args).
    def on_open_counter(self, regs, proto, syscall, *args):
        syscall.skip_syscall = True
        fd = yield from plugins.anonfs.register_anon_file(self.counter_file, name="[anon_counter]")
        syscall.retval = fd

    def on_open_sock(self, regs, proto, syscall, *args):
        syscall.skip_syscall = True
        fd = yield from plugins.anonfs.register_socket(self.sock_file)
        syscall.retval = fd
