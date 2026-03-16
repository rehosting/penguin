#!/usr/bin/env python3
from penguin import Plugin, plugins
from os.path import join

kffi = plugins.kffi
mem = plugins.mem
syscalls = plugins.syscalls

CALLBACK_ARGS = [
    1,
    0xffffffff,
    0xf0f0f0f0f0f0f0f0,
    2,
    3,
    4,
    9,
    0x1337c0de,
]


class KFFITest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        if self.panda.bits == 32:
            self.mask = 0xffffffff
        else:
            self.mask = 0xffffffffffffffff

        self.cb_args = [
            i & self.mask for i in CALLBACK_ARGS
        ]

    def callback(self, pt_regs, a, b, c, d, e, f, g, h):
        for i, val in enumerate([a, b, c, d, e, f, g, h]):
            if self.cb_args[i] != val:
                raise ValueError(f"Expected {CALLBACK_ARGS[i]} for arg {i}, got {val}")

        with open(join(self.outdir, "kffi_test.txt"), "a") as f:
            f.write("Callback called with expected values!\n")
        return 42

    @syscalls.syscall("on_sys_ioctl_return", arg_filters=[0x14, 0x15, 0x16])
    def test_kffi(self, regs, proto, syscall, fd, op, arg):
        self.logger.info("Starting KFFI & DWARFFI Integration Tests...")

        args = [3, 8, 9, 0x1338c0de, 12, 13, 14, 15]
        val = yield from kffi.call("igloo_test_function", *args)
        assert val == sum(args), f"Expected {sum(args)}, got {val}, r/w failed"
        level = b"\x01\x03"
        yield from kffi.call("igloo_printk", level + b"test printk %d %d %d %d\x00", 1, 2, 3, 4)

        # ---------------------------------------------------------
        # NEW: DWARFFI ENHANCEMENTS & MARSHALLING TESTS
        # ---------------------------------------------------------
        self.logger.info("Testing DWARFFI nested struct & array initialization...")

        # 1. Deep initialization & Arrays
        # (Using list_head as it is universally available in the Linux kernel ISF)
        nodes = kffi.new("struct list_head[2]", [
            {"next": 0x1111, "prev": 0x2222},
            {"next": 0x3333, "prev": 0x4444}
        ])
        assert nodes[0].next == 0x1111, "Deep initialization failed"
        assert nodes[1].prev == 0x4444, "Deep initialization failed"

        # 2. Struct-to-struct assignment (Zero-copy memory slice test)
        nodes[1] = nodes[0]
        assert nodes[1].next == 0x1111, "Struct assignment failed"
        assert nodes[1].prev == 0x2222, "Struct assignment failed"

        # 3. Extracting raw bytes natively
        raw_bytes = bytes(nodes)
        expected_size = kffi.ffi.sizeof("struct list_head") * 2
        assert len(raw_bytes) == expected_size, f"Expected {expected_size} bytes, got {len(raw_bytes)}"

        # 4. KFFI Auto-Marshalling: Pass BoundTypeInstance to a kernel function
        # The KFFI _prepare_ffi_call marshaller should automatically kmalloc,
        # write the bytes, and pass the pointer!
        try:
            yield from kffi.call("igloo_test_function", 1, 2, 3, 4, 5, 6, 7, nodes[0])
        except Exception as e:
            assert False, f"Failed to marshal BoundTypeInstance: {e}"

        # 5. Enum Extraction & Wrapping
        enum_dict = kffi.get_enum_dict("pid_type")
        # The KFFI Wrapper class allows dot-attribute access for constants
        assert getattr(enum_dict, "PIDTYPE_PID", None) is not None, "Failed to parse enum pid_type"

        self.logger.info("DWARFFI enhancements successfully tested!")
        # ---------------------------------------------------------

        tramp_addr = yield from kffi.callback(self.callback)
        ret = yield from kffi.call(tramp_addr, *self.cb_args)

        assert ret == 42, f"Expected 42 from callback, got {ret}"

        tramp_addr2 = yield from kffi.callback(self.callback)
        assert tramp_addr == tramp_addr2, "Expected same trampoline address for same callback"

        id = kffi.get_callback_id(self.callback)

        fn_name = f"portal_tramp_fn_{id:x}"
        rv = yield from kffi.kallsyms_lookup(fn_name)
        assert rv == tramp_addr, f"Expected {tramp_addr:x} from kallsyms_lookup, got {rv:x}"

        # Get full path of executable that issued this system call
        current = yield from plugins.osi.get_proc()
        task = yield from plugins.kffi.read_type(current.taskd, "task_struct")
        exe_file_ptr = yield from plugins.kffi.call_kernel_function("get_task_exe_file", task)
        exe_file = yield from plugins.kffi.read_type(exe_file_ptr, "file")
        buf = yield from plugins.kffi.kmalloc(64)
        f_path_ptr = plugins.kffi.ffi.addressof(exe_file, "f_path").address

        # ---------------------------------------------------------
        # NEW: DEREF AND CASTING TESTS
        # ---------------------------------------------------------
        # We explicitly cast the f_inode integer to a Ptr object, then yield from deref
        inode_ptr = kffi.ffi.cast("struct inode *", exe_file.f_inode.address)
        inode_deref = yield from kffi.deref(inode_ptr)
        assert inode_deref is not None, "kffi.deref failed to read memory"

        # Testing types with a known result
        inode = yield from plugins.kffi.read_type(exe_file.f_inode, "inode")
        assert inode.i_ino == inode_deref.i_ino, "Deref value mismatch! (Memory consistency error)"

        i_opflags = plugins.kffi.get_field_casted(inode, "i_opflags")
        assert 'short unsigned int' == plugins.kffi.ffi.typeof(i_opflags).name
        #  char *d_path(const struct path *path, char *buf, int buflen)
        path = yield from plugins.kffi.call_kernel_function("d_path", f_path_ptr, buf, 64)
        exe_path = yield from plugins.mem.read_str(path)
        exe_path_from_osi = yield from plugins.osi.get_proc_exe(current.pid)
        assert exe_path == exe_path_from_osi, f"Expected exe path from osi {exe_path_from_osi}, got {exe_path}"
        yield from plugins.kffi.call_kernel_function("fput", exe_file_ptr)
        yield from plugins.kffi.kfree(buf)

        with open(join(self.outdir, "kffi_test.txt"), "a") as f:
            f.write(f"Calling program is {exe_path}\n")

        self.logger.info("All KFFI & DWARFFI tests passed successfully!")
        # we've commented this out for now since it needs to be updated for 4.10
        # # open our file
        # file_ptr = yield from kffi.call("filp_open", "/igloo/init", 0, 0)

        # # allocate kernel buffer to read file content
        # buf = yield from kffi.kmalloc(64)

        # # read file content
        # val = yield from kffi.call("kernel_read", file_ptr, buf, 64, 0)

        # # read buffer
        # buf_bytes = yield from mem.read_bytes(buf, 64)

        # # check buffer values
        # assert buf_bytes.startswith(b"#!/igloo/utils/sh\n"), \
        #     f"Expected file content to start with '#!/igloo/utils/sh\\n', got {buf_bytes[:30]!r}"

        # # clean up
        # yield from kffi.kfree(buf)
        # yield from kffi.call("filp_close", file_ptr, 0)
