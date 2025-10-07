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
        args = [3, 8, 9, 0x1338c0de, 12, 13, 14, 15]
        val = yield from kffi.call("igloo_test_function", *args)
        assert val == sum(args), f"Expected {sum(args)}, got {val}, r/w failed"
        level = b"\x01\x03"
        yield from kffi.call("igloo_printk", level + b"test printk %d %d %d %d\x00", 1, 2, 3, 4)

        tramp_addr = yield from kffi.callback(self.callback)
        print(tramp_addr)
        ret = yield from kffi.call(tramp_addr, *self.cb_args)

        assert ret == 42, f"Expected 42 from callback, got {ret}"

        tramp_addr2 = yield from kffi.callback(self.callback)
        assert tramp_addr == tramp_addr2, "Expected same trampoline address for same callback"

        id = kffi.get_callback_id(self.callback)

        fn_name = f"portal_tramp_fn_{id:x}"
        rv = yield from kffi.kallsyms_lookup(fn_name)
        assert rv == tramp_addr, f"Expected {tramp_addr:x} from kallsyms_lookup, got {rv:x}"

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
