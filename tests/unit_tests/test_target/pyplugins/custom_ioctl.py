from pandare import PyPlugin


class CustomIoctl(PyPlugin):
    def ioctl(self, ctx, path, cmd, arg, details):
        match cmd:
            case 0x6621:
                data = ctx.read_bytes(arg, 4)
                data = int.from_bytes(data, byteorder=ctx.panda.endianness)
                return data
            case 0x6622:
                data = ctx.read_bytes(arg, ctx.panda.bits // 8)
                addr = int.from_bytes(data, byteorder=ctx.panda.endianness)
                ctx.write_bytes(addr, b"hello world\x00")
                return 200
            case 0x6623:
                return -300
