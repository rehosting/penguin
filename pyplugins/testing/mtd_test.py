import os
from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import MtdDevice, CharPtr, SizeT, LoffT


class DynamicMtdDevice(MtdDevice):
    """
    A custom object-oriented MTD device representing a 64KB NOR Flash chip.
    It simulates real NOR flash physics where writes can only clear bits (1->0),
    and erases are required to reset them to 1.
    """
    NAME = "dynamic_mtd"
    SIZE = 64 * 1024  # 64 KB
    ERASE_SIZE = 4096
    WRITE_SIZE = 1
    TYPE = "nor"

    def __init__(self, outdir: str):
        self.outdir = outdir
        # Initialize flash to erased state (all 0xFF)
        self.data = bytearray(b'\xff' * self.SIZE)
        super().__init__()

    def _log_to_file(self, message: str):
        """Append a marker to our custom output file for the verifier."""
        if self.outdir:
            with open(os.path.join(self.outdir, "mtd_test_output.txt"), "a") as f:
                f.write(message + "\n")

    def read(self, ptregs: PtRegsWrapper, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        off = int(offset)
        sz = int(length)

        self._log_to_file(
            f"DynamicMtdDevice read called: offset={off}, length={sz}")

        if off >= self.SIZE:
            ptregs.retval = 0
            return 0

        chunk = min(sz, self.SIZE - off)

        # Write the requested chunk of our simulated flash into the guest's buffer
        yield from plugins.mem.write(buf_ptr, bytes(self.data[off:off+chunk]))

        ptregs.retval = 0
        return 0

    def write(self, ptregs: PtRegsWrapper, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        off = int(offset)
        sz = int(length)

        self._log_to_file(
            f"DynamicMtdDevice write called: offset={off}, length={sz}")

        if off >= self.SIZE:
            ptregs.retval = -28  # -ENOSPC
            return -28

        chunk = min(sz, self.SIZE - off)

        # Read the raw bytes the guest wants to write
        raw = yield from plugins.mem.read(buf_ptr, chunk, fmt="bytes")

        # Simulate NOR flash behavior: you can only pull bits to 0 (bitwise AND)
        for i in range(chunk):
            self.data[off + i] &= raw[i]

        ptregs.retval = 0
        return 0

    def erase(self, ptregs: PtRegsWrapper, offset: LoffT, length: SizeT):
        off = int(offset)
        sz = int(length)

        self._log_to_file(
            f"DynamicMtdDevice erase called: offset={off}, length={sz}")

        if off >= self.SIZE:
            ptregs.retval = -22  # -EINVAL
            return -22

        chunk = min(sz, self.SIZE - off)

        # Reset the block to 0xFF
        self.data[off:off+chunk] = b'\xff' * chunk

        ptregs.retval = 0
        return 0


class MtdTest(Plugin):
    def __init__(self):
        # Fetch the output directory from the Plugin base class
        outdir = self.get_arg("outdir")

        # Clear the file to ensure a clean run
        if outdir:
            with open(os.path.join(outdir, "mtd_test_output.txt"), "w") as f:
                f.write("")

        # Register our dynamic OOP MTD device
        plugins.mtd.register_mtd(DynamicMtdDevice(outdir))
